// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"database/sql"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	pq "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/yaml.v3"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/blackbox_exporter/prober"
)

const (
	defaultDBQuery  = "SELECT config FROM blackbox_config WHERE id = $1"
	defaultDBUpsert = "INSERT INTO blackbox_config (id, config) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO UPDATE SET config = EXCLUDED.config"
)

var (
	sc              = config.NewSafeConfig(prometheus.DefaultRegisterer)
	configFile      = kingpin.Flag("config.file", "Blackbox exporter configuration file.").Default("blackbox.yml").String()
	configDBDSNFile = kingpin.Flag("config.db_dsn_file", "Path to YAML file containing PostgreSQL connection parameters for configuration. If set, config will be loaded from database.").String()
	configDBQuery   = kingpin.Flag("config.db_query", "SQL query returning configuration JSON for a given id.").Default(defaultDBQuery).String()
	configDBUpsert  = kingpin.Flag("config.db_upsert", "SQL upsert statement to store configuration when using --config.db_import.").Default(defaultDBUpsert).String()
	configDBImport  = kingpin.Flag("config.db_import", "If true, import configuration from --config.file into the database and exit.").Bool()
	configDBExport  = kingpin.Flag("config.db_export", "If true, export configuration from the database to --config.file and exit.").Bool()
	timeoutOffset   = kingpin.Flag("timeout-offset", "Offset to subtract from timeout in seconds.").Default("0.5").Float64()
	configCheck     = kingpin.Flag("config.check", "If true validate the config file and then exit.").Default().Bool()
	logLevelProber  = kingpin.Flag("log.prober", "Log level for probe request logs. One of: [debug, info, warn, error]. Defaults to debug. Please see the section `Controlling log level for probe logs` in the project README for more information.").Default("debug").String()
	historyLimit    = kingpin.Flag("history.limit", "The maximum amount of items to keep in the history.").Default("100").Uint()
	externalURL     = kingpin.Flag("web.external-url", "The URL under which Blackbox exporter is externally reachable (for example, if Blackbox exporter is served via a reverse proxy). Used for generating relative and absolute links back to Blackbox exporter itself. If the URL has a path portion, it will be used to prefix all HTTP endpoints served by Blackbox exporter. If omitted, relevant URL components will be derived automatically.").PlaceHolder("<url>").String()
	routePrefix     = kingpin.Flag("web.route-prefix", "Prefix for the internal routes of web endpoints. Defaults to path of --web.external-url.").PlaceHolder("<path>").String()
	toolkitFlags    = webflag.AddFlags(kingpin.CommandLine, ":9115")

	moduleUnknownCounter = promauto.NewCounter(prometheus.CounterOpts{
		Name: "blackbox_module_unknown_total",
		Help: "Count of unknown modules requested by probes",
	})
)

func init() {
	prometheus.MustRegister(versioncollector.NewCollector("blackbox_exporter"))
}

func main() {
	os.Exit(run())
}

func run() int {
	kingpin.CommandLine.UsageWriter(os.Stdout)
	promslogConfig := &promslog.Config{}
	flag.AddFlags(kingpin.CommandLine, promslogConfig)
	kingpin.Version(version.Print("blackbox_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promslog.New(promslogConfig)
	rh := &prober.ResultHistory{MaxResults: *historyLimit}

	var (
		dbDSN           string
		dbID            = "blackbox"
		dbRetryInterval = time.Minute
		dbTable         = "blackbox_config"
		dbSchema        string
	)
	if *configDBDSNFile != "" {
		b, err := os.ReadFile(*configDBDSNFile)
		if err != nil {
			logger.Error("Error reading DSN file", "err", err)
			return 1
		}
		var params map[string]interface{}
		if err := yaml.Unmarshal(b, &params); err != nil {
			logger.Error("Error parsing DSN YAML", "err", err)
			return 1
		}
		if v, ok := params["id"]; ok {
			dbID = fmt.Sprint(v)
			delete(params, "id")
		} else if v, ok := params["hostname"]; ok {
			dbID = fmt.Sprint(v)
			delete(params, "hostname")
		}
		if v, ok := params["retry_interval"]; ok {
			if d, err := time.ParseDuration(fmt.Sprint(v)); err == nil {
				dbRetryInterval = d
			} else {
				logger.Warn("Invalid retry_interval, using default", "value", v)
			}
			delete(params, "retry_interval")
		}
		if v, ok := params["table"]; ok {
			dbTable = fmt.Sprint(v)
			delete(params, "table")
		}
		if v, ok := params["schema"]; ok {
			dbSchema = fmt.Sprint(v)
			delete(params, "schema")
		}
		parts := make([]string, 0, len(params))
		for k, v := range params {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		dbDSN = strings.Join(parts, " ")

		fullTable := pq.QuoteIdentifier(dbTable)
		if dbSchema != "" {
			fullTable = pq.QuoteIdentifier(dbSchema) + "." + fullTable
		}
		if *configDBQuery == defaultDBQuery {
			*configDBQuery = fmt.Sprintf("SELECT config FROM %s WHERE id = $1", fullTable)
		}
		if *configDBUpsert == defaultDBUpsert {
			*configDBUpsert = fmt.Sprintf("INSERT INTO %s (id, config) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO UPDATE SET config = EXCLUDED.config", fullTable)
		}

		if err := ensureDatabaseAndTable(dbDSN, params, dbSchema, dbTable); err != nil {
			logger.Error("Error ensuring database", "err", err)
			return 1
		}
	}

	probeLogLevel := promslog.NewLevel()
	if err := probeLogLevel.Set(*logLevelProber); err != nil {
		logger.Warn("Error setting log prober level, log prober level unchanged", "err", err, "current_level", probeLogLevel.String())
	}

	logger.Info("Starting blackbox_exporter", "version", version.Info())
	logger.Info(version.BuildContext())

	if *configDBImport {
		if dbDSN == "" || dbID == "" {
			logger.Error("config.db_dsn_file with id must be set when using --config.db_import")
			return 1
		}
		if err := config.ImportConfigToDB(*configFile, dbDSN, *configDBUpsert, dbID); err != nil {
			logger.Error("Error importing config", "err", err)
			return 1
		}
		logger.Info("Imported config to database")
		return 0
	}

	if *configDBExport {
		if dbDSN == "" {
			logger.Error("config.db_dsn_file must be set when using --config.db_export")
			return 1
		}
		if err := config.ExportConfigFromDB(*configFile, dbDSN, *configDBQuery, dbID); err != nil {
			logger.Error("Error exporting config", "err", err)
			return 1
		}
		logger.Info("Exported config from database")
		return 0
	}

	var (
		configLoaded bool
		dbLoadErr    error
		retryTicker  *time.Ticker
	)
	loadConfig := func() error {
		var err error
		if dbDSN != "" {
			if dbID == "" {
				err = fmt.Errorf("id must be specified in DSN file")
			} else {
				err = sc.ReloadConfigFromDB(dbDSN, *configDBQuery, dbID, logger)
			}
		} else {
			err = sc.ReloadConfig(*configFile, logger)
		}
		if err != nil {
			dbLoadErr = sanitizeError(err)
		} else {
			configLoaded = true
			dbLoadErr = nil
		}
		return err
	}

	startRetry := func() {
		if dbDSN == "" {
			return
		}
		if retryTicker != nil {
			return
		}
		retryTicker = time.NewTicker(dbRetryInterval)
		go func() {
			for range retryTicker.C {
				if err := loadConfig(); err != nil {
					logger.Error("Error loading config", "err", err)
					continue
				}
				logger.Info("Loaded config")
				retryTicker.Stop()
				retryTicker = nil
				break
			}
		}()
	}

	if err := loadConfig(); err != nil {
		logger.Error("Error loading config", "err", err)
		startRetry()
	} else {
		logger.Info("Loaded config")
	}

	if *configCheck {
		logger.Info("Config is ok exiting...")
		return 0
	}

	// Infer or set Blackbox exporter externalURL
	listenAddrs := toolkitFlags.WebListenAddresses
	if *externalURL == "" && *toolkitFlags.WebSystemdSocket {
		logger.Error("Cannot automatically infer external URL with systemd socket listener. Please provide --web.external-url")
		return 1
	} else if *externalURL == "" && len(*listenAddrs) > 1 {
		logger.Info("Inferring external URL from first provided listen address")
	}
	beURL, err := computeExternalURL(*externalURL, (*listenAddrs)[0])
	if err != nil {
		logger.Error("failed to determine external URL", "err", err)
		return 1
	}
	logger.Debug(beURL.String())

	// Default -web.route-prefix to path of -web.external-url.
	if *routePrefix == "" {
		*routePrefix = beURL.Path
	}

	// routePrefix must always be at least '/'.
	*routePrefix = "/" + strings.Trim(*routePrefix, "/")
	// routePrefix requires path to have trailing "/" in order
	// for browsers to interpret the path-relative path correctly, instead of stripping it.
	if *routePrefix != "/" {
		*routePrefix = *routePrefix + "/"
	}
	logger.Debug(*routePrefix)

	hup := make(chan os.Signal, 1)
	reloadCh := make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-hup:
				if err := loadConfig(); err != nil {
					logger.Error("Error reloading config", "err", err)
					startRetry()
					continue
				}
				logger.Info("Reloaded config")
			case rc := <-reloadCh:
				if err := loadConfig(); err != nil {
					logger.Error("Error reloading config", "err", err)
					startRetry()
					rc <- err
				} else {
					logger.Info("Reloaded config")
					rc <- nil
				}
			}
		}
	}()

	// Match Prometheus behavior and redirect over externalURL for root path only
	// if routePrefix is different than "/"
	if *routePrefix != "/" {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, beURL.String(), http.StatusFound)
		})
	}

	http.HandleFunc(path.Join(*routePrefix, "/-/reload"),
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				fmt.Fprintf(w, "This endpoint requires a POST request.\n")
				return
			}

			rc := make(chan error)
			reloadCh <- rc
			if err := <-rc; err != nil {
				http.Error(w, fmt.Sprintf("failed to reload config: %s", err), http.StatusInternalServerError)
			}
		})
	http.Handle(path.Join(*routePrefix, "/metrics"), promhttp.Handler())
	http.HandleFunc(path.Join(*routePrefix, "/-/healthy"), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Healthy"))
	})
	http.HandleFunc(path.Join(*routePrefix, "/probe"), func(w http.ResponseWriter, r *http.Request) {
		sc.Lock()
		conf := sc.C
		sc.Unlock()
		prober.Handler(w, r, conf, logger, rh, *timeoutOffset, nil, moduleUnknownCounter, promslogConfig.Level, probeLogLevel)
	})
	http.HandleFunc(*routePrefix, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html>
    <head><title>Blackbox Exporter</title></head>
    <body>
    <h1>Blackbox Exporter</h1>
    <p><a href="probe?target=prometheus.io&module=http_2xx">Probe prometheus.io for http_2xx</a></p>
    <p><a href="probe?target=prometheus.io&module=http_2xx&debug=true">Debug probe prometheus.io for http_2xx</a></p>
    <p><a href="metrics">Metrics</a></p>
    <p><a href="config">Configuration</a></p>
    <h2>Recent Probes</h2>
    <table border='1'><tr><th>Module</th><th>Target</th><th>Result</th><th>Debug</th>`))

		results := rh.List()

		for i := len(results) - 1; i >= 0; i-- {
			r := results[i]
			success := "Success"
			if !r.Success {
				success = "<strong>Failure</strong>"
			}
			fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td><td><a href='logs?id=%d'>Logs</a></td></td>",
				html.EscapeString(r.ModuleName), html.EscapeString(r.Target), success, r.Id)
		}

		w.Write([]byte(`</table></body>
    </html>`))
	})

	http.HandleFunc(path.Join(*routePrefix, "/logs"), func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if err != nil {
			id = -1
		}
		target := r.URL.Query().Get("target")
		if err == nil && target != "" {
			http.Error(w, "Probe id and target can't be defined at the same time", http.StatusBadRequest)
			return
		}
		if id == -1 && target == "" {
			http.Error(w, "Probe id or target must be defined as http query parameters", http.StatusBadRequest)
			return
		}
		result := new(prober.Result)
		if target != "" {
			result = rh.GetByTarget(target)
			if result == nil {
				http.Error(w, "Probe target not found", http.StatusNotFound)
				return
			}
		} else {
			result = rh.GetById(id)
			if result == nil {
				http.Error(w, "Probe id not found", http.StatusNotFound)
				return
			}
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(result.DebugOutput))
	})

	configHandler := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if dbDSN != "" && !configLoaded {
				msg := "database unavailable"
				if dbLoadErr != nil {
					msg = fmt.Sprintf("%s: %s", msg, dbLoadErr)
				}
				http.Error(w, msg, http.StatusServiceUnavailable)
				return
			}
			sc.RLock()
			yamlData, err := yaml.Marshal(sc.C)
			sc.RUnlock()
			if err != nil {
				logger.Warn("Error marshalling configuration", "err", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			jsonData, err := k8syaml.YAMLToJSON(yamlData)
			if err != nil {
				logger.Warn("Error converting configuration to JSON", "err", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(jsonData)
		case http.MethodPost:
			if dbDSN == "" {
				http.Error(w, "database configuration not enabled", http.StatusBadRequest)
				return
			}
			data, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := config.UpsertConfigToDB(data, dbDSN, *configDBUpsert, dbID); err != nil {
				http.Error(w, sanitizeError(err).Error(), http.StatusInternalServerError)
				return
			}
			if err := loadConfig(); err != nil {
				logger.Error("Error reloading config", "err", err)
				startRetry()
				http.Error(w, sanitizeError(err).Error(), http.StatusInternalServerError)
				return
			}
			if retryTicker != nil {
				retryTicker.Stop()
				retryTicker = nil
			}
			logger.Info("Loaded config")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprintf(w, "This endpoint requires a GET or POST request.\n")
		}
	}
	http.HandleFunc(path.Join(*routePrefix, "/config"), configHandler)
	http.HandleFunc(path.Join(*routePrefix, "/-/config"), configHandler)

	srv := &http.Server{}
	srvc := make(chan struct{})
	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := web.ListenAndServe(srv, toolkitFlags, logger); err != nil {
			logger.Error("Error starting HTTP server", "err", err)
			close(srvc)
		}
	}()

	for {
		select {
		case <-term:
			logger.Info("Received SIGTERM, exiting gracefully...")
			return 0
		case <-srvc:
			return 1
		}
	}

}

func ensureDatabaseAndTable(dsn string, params map[string]interface{}, schema, table string) error {
	dbname, ok := params["dbname"].(string)
	if !ok || dbname == "" {
		return errors.New("dbname must be specified")
	}
	db, err := sql.Open("postgres", dsn)
	if err == nil {
		err = db.Ping()
	}
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "3D000" {
			paramsCopy := make(map[string]interface{}, len(params))
			for k, v := range params {
				paramsCopy[k] = v
			}
			paramsCopy["dbname"] = "postgres"
			parts := make([]string, 0, len(paramsCopy))
			for k, v := range paramsCopy {
				parts = append(parts, fmt.Sprintf("%s=%v", k, v))
			}
			rootDSN := strings.Join(parts, " ")
			rootDB, err2 := sql.Open("postgres", rootDSN)
			if err2 != nil {
				return fmt.Errorf("error connecting to postgres: %w", err2)
			}
			defer rootDB.Close()
			if _, err2 = rootDB.Exec(fmt.Sprintf("CREATE DATABASE %s", pq.QuoteIdentifier(dbname))); err2 != nil {
				if pqErr, ok := err2.(*pq.Error); !ok || pqErr.Code != "42P04" {
					return fmt.Errorf("error creating database: %w", err2)
				}
			}
			if err = db.Close(); err != nil {
				return fmt.Errorf("error closing database: %w", err)
			}
			db, err = sql.Open("postgres", dsn)
			if err == nil {
				err = db.Ping()
			}
		}
		if err != nil {
			return fmt.Errorf("error opening database: %w", err)
		}
	}
	defer db.Close()

	if schema != "" {
		if _, err := db.Exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", pq.QuoteIdentifier(schema))); err != nil {
			return fmt.Errorf("error creating schema: %w", err)
		}
	}
	fullTable := pq.QuoteIdentifier(table)
	if schema != "" {
		fullTable = pq.QuoteIdentifier(schema) + "." + fullTable
	}
	if _, err := db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (id TEXT PRIMARY KEY, config JSONB NOT NULL)", fullTable)); err != nil {
		return fmt.Errorf("error creating table: %w", err)
	}
	return nil
}

var passwordRe = regexp.MustCompile(`password=[^\s]+`)

func sanitizeError(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(passwordRe.ReplaceAllString(err.Error(), "password=REDACTED"))
}

func startsOrEndsWithQuote(s string) bool {
	return strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") ||
		strings.HasSuffix(s, "\"") || strings.HasSuffix(s, "'")
}

// computeExternalURL computes a sanitized external URL from a raw input. It infers unset
// URL parts from the OS and the given listen address.
func computeExternalURL(u, listenAddr string) (*url.URL, error) {
	if u == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, err
		}
		_, port, err := net.SplitHostPort(listenAddr)
		if err != nil {
			return nil, err
		}
		u = fmt.Sprintf("http://%s:%s/", hostname, port)
	}

	if startsOrEndsWithQuote(u) {
		return nil, errors.New("URL must not begin or end with quotes")
	}

	eu, err := url.Parse(u)
	if err != nil {
		return nil, err
	}

	ppref := strings.TrimRight(eu.Path, "/")
	if ppref != "" && !strings.HasPrefix(ppref, "/") {
		ppref = "/" + ppref
	}
	eu.Path = ppref

	return eu, nil
}
