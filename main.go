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
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
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

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/blackbox_exporter/prober"
)

var (
	sc = config.NewSafeConfig(prometheus.DefaultRegisterer)

	configFile      = kingpin.Flag("config.file", "Blackbox exporter configuration file.").Default("blackbox.yml").String()
	configDBDSNFile = kingpin.Flag("config.db_dsn_file", "Path to YAML file containing PostgreSQL connection parameters for configuration. If set, config will be loaded from database.").String()
	configDBQuery   = kingpin.Flag("config.db_query", "SQL query returning configuration JSON for a given id.").Default("SELECT config FROM blackbox_config WHERE id = $1").String()
	configDBUpsert  = kingpin.Flag("config.db_upsert", "SQL upsert statement to store configuration when using --config.db_import.").Default("INSERT INTO blackbox_config (id, config) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO UPDATE SET config = EXCLUDED.config").String()
	configDBImport  = kingpin.Flag("config.db_import", "If true, import configuration from --config.file into the database and exit.").Bool()
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
		dbDSN string
		dbID  string
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
		parts := make([]string, 0, len(params))
		for k, v := range params {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		dbDSN = strings.Join(parts, " ")
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

	loadConfig := func() error {
		if dbDSN != "" {
			if dbID == "" {
				return fmt.Errorf("id must be specified in DSN file")
			}
			return sc.ReloadConfigFromDB(dbDSN, *configDBQuery, dbID, logger)
		}
		return sc.ReloadConfig(*configFile, logger)
	}

	if err := loadConfig(); err != nil {
		logger.Error("Error loading config", "err", err)
		return 1
	}

	if *configCheck {
		logger.Info("Config is ok exiting...")
		return 0
	}

	logger.Info("Loaded config")

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
					continue
				}
				logger.Info("Reloaded config")
			case rc := <-reloadCh:
				if err := loadConfig(); err != nil {
					logger.Error("Error reloading config", "err", err)
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
		sc.RLock()
		c, err := yaml.Marshal(sc.C)
		sc.RUnlock()
		if err != nil {
			logger.Warn("Error marshalling configuration", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(c)
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
