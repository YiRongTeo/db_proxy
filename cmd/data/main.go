package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/logging"
	"zerotrust-proxy/internal/metrics"
	"zerotrust-proxy/internal/proxy"
	"zerotrust-proxy/internal/store"
)

// storeOptions maps the valkey config block onto store.StoreOptions: mode
// "sentinel" uses SentinelAddrs + MasterName, anything else is direct against
// Addr; valkey.ssl.enabled loads the TLS files once here (fail fast) with the
// ServerName taken from the first address' host — DIRECT MODE ONLY (review
// 2026-08-17): in sentinel mode the MASTER's host is unknown until discovery,
// and the sentinel's hostname would be wrong for the master connections
// (BuildClientOption wires the same TLS config to both), failing cert
// verification when sentinel and master live on different hosts. Sentinel
// TLS therefore leaves ServerName unset — rely on the CA chain, IP SANs, or
// valkey.ssl.skip_verify.
func storeOptions(vc config.ValkeyConfig) (store.StoreOptions, error) {
	opts := store.StoreOptions{Password: vc.Password, DB: vc.DB}
	if vc.Mode == "sentinel" {
		opts.Addrs = vc.SentinelAddrs
		opts.MasterName = vc.MasterName
		opts.SentinelPassword = vc.SentinelPassword
	} else {
		opts.Addrs = []string{vc.Addr}
	}
	if !vc.SSL.Enabled {
		return opts, nil
	}
	var serverName string
	if vc.Mode != "sentinel" && len(opts.Addrs) > 0 {
		if host, _, err := net.SplitHostPort(opts.Addrs[0]); err == nil {
			serverName = host
		}
	}
	tlsCfg, err := store.TLSFromFiles(vc.SSL.CAFile, vc.SSL.CertFile, vc.SSL.KeyFile, vc.SSL.SkipVerify, serverName)
	if err != nil {
		return opts, err
	}
	opts.TLS = tlsCfg
	return opts, nil
}

// buildCredResolver constructs the backend-password resolver from the data
// config (Task 8.7): credentials_source "config" wraps the committed
// credentials list in a ConfigCredResolver (pre-8.7 behavior); "api" builds
// an APICredResolver against credentials_api (vault contract: GET
// ?db_type&db_user&db_ip&db_port with X-Api-Key → {"password"}). The
// config layer already fail-fasts on source=api with an empty URL; the
// constructor fail-fasts here on a malformed URL. The password is never
// stored or logged — it exists in memory only for each in-flight connect.
func buildCredResolver(cfg *config.DataConfig) (proxy.CredResolver, error) {
	if cfg.CredentialsSource == "api" {
		return proxy.NewAPICredResolver(
			cfg.CredentialsAPI.URL,
			cfg.CredentialsAPI.APIKey,
			time.Duration(cfg.CredentialsAPI.TimeoutSeconds)*time.Second,
		)
	}
	return &proxy.ConfigCredResolver{Creds: cfg.Credentials}, nil
}

func main() {
	log := logging.New("data")
	cfg, err := config.LoadData("configs/data.yaml")
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// NewValkeyStore pings Valkey during construction (3s timeout) — fail fast
	// here if the shared store is unreachable.
	opts, err := storeOptions(cfg.Valkey)
	if err != nil {
		log.Error("valkey tls", "err", err)
		os.Exit(1)
	}
	vs, err := store.NewValkeyStore(ctx, opts)
	if err != nil {
		log.Error("valkey", "err", err)
		os.Exit(1)
	}
	defer vs.Close()

	// Both proxies share one listener: the Dispatcher detects the protocol per
	// connection (PG client-first, MySQL server-first) and routes accordingly.
	// The proxies are also handed to the kill switch below: the ctl:kill
	// subscriber fans out to both registries (Task 6.4).
	//
	// Client-side TLS (Tasks 7.4 + 7.5): when tls.enabled, load the cert/key
	// pair (the config layer already fail-fasts on enabled+missing/unreadable)
	// and hand the SAME tls.Config to both proxies — MySQL advertises
	// CLIENT_SSL and answers SSLRequests, PostgreSQL answers SSLRequest with
	// 'S' and runs the TLS handshake before the real StartupMessage. nil
	// keeps the plaintext wire path for both.
	var dataTLS *tls.Config
	if cfg.TLS != nil {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			log.Error("data plane tls", "err", err)
			os.Exit(1)
		}
		dataTLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	// Task 8.7: the backend-password source is a CredResolver — config list
	// (default) or per-connect credential API. The password is never stored
	// or logged.
	credResolver, err := buildCredResolver(cfg)
	if err != nil {
		log.Error("credentials", "err", err)
		os.Exit(1)
	}
	mysqlProxy := proxy.NewMySQLProxy(log, vs, credResolver, dataTLS)
	pgProxy := proxy.NewPGProxy(log, vs, credResolver, dataTLS)
	// Task 9.2: the TDS (SQL Server) proxy shares the listener; the
	// Dispatcher detects it client-first (first byte 0x12 = PRELOGIN) and
	// routes here. Client-side TLS (same dataTLS): the proxy answers the
	// client PRELOGIN with ENCRYPT_ON and upgrades through the 0x12-wrapped
	// TDS 8.0 wiring; nil keeps the plaintext ENCRYPT_NOT_SUP path (sqlcmd
	// needs -N o then).
	mssqlProxy := proxy.NewMSSQLProxy(log, vs, credResolver, dataTLS)
	// Task 8.8 query logging: every query is ALWAYS logged with context;
	// the captured result payload (columns/rows/row_count/truncated) is
	// added only when log_query_output is on (configs/data.yaml,
	// ZT_LOG_QUERY_OUTPUT).
	mysqlProxy.SetLogQueryOutput(cfg.LogQueryOutput)
	pgProxy.SetLogQueryOutput(cfg.LogQueryOutput)
	mssqlProxy.SetLogQueryOutput(cfg.LogQueryOutput)
	// Task 8.13 maker write-gate grace hold: blocked SQL commands on an
	// unwatched write session wait up to gate_wait_seconds for a checker
	// instead of failing instantly (0 = reject immediately, the pre-8.13
	// behavior; configs/data.yaml, ZT_GATE_WAIT_SECONDS).
	mysqlProxy.SetGateWaitSeconds(cfg.GateWaitSeconds)
	pgProxy.SetGateWaitSeconds(cfg.GateWaitSeconds)
	mssqlProxy.SetGateWaitSeconds(cfg.GateWaitSeconds)
	// Task 9.8 OTel metrics: enabled (configs/data.yaml metrics block,
	// ZT_METRICS_ENABLED) builds the Prometheus-backed meter wrapper and
	// wires it into every instrumented site; disabled (default) leaves the
	// wrapper nil and every call site a no-op.
	m, err := metrics.New(cfg.Metrics.Enabled)
	if err != nil {
		log.Error("metrics", "err", err)
		os.Exit(1)
	}
	mysqlProxy.SetMetrics(m)
	pgProxy.SetMetrics(m)
	mssqlProxy.SetMetrics(m)
	killer := proxy.NewKiller(mysqlProxy, pgProxy, mssqlProxy)
	killer.SetMetrics(m)

	// Task 9.8 metrics endpoint: when enabled, serve the Prometheus scrape
	// on its own goroutine (configs/data.yaml metrics block,
	// ZT_METRICS_LISTEN + ZT_METRICS_PATH; defaults 0.0.0.0:9464
	// /metrics). The config layer already fail-fasted on a malformed
	// listen address; a bind failure here is fatal too — a configured
	// scrape endpoint that cannot serve must not silently degrade
	// observability. Shutdown is graceful: srv.Shutdown on the way out.
	var metricsSrv *http.Server
	if m != nil {
		mux := http.NewServeMux()
		mux.Handle(cfg.Metrics.Path, m.Handler())
		metricsSrv = &http.Server{Addr: cfg.Metrics.Listen, Handler: mux}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics http", "err", err)
				os.Exit(1)
			}
		}()
		log.Info("metrics endpoint", "addr", cfg.Metrics.Listen, "path", cfg.Metrics.Path)
	}
	d := proxy.NewDispatcher(
		log,
		mysqlProxy,
		pgProxy,
		mssqlProxy, // TDS proxy wired in Task 9.2 — detected TDS clients are served
		time.Duration(cfg.DetectDelayMS)*time.Millisecond,
		int64(cfg.MaxConns),
	)

	l, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	log.Info("dispatcher listening", "addr", cfg.ListenAddr)

	serveErr := make(chan error, 1)
	go func() { serveErr <- d.Serve(l, ctx) }()

	// Kill switch (Task 6.4 + Task 8.3 two-level kill): subscribe to the
	// ctl:kill channel — the ONLY coupling between planes (no HTTP). Each
	// message carries {"session_id": "...", "mode": "query"|"connection"}
	// (mode absent = connection, Task 6.4 backward compat); the combined
	// killer fans out to whichever plane holds the session. HandleKill
	// returns the outcome log line ("session killed" / "query killed" /
	// "kill: unknown session" / "kill: unknown mode") plus the session id;
	// a malformed payload returns ("", "") and is dropped silently.
	// Subscribe blocks until ctx cancellation (it then returns ctx.Err(),
	// which is not an error here), so the channel is closed on the way out
	// and the consumer loop below exits with it.
	killCh := make(chan []byte, 16)
	go func() {
		defer close(killCh)
		if err := vs.Subscribe(ctx, "ctl:kill", false, killCh); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("kill subscriber", "err", err)
		}
	}()
	go func() {
		for msg := range killCh {
			line, sid := killer.HandleKill(msg)
			if line == "" {
				continue
			}
			switch line {
			case "session killed", "query killed":
				log.Info(line, "session_id", sid)
			default:
				log.Warn(line, "session_id", sid)
			}
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Fail fast on fatal errors (select pattern): an unexpected Serve error
	// exits non-zero even without a signal; a signal triggers graceful shutdown.
	select {
	case <-stop:
		log.Info("shutting down")
	case err := <-serveErr:
		if err != nil {
			log.Error("dispatcher", "err", err)
			os.Exit(1)
		}
	}

	// Critical: Serve only sees ctx cancellation AFTER Accept returns, so the
	// listener MUST be closed to unblock the blocked Accept; Serve then
	// returns nil via ctx.Err(). Cancel first, then close.
	cancel()
	_ = l.Close()
	if metricsSrv != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = metricsSrv.Shutdown(shutdownCtx)
	}

	// Bound the shutdown wait at 5s.
	select {
	case <-serveErr:
		log.Info("dispatcher stopped")
	case <-time.After(5 * time.Second):
		log.Warn("dispatcher did not stop within 5s")
	}
}
