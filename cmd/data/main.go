package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/logging"
	"zerotrust-proxy/internal/proxy"
	"zerotrust-proxy/internal/store"
)

// storeOptions maps the valkey config block onto store.StoreOptions: mode
// "sentinel" uses SentinelAddrs + MasterName, anything else is direct against
// Addr; valkey.ssl.enabled loads the TLS files once here (fail fast) with the
// ServerName taken from the first address' host.
func storeOptions(vc config.ValkeyConfig) (store.StoreOptions, error) {
	opts := store.StoreOptions{Password: vc.Password, DB: vc.DB}
	if vc.Mode == "sentinel" {
		opts.Addrs = vc.SentinelAddrs
		opts.MasterName = vc.MasterName
		opts.SentinelUsername = vc.SentinelUsername
		opts.SentinelPassword = vc.SentinelPassword
	} else {
		opts.Addrs = []string{vc.Addr}
	}
	if !vc.SSL.Enabled {
		return opts, nil
	}
	var serverName string
	if len(opts.Addrs) > 0 {
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
	d := proxy.NewDispatcher(
		log,
		mysqlProxy,
		pgProxy,
		time.Duration(cfg.DetectDelayMS)*time.Millisecond,
		int64(cfg.MaxConns),
	)
	killer := proxy.NewKiller(mysqlProxy, pgProxy)

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

	// Bound the shutdown wait at 5s.
	select {
	case <-serveErr:
		log.Info("dispatcher stopped")
	case <-time.After(5 * time.Second):
		log.Warn("dispatcher did not stop within 5s")
	}
}
