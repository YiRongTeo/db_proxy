package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"zerotrust-proxy/internal/api"
	"zerotrust-proxy/internal/audit"
	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/logging"
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

func main() {
	log := logging.New("control")
	cfg, err := config.LoadControl("configs/control.yaml")
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

	// Task 9.7 session audit: when audit.mysql.enabled is set, open the
	// writer (auto-creates zt_audit.sessions) and fail fast if the database
	// is unreachable — an audit-enabled plane that cannot write must not
	// start silently. Runtime write failures stay non-fatal (logged only).
	var aw *audit.Writer
	if cfg.Audit.MySQL.Enabled {
		aw, err = audit.NewWriter(log, audit.Config{
			Host: cfg.Audit.MySQL.Host, Port: cfg.Audit.MySQL.Port,
			User: cfg.Audit.MySQL.User, Password: cfg.Audit.MySQL.Password,
			Database: cfg.Audit.MySQL.Database,
		})
		if err != nil {
			log.Error("audit mysql", "err", err)
			os.Exit(1)
		}
		defer aw.Close()
		log.Info("session audit enabled", "host", cfg.Audit.MySQL.Host,
			"port", cfg.Audit.MySQL.Port, "database", cfg.Audit.MySQL.Database)
	}

	apiSrv := api.NewAPI(log, cfg, vs, aw) // Task 2.2/2.3 replaces the stub
	if aw != nil {
		// Consume the hub's queries:sess:* lifecycle events (started/ended)
		// into the audit writer for the process lifetime.
		go apiSrv.RunAuditLifecycle(ctx)
		// Review 9.9: expire stale pending audit rows (token issued, maker
		// never connected) on a timer — the audit trail must terminate.
		go apiSrv.RunAuditSweeper(ctx)
	}
	// Review 9.9: server timeouts — bounded header/body reads (slowloris
	// hardening), bounded response writes and a keep-alive idle window.
	// WebSocket connections are exempt: hijacked conns bypass WriteTimeout,
	// and the hub applies its own per-write deadlines (watchWriteTimeout).
	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           apiSrv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	go func() {
		if cfg.TLS != nil && cfg.TLS.Enabled {
			log.Info("control plane listening (https)", "addr", cfg.HTTPAddr)
			if err := srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				// Review 9.9c: a bind/serve failure must FAIL FAST — the old
				// cancel()-only path left main blocked on <-stop forever.
				log.Error("https", "err", err)
				os.Exit(1)
			}
			return
		}
		log.Info("control plane listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http", "err", err)
			os.Exit(1)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Info("shutting down")
	shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shCancel()
	if err := srv.Shutdown(shCtx); err != nil {
		log.Warn("shutdown", "err", err)
	}
}
