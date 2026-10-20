package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
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

// serveControl builds the http.Server over api.NewAPI(...).Routes() and
// serves it on cfg.HTTPAddr — TLS when the native http.tls pair resolved
// (ListenAndServeTLS with the hardcoded TLS 1.2 floor), plain HTTP
// otherwise (G3: byte-identical to the historical listener). It returns the
// ACTUAL listen address (the caller's cfg.HTTPAddr may be :0) and a stop
// func shutting the server down; a TLS setup failure (unreadable/unparsable
// cert or key) is returned as an ERROR so the boot fails fast — never a
// silent plaintext fallback. Run-loop errors after a successful bind surface
// the same way (the caller decides to exit; ErrServerClosed is nil-ed).
func serveControl(ctx context.Context, log *slog.Logger, cfg *config.ControlConfig, vs *store.ValkeyStore, aw *audit.Writer) (string, func(), error) {
	apiSrv := api.NewAPI(log, cfg, vs, aw)
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
	if cfg.TLS != nil && cfg.TLS.Enabled {
		// Hardcoded TLS 1.2 floor (design: no min-version knob needed) —
		// set BEFORE serving so the policy is effective from the very
		// first handshake.
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		// LoadX509KeyPair HERE (not lazily at the first handshake): a
		// broken/unreadable cert or key fails the BOOT (a returned error),
		// never the first browser connection.
		pair, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return "", func() {}, fmt.Errorf("http.tls: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
		ln, err := tls.Listen("tcp", cfg.HTTPAddr, tlsCfg)
		if err != nil {
			return "", func() {}, err
		}
		// Keep the server's TLSConfig in sync for any Accept-derived use.
		srv.TLSConfig = tlsCfg
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("https", "err", err)
			}
		}()
		return ln.Addr().String(), stopShared(srv, log), nil
	}
	ln, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return "", func() {}, err
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http", "err", err)
		}
	}()
	return ln.Addr().String(), stopShared(srv, log), nil
}

// stopShared shuts the server down with the historical 5s grace window
// (Review 9.9 shutdown semantics), warning on in-flight work that did not
// drain in time.
func stopShared(srv *http.Server, log *slog.Logger) func() {
	return func() {
		shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shCancel()
		if err := srv.Shutdown(shCtx); err != nil {
			log.Warn("shutdown", "err", err)
		}
	}
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
	// Native TLS: serveControl fails fast on a broken listener — TLS setup
	// errors exit the process, they never fall back to plaintext.
	_, stop, err := serveControl(ctx, log, cfg, vs, aw)
	if err != nil {
		// Fail fast (Review 9.9c): a bind/serve failure must exit the
		// process — never fall back to plaintext, never block on <-stop.
		log.Error("control plane listen", "err", err)
		os.Exit(1)
	}
	// The boot line keeps its historical shape and GAINS the tls field —
	// the operator sees the serving mode at a glance in every log sink.
	log.Info("control plane listening", "addr", cfg.HTTPAddr, "tls", cfg.TLS != nil && cfg.TLS.Enabled)
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	<-stopChan
	log.Info("shutting down")
	stop()
}
