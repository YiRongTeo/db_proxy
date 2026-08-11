package main

import (
	"context"
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
	vs, err := store.NewValkeyStore(ctx, cfg.ValkeyAddr, cfg.ValkeyPassword, cfg.ValkeyDB)
	if err != nil {
		log.Error("valkey", "err", err)
		os.Exit(1)
	}
	defer vs.Close()

	// Both proxies share one listener: the Dispatcher detects the protocol per
	// connection (PG client-first, MySQL server-first) and routes accordingly.
	d := proxy.NewDispatcher(
		log,
		proxy.NewMySQLProxy(log, vs, cfg.Credentials),
		proxy.NewPGProxy(log, vs, cfg.Credentials),
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
