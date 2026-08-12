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

	apiSrv := api.NewAPI(log, cfg, vs) // Task 2.2/2.3 replaces the stub
	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: apiSrv.Routes()}

	go func() {
		log.Info("control plane listening", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http", "err", err)
			cancel()
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Info("shutting down")
	shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shCancel()
	_ = srv.Shutdown(shCtx)
}
