package main

import (
	"context"
	"errors"
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

func main() {
	log := logging.New("control")
	cfg, err := config.LoadControl("configs/control.yaml")
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vs, err := store.NewValkeyStore(ctx, cfg.Valkey.Addr, cfg.Valkey.Password, cfg.Valkey.DB)
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
