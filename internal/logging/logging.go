package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New builds the plane's JSON logger. The level is read from the
// ZT_LOG_LEVEL env var (debug|info|warn|error; default info) so operators
// can raise verbosity without rebuilding — both planes construct their
// logger through this single entry point.
func New(service string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("ZT_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	case "", "info":
		level = slog.LevelInfo
	default:
		// Unknown values degrade to info (never fail the plane's boot for
		// a log-level typo; the docs spell out the accepted values).
		level = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})).
		With("service", service)
}
