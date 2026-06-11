package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ken9xkyo/anti-ddos/internal/agent"
	"github.com/ken9xkyo/anti-ddos/internal/control"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: control-api migrate|serve|print-migrations")
		os.Exit(2)
	}

	cfg := control.LoadConfigFromEnv()
	switch os.Args[1] {
	case "print-migrations":
		fmt.Print(control.SQLMigrationText())
	case "migrate":
		if err := cfg.Validate(true); err != nil {
			logger.Error("invalid config", "error", agent.RedactString(err.Error()))
			os.Exit(2)
		}
		if err := runMigrate(context.Background(), cfg); err != nil {
			logger.Error("migrate failed", "error", agent.RedactString(err.Error()))
			os.Exit(1)
		}
	case "serve":
		if err := cfg.Validate(true); err != nil {
			logger.Error("invalid config", "error", agent.RedactString(err.Error()))
			os.Exit(2)
		}
		if err := runServe(cfg, logger); err != nil {
			logger.Error("server stopped", "error", agent.RedactString(err.Error()))
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func runMigrate(ctx context.Context, cfg control.Config) error {
	pool, err := control.OpenPool(ctx, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	return control.RunMigrations(ctx, pool)
}

func runServe(cfg control.Config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := control.OpenPool(ctx, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := control.RunMigrations(ctx, pool); err != nil {
		return err
	}
	store := control.NewStore(pool, cfg, logger)
	handler := control.NewServer(store, cfg, logger)
	handler.StartBackgroundSchedulers(ctx)
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("control api listening", "addr", cfg.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
