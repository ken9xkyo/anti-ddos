package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ken9xkyo/anti-ddos/internal/agent"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := agent.LoadConfigFromEnv()
	if err != nil {
		logger.Error("invalid config", "error", agent.RedactString(err.Error()))
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	nodeAgent, err := agent.New(cfg, logger)
	if err != nil {
		logger.Error("create agent", "error", agent.RedactString(err.Error()))
		os.Exit(2)
	}

	if err := nodeAgent.Run(ctx); err != nil {
		logger.Error("agent stopped with error", "error", agent.RedactString(err.Error()))
		os.Exit(1)
	}
}
