package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ken9xkyo/anti-ddos/internal/agent"
	"github.com/ken9xkyo/anti-ddos/internal/control"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: control-admin bootstrap --username admin --password-stdin")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "bootstrap":
		if err := bootstrap(logger, os.Args[2:]); err != nil {
			logger.Error("bootstrap failed", "error", agent.RedactString(err.Error()))
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func bootstrap(logger *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	username := fs.String("username", "admin", "admin username")
	passwordStdin := fs.Bool("password-stdin", false, "read password from stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*passwordStdin {
		return fmt.Errorf("--password-stdin is required")
	}
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	password = strings.TrimRight(password, "\r\n")

	cfg := control.LoadConfigFromEnv()
	if err := cfg.Validate(true); err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := control.OpenPool(ctx, cfg.DBDSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := control.RunMigrations(ctx, pool); err != nil {
		return err
	}
	store := control.NewStore(pool, cfg, logger)
	user, err := store.BootstrapAdmin(ctx, *username, password)
	if err != nil {
		return err
	}
	fmt.Printf("bootstrapped admin %s (%s)\n", user.Username, user.ID)
	return nil
}
