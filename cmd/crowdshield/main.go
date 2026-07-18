package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"crowdshield/internal/app"
	"crowdshield/internal/buildinfo"
	"crowdshield/internal/cli"
	"crowdshield/internal/config"
)

func main() {
	ctx, stop := signalContext(context.Background())
	defer stop()
	os.Exit(runContext(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdout, stderr)
}

func runContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return cli.Execute(ctx, args, stdout, stderr, productionOptions())
}

func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

func productionOptions() cli.Options {
	version := buildinfo.Current()
	loader := config.DefaultLoader(version.Version)
	return cli.Options{
		Version:    version,
		LoadConfig: loader.Load,
		Actions: cli.Actions{
			ValidateConfig: app.ValidateCLIConfig,
			Run:            app.RunCLI,
			Sync:           app.SyncCLI,
			Status:         app.StatusCLI,
			ListFeeds:      app.ListFeedsCLI,
			Explain:        app.ExplainCLI,
			Prune:          app.PruneCLI,
			DBCheck:        app.DBCheckCLI,
		},
	}
}
