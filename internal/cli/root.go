package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/config"
	"crowdshield/internal/ops"
)

const (
	ExitSuccess     = 0
	ExitOperational = 1
	ExitUsage       = 2
	ExitNotReady    = 3
	ExitOwnership   = 4
)

const Usage = "usage: crowdshield <run|sync|status|validate-config|list-feeds|explain|prune|db|version|help> [options]"

type ConfigLoader func(string) (config.Config, error)

type Actions struct {
	Run       func(context.Context, config.Config, bool, io.Writer) error
	Status    func(context.Context, config.Config) (Status, error)
	Sync      func(context.Context, config.Config, SyncRequest) (ops.Result, error)
	ListFeeds func(context.Context, config.Config) ([]FeedStatus, error)
	Explain   func(context.Context, config.Config, string) (ExplainResult, error)
	Prune     func(context.Context, config.Config, bool) (PruneResult, error)
	DBCheck   func(context.Context, config.Config) error
}

type Options struct {
	Version    buildinfo.Info
	LoadConfig ConfigLoader
	Actions    Actions
}

func writeUsage(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, Usage)
}

func commandFlags(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func validateConfig(args []string, stdout, stderr io.Writer, options Options) int {
	flags := commandFlags("validate-config")
	path := flags.String("config", config.DefaultPath, "configuration file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || options.LoadConfig == nil {
		writeUsage(stderr)
		return ExitUsage
	}
	loaded, err := options.LoadConfig(*path)
	if err != nil || loaded.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "configuration invalid")
		return ExitUsage
	}
	_, _ = fmt.Fprintln(stdout, "configuration valid")
	return ExitSuccess
}

func runCommand(ctx context.Context, args []string, stdout, stderr io.Writer, options Options) int {
	flags := commandFlags("run")
	path := flags.String("config", config.DefaultPath, "configuration file")
	runOnce := flags.Bool("run-once", false, "run one synchronization and stop")
	if flags.Parse(args) != nil || flags.NArg() != 0 || options.LoadConfig == nil {
		writeUsage(stderr)
		return ExitUsage
	}
	loaded, err := options.LoadConfig(*path)
	if err != nil || loaded.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "configuration invalid")
		return ExitUsage
	}
	if options.Actions.Run == nil || options.Actions.Run(ctx, loaded, *runOnce, stdout) != nil {
		_, _ = fmt.Fprintln(stderr, "runtime failed")
		return ExitOperational
	}
	return ExitSuccess
}

func Execute(ctx context.Context, args []string, stdout, stderr io.Writer, options Options) int {
	if ctx == nil || stdout == nil || stderr == nil {
		return ExitUsage
	}
	if len(args) == 0 {
		writeUsage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "help":
		if len(args) != 1 {
			writeUsage(stderr)
			return ExitUsage
		}
		writeUsage(stdout)
		return ExitSuccess
	case "version":
		if len(args) != 1 {
			writeUsage(stderr)
			return ExitUsage
		}
		_, _ = fmt.Fprintln(stdout, options.Version.String())
		return ExitSuccess
	case "validate-config":
		return validateConfig(args[1:], stdout, stderr, options)
	case "run":
		return runCommand(ctx, args[1:], stdout, stderr, options)
	case "status":
		return statusCommand(ctx, args[1:], stdout, stderr, options)
	case "sync":
		return syncCommand(ctx, args[1:], stdout, stderr, options)
	case "list-feeds":
		return listFeedsCommand(ctx, args[1:], stdout, stderr, options)
	case "explain":
		return explainCommand(ctx, args[1:], stdout, stderr, options)
	case "prune":
		return pruneCommand(ctx, args[1:], stdout, stderr, options)
	case "db":
		return dbCommand(ctx, args[1:], stdout, stderr, options)
	default:
		writeUsage(stderr)
		return ExitUsage
	}
}
