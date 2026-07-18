package cli

import (
	"context"
	"fmt"
	"io"

	"crowdshield/internal/config"
)

func dbCommand(ctx context.Context, args []string, stdout, stderr io.Writer, options Options) int {
	if len(args) == 0 || args[0] != "check" {
		writeUsage(stderr)
		return ExitUsage
	}
	flags := commandFlags("db check")
	path := flags.String("config", config.DefaultPath, "configuration file")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || options.LoadConfig == nil {
		writeUsage(stderr)
		return ExitUsage
	}
	loaded, err := options.LoadConfig(*path)
	if err != nil || loaded.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "configuration invalid")
		return ExitUsage
	}
	if options.Actions.DBCheck == nil || options.Actions.DBCheck(ctx, loaded) != nil {
		_, _ = fmt.Fprintln(stderr, "database check failed")
		return ExitOperational
	}
	_, _ = fmt.Fprintln(stdout, "database ok")
	return ExitSuccess
}
