package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"

	"crowdshield/internal/config"
)

func validExplainInput(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.IsValid()
	}
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix.IsValid()
}

func explainCommand(ctx context.Context, args []string, stdout, stderr io.Writer, options Options) int {
	flags := commandFlags("explain")
	path := flags.String("config", config.DefaultPath, "configuration file")
	asJSON := flags.Bool("json", false, "emit JSON")
	if flags.Parse(args) != nil || flags.NArg() != 1 || options.LoadConfig == nil || !validExplainInput(flags.Arg(0)) {
		writeUsage(stderr)
		return ExitUsage
	}
	loaded, err := options.LoadConfig(*path)
	if err != nil || loaded.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "configuration invalid")
		return ExitUsage
	}
	if options.Actions.Explain == nil {
		_, _ = fmt.Fprintln(stderr, "explanation unavailable")
		return ExitOperational
	}
	result, err := options.Actions.Explain(ctx, loaded, flags.Arg(0))
	if err != nil || result.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "explanation unavailable")
		return ExitOperational
	}
	result.Contributors = append([]string(nil), result.Contributors...)
	sort.Strings(result.Contributors)
	if *asJSON {
		if json.NewEncoder(stdout).Encode(result) != nil {
			return ExitOperational
		}
	} else {
		_, _ = fmt.Fprintf(stdout,
			"canonical=%s kind=%s desired=%t allowlisted=%t covered=%t owned=%t ownership_conflict=%t",
			result.Canonical, result.Kind, result.Desired, result.Allowlisted,
			result.Covered, result.Owned, result.OwnershipConflict,
		)
		if result.Covered {
			_, _ = fmt.Fprintf(stdout, " covering_prefix=%s", result.CoveringPrefix)
		}
		_, _ = fmt.Fprintf(stdout, " contributors=%s\n", strings.Join(result.Contributors, ","))
	}
	if result.OwnershipConflict {
		return ExitOwnership
	}
	return ExitSuccess
}
