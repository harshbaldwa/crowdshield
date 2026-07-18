package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"crowdshield/internal/config"
	"crowdshield/internal/ops"
)

type SyncRequest struct {
	DryRun bool
	Feed   string
}

type syncOutput struct {
	Outcome         ops.Outcome         `json:"outcome"`
	Failure         ops.FailureCategory `json:"failure,omitempty"`
	FeedsSucceeded  int64               `json:"feeds_succeeded"`
	FeedsFailed     int64               `json:"feeds_failed"`
	FeedsUnchanged  int64               `json:"feeds_unchanged"`
	FeedsNotDue     int64               `json:"feeds_not_due"`
	Added           int64               `json:"added"`
	Refreshed       int64               `json:"refreshed"`
	Removed         int64               `json:"removed"`
	Rejected        int64               `json:"rejected"`
	Skipped         int64               `json:"skipped"`
	LAPIRequests    int64               `json:"lapi_requests"`
	ActiveDecisions int64               `json:"active_decisions"`
}

func outputForSync(result ops.Result) syncOutput {
	return syncOutput{
		Outcome: result.Outcome, Failure: result.Failure,
		FeedsSucceeded: result.Counts.FeedsSucceeded, FeedsFailed: result.Counts.FeedsFailed,
		FeedsUnchanged: result.Counts.FeedsUnchanged, FeedsNotDue: result.Counts.FeedsNotDue,
		Added: result.Counts.Added, Refreshed: result.Counts.Refreshed, Removed: result.Counts.Removed,
		Rejected: result.Counts.Rejected, Skipped: result.Counts.Skipped,
		LAPIRequests: result.Counts.LAPIRequests, ActiveDecisions: result.Counts.ActiveDecisions,
	}
}

func syncExit(result ops.Result) int {
	if result.Failure == ops.FailureConfig {
		return ExitUsage
	}
	if result.Failure == ops.FailureOwnership {
		return ExitOwnership
	}
	switch result.Outcome {
	case ops.OutcomeSuccess:
		return ExitSuccess
	case ops.OutcomeDegraded:
		return ExitNotReady
	default:
		return ExitOperational
	}
}

func syncCommand(ctx context.Context, args []string, stdout, stderr io.Writer, options Options) int {
	flags := commandFlags("sync")
	path := flags.String("config", config.DefaultPath, "configuration file")
	dryRun := flags.Bool("dry-run", false, "preview without persistence or LAPI writes")
	feedName := flags.String("feed", "", "configured feed name")
	asJSON := flags.Bool("json", false, "emit JSON")
	if flags.Parse(args) != nil || flags.NArg() != 0 || options.LoadConfig == nil ||
		(*feedName != "" && !ops.ValidFeedName(*feedName)) {
		writeUsage(stderr)
		return ExitUsage
	}
	loaded, err := options.LoadConfig(*path)
	if err != nil || loaded.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "configuration invalid")
		return ExitUsage
	}
	if options.Actions.Sync == nil {
		_, _ = fmt.Fprintln(stderr, "synchronization failed")
		return ExitOperational
	}
	result, err := options.Actions.Sync(ctx, loaded, SyncRequest{DryRun: *dryRun, Feed: *feedName})
	if err != nil || result.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "synchronization failed")
		return ExitOperational
	}
	output := outputForSync(result)
	if *asJSON {
		if json.NewEncoder(stdout).Encode(output) != nil {
			return ExitOperational
		}
	} else {
		_, _ = fmt.Fprintf(stdout,
			"outcome=%s failure=%s feeds_succeeded=%d feeds_failed=%d feeds_unchanged=%d feeds_not_due=%d added=%d refreshed=%d removed=%d rejected=%d skipped=%d lapi_requests=%d active_decisions=%d\n",
			output.Outcome, output.Failure, output.FeedsSucceeded, output.FeedsFailed,
			output.FeedsUnchanged, output.FeedsNotDue, output.Added, output.Refreshed,
			output.Removed, output.Rejected, output.Skipped, output.LAPIRequests, output.ActiveDecisions,
		)
	}
	return syncExit(result)
}
