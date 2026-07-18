package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"crowdshield/internal/config"
)

const PruneConfirmation = "DELETE-EXPIRED-CROWDSHIELD-HISTORY"

type PruneResult struct {
	SyncRuns           int64 `json:"sync_runs"`
	Operations         int64 `json:"operations"`
	Decisions          int64 `json:"decisions"`
	Alerts             int64 `json:"alerts"`
	EnforcementObjects int64 `json:"enforcement_objects"`
	FeedEntries        int64 `json:"feed_entries"`
	OwnershipConflicts int64 `json:"ownership_conflicts"`
}

func (r PruneResult) Validate() error {
	for _, count := range []int64{
		r.SyncRuns, r.Operations, r.Decisions, r.Alerts,
		r.EnforcementObjects, r.FeedEntries, r.OwnershipConflicts,
	} {
		if count < 0 || count > maxOperatorCount {
			return ErrInvalidOperatorResult
		}
	}
	return nil
}

type pruneOutput struct {
	Mode string `json:"mode"`
	PruneResult
}

func pruneCommand(ctx context.Context, args []string, stdout, stderr io.Writer, options Options) int {
	flags := commandFlags("prune")
	path := flags.String("config", config.DefaultPath, "configuration file")
	confirmation := flags.String("confirm", "", "exact destructive confirmation")
	asJSON := flags.Bool("json", false, "emit JSON")
	if flags.Parse(args) != nil || flags.NArg() != 0 || options.LoadConfig == nil ||
		(*confirmation != "" && *confirmation != PruneConfirmation) {
		writeUsage(stderr)
		return ExitUsage
	}
	loaded, err := options.LoadConfig(*path)
	if err != nil || loaded.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "configuration invalid")
		return ExitUsage
	}
	if options.Actions.Prune == nil {
		_, _ = fmt.Fprintln(stderr, "prune unavailable")
		return ExitOperational
	}
	confirmed := *confirmation == PruneConfirmation
	result, err := options.Actions.Prune(ctx, loaded, confirmed)
	if err != nil || result.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "prune unavailable")
		return ExitOperational
	}
	mode := "plan"
	if result.OwnershipConflicts > 0 {
		mode = "blocked"
	} else if confirmed {
		mode = "applied"
	}
	if *asJSON {
		if json.NewEncoder(stdout).Encode(pruneOutput{Mode: mode, PruneResult: result}) != nil {
			return ExitOperational
		}
	} else {
		_, _ = fmt.Fprintf(stdout,
			"mode=%s sync_runs=%d operations=%d decisions=%d alerts=%d enforcement_objects=%d feed_entries=%d ownership_conflicts=%d\n",
			mode, result.SyncRuns, result.Operations, result.Decisions, result.Alerts,
			result.EnforcementObjects, result.FeedEntries, result.OwnershipConflicts,
		)
	}
	if result.OwnershipConflicts > 0 {
		return ExitOwnership
	}
	return ExitSuccess
}
