package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"crowdshield/internal/config"
)

type statusJSON struct {
	Status          string       `json:"status"`
	Reason          StatusReason `json:"reason"`
	LastSafeSync    string       `json:"last_safe_sync,omitempty"`
	ActiveDecisions int64        `json:"active_decisions"`
	LastOutcome     string       `json:"last_outcome,omitempty"`
	LastFailure     string       `json:"last_failure,omitempty"`
}

func statusCommand(ctx context.Context, args []string, stdout, stderr io.Writer, options Options) int {
	flags := commandFlags("status")
	path := flags.String("config", config.DefaultPath, "configuration file")
	asJSON := flags.Bool("json", false, "emit JSON")
	if flags.Parse(args) != nil || flags.NArg() != 0 || options.LoadConfig == nil {
		writeUsage(stderr)
		return ExitUsage
	}
	loaded, err := options.LoadConfig(*path)
	if err != nil || loaded.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "configuration invalid")
		return ExitUsage
	}
	if options.Actions.Status == nil {
		_, _ = fmt.Fprintln(stderr, "status unavailable")
		return ExitOperational
	}
	status, err := options.Actions.Status(ctx, loaded)
	if err != nil || status.Validate() != nil {
		_, _ = fmt.Fprintln(stderr, "status unavailable")
		return ExitOperational
	}
	state := "not_ready"
	if status.Ready {
		state = "ready"
	}
	if *asJSON {
		output := statusJSON{
			Status: state, Reason: status.Reason, ActiveDecisions: status.ActiveDecisions,
			LastOutcome: string(status.LastOutcome), LastFailure: string(status.LastFailure),
		}
		if !status.LastSafeSync.IsZero() {
			output.LastSafeSync = status.LastSafeSync.UTC().Format(time.RFC3339)
		}
		if json.NewEncoder(stdout).Encode(output) != nil {
			return ExitOperational
		}
	} else {
		_, _ = fmt.Fprintf(stdout, "status=%s reason=%s active_decisions=%d", state, status.Reason, status.ActiveDecisions)
		if !status.LastSafeSync.IsZero() {
			_, _ = fmt.Fprintf(stdout, " last_safe_sync=%s", status.LastSafeSync.UTC().Format(time.RFC3339))
		}
		if status.LastOutcome != "" {
			_, _ = fmt.Fprintf(stdout, " last_outcome=%s", status.LastOutcome)
		}
		if status.LastFailure != "" {
			_, _ = fmt.Fprintf(stdout, " last_failure=%s", status.LastFailure)
		}
		_, _ = fmt.Fprintln(stdout)
	}
	if !status.Ready {
		return ExitNotReady
	}
	return ExitSuccess
}
