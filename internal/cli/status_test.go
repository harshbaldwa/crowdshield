package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/config"
	"crowdshield/internal/ops"
)

func TestStatusHasBoundedHumanAndJSONOutput(t *testing.T) {
	at := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	status := Status{
		Ready: true, Reason: StatusReady, LastSafeSync: at,
		ActiveDecisions: 7, LastOutcome: ops.OutcomeSuccess,
	}
	options := Options{
		Version:    buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
		Actions:    Actions{Status: func(context.Context, config.Config) (Status, error) { return status, nil }},
	}
	for _, test := range []struct {
		args []string
		want string
	}{
		{args: []string{"status"}, want: "status=ready reason=ready active_decisions=7"},
		{args: []string{"status", "--json"}, want: `"active_decisions":7`},
	} {
		var stdout, stderr bytes.Buffer
		if code := Execute(context.Background(), test.args, &stdout, &stderr, options); code != ExitSuccess {
			t.Fatalf("status command failed: %v", test.args)
		}
		if !strings.Contains(stdout.String(), test.want) || stderr.Len() != 0 {
			t.Fatalf("unexpected status output: %q / %q", stdout.String(), stderr.String())
		}
	}
}

func TestStatusNotReadyAndFailureUseStablePrivateExits(t *testing.T) {
	const canary = "status-error-canary-do-not-emit"
	tests := []struct {
		name   string
		status Status
		err    error
		code   int
		line   string
	}{
		{name: "not ready", status: Status{Reason: StatusSyncPending}, code: ExitNotReady, line: "status=not_ready reason=sync_pending"},
		{name: "backend failure", err: errors.New(canary), code: ExitOperational, line: "status unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := Options{
				Version:    buildinfo.Current(),
				LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
				Actions:    Actions{Status: func(context.Context, config.Config) (Status, error) { return test.status, test.err }},
			}
			var stdout, stderr bytes.Buffer
			code := Execute(context.Background(), []string{"status"}, &stdout, &stderr, options)
			if code != test.code || !strings.Contains(stdout.String()+stderr.String(), test.line) || strings.Contains(stdout.String()+stderr.String(), canary) {
				t.Fatalf("unexpected bounded status failure: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}
