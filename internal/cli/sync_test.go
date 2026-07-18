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

func syncResult(outcome ops.Outcome, failure ops.FailureCategory) ops.Result {
	at := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	return ops.Result{
		Outcome: outcome, Failure: failure, StartedAt: at, CompletedAt: at.Add(time.Second),
		Counts: ops.Counts{FeedsSucceeded: 1, Added: 2, ActiveDecisions: 3},
		Feeds:  []ops.FeedResult{{Name: "feed-one", Outcome: ops.OutcomeSuccess, Accepted: 10}},
	}
}

func TestSyncPassesDryRunAndBoundedFeedSelector(t *testing.T) {
	called := false
	options := Options{
		Version:    buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
		Actions: Actions{Sync: func(_ context.Context, _ config.Config, request SyncRequest) (ops.Result, error) {
			called = true
			if !request.DryRun || request.Feed != "feed-one" {
				t.Error("sync request flags were not preserved")
			}
			return syncResult(ops.OutcomeSuccess, ""), nil
		}},
	}
	var stdout, stderr bytes.Buffer
	code := Execute(context.Background(), []string{"sync", "--dry-run", "--feed", "feed-one"}, &stdout, &stderr, options)
	if code != ExitSuccess || !called || stderr.Len() != 0 ||
		!strings.Contains(stdout.String(), "outcome=success") || !strings.Contains(stdout.String(), "added=2") ||
		!strings.Contains(stdout.String(), "active_decisions=3") {
		t.Fatalf("unexpected sync output: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestSyncUsesStableFailureAndOwnershipExits(t *testing.T) {
	tests := []struct {
		name   string
		result ops.Result
		err    error
		code   int
		line   string
	}{
		{name: "degraded", result: syncResult(ops.OutcomeDegraded, ops.FailureFeedDownload), code: ExitNotReady, line: "outcome=degraded failure=feed_download"},
		{name: "ownership", result: syncResult(ops.OutcomeFailed, ops.FailureOwnership), code: ExitOwnership, line: "outcome=failed failure=ownership"},
		{name: "backend", err: errors.New("sync-canary-do-not-emit"), code: ExitOperational, line: "synchronization failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := Options{
				Version:    buildinfo.Current(),
				LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
				Actions:    Actions{Sync: func(context.Context, config.Config, SyncRequest) (ops.Result, error) { return test.result, test.err }},
			}
			var stdout, stderr bytes.Buffer
			code := Execute(context.Background(), []string{"sync", "--dry-run"}, &stdout, &stderr, options)
			combined := stdout.String() + stderr.String()
			if code != test.code || !strings.Contains(combined, test.line) || strings.Contains(combined, "sync-canary") {
				t.Fatalf("unexpected sync failure mapping: code=%d output=%q", code, combined)
			}
		})
	}
}

func TestSyncRejectsUnsafeFeedBeforeBackend(t *testing.T) {
	called := false
	options := Options{
		Version:    buildinfo.Current(),
		LoadConfig: func(string) (config.Config, error) { return config.Defaults("test"), nil },
		Actions: Actions{Sync: func(context.Context, config.Config, SyncRequest) (ops.Result, error) {
			called = true
			return ops.Result{}, nil
		}},
	}
	var stdout, stderr bytes.Buffer
	if code := Execute(context.Background(), []string{"sync", "--feed", "unsafe/feed"}, &stdout, &stderr, options); code != ExitUsage || called {
		t.Fatal("unsafe feed selector reached synchronization backend")
	}
}
