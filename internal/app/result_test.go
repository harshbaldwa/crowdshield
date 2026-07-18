package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"crowdshield/internal/lapi"
	"crowdshield/internal/ops"
	"crowdshield/internal/reconcile"
	"crowdshield/internal/syncer"
)

func TestResultFromSyncPreservesOnlyBoundedOperationalData(t *testing.T) {
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	completed := started.Add(2 * time.Second)
	report := syncer.Report{
		FeedsSucceeded: 1, FeedsUnchanged: 1, FeedsNotDue: 1,
		Feeds: []syncer.FeedResult{
			{Name: "feed-one", Status: syncer.FeedSucceeded, Accepted: 100, Rejected: 2},
			{Name: "feed-two", Status: syncer.FeedUnchanged, Accepted: 80},
			{Name: "feed-three", Status: syncer.FeedNotDue},
		},
		Reconcile: reconcile.Report{Added: 4, Refreshed: 3, Removed: 2, Recovered: 1, Rejected: 5, Skipped: 6, LAPIRequests: 7},
	}
	result, err := ResultFromSync(report, nil, started, completed, 8)
	if err != nil || result.Validate() != nil {
		t.Fatal("valid successful sync report was not converted")
	}
	if result.Outcome != ops.OutcomeSuccess || result.Failure != "" || result.Retryable ||
		result.Counts.FeedsSucceeded != 1 || result.Counts.FeedsUnchanged != 1 || result.Counts.Added != 4 || result.Counts.Rejected != 7 ||
		result.Counts.ActiveDecisions != 8 || len(result.Feeds) != 3 || result.Feeds[1].Outcome != ops.OutcomeNotModified {
		t.Fatal("successful operational result was inaccurate")
	}
}

func TestResultFromSyncClassifiesDegradedFeedsWithoutErrorText(t *testing.T) {
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	report := syncer.Report{
		FeedsFailed: 2, SuspiciousChanges: 1,
		Feeds: []syncer.FeedResult{
			{Name: "feed-one", Status: syncer.FeedFailed, ErrorClass: "request"},
			{Name: "feed-two", Status: syncer.FeedFailed, ErrorClass: "suspicious_change"},
		},
	}
	result, err := ResultFromSync(report, &syncer.Error{Category: syncer.ErrDegraded}, started, started.Add(time.Second), 0)
	if err != nil || result.Validate() != nil {
		t.Fatal("degraded feed report was not converted")
	}
	if result.Outcome != ops.OutcomeDegraded || result.Failure != ops.FailureFeedValidation || !result.Retryable ||
		result.Feeds[0].Failure != ops.FailureFeedDownload || result.Feeds[1].Failure != ops.FailureFeedValidation {
		t.Fatal("degraded feed categories or retry policy were inaccurate")
	}
}

func TestResultFromSyncClassifiesNestedRuntimeFailures(t *testing.T) {
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		err       error
		failure   ops.FailureCategory
		retryable bool
		outcome   ops.Outcome
	}{
		{
			name: "lapi auth",
			err: errors.Join(
				&syncer.Error{Category: syncer.ErrReconcile},
				&reconcile.Error{Category: reconcile.ErrLAPI},
				&lapi.Error{Category: lapi.ErrAuth},
			),
			failure: ops.FailureLAPIAuth, outcome: ops.OutcomeFailed,
		},
		{name: "database", err: &syncer.Error{Category: syncer.ErrState}, failure: ops.FailureDatabase, retryable: true, outcome: ops.OutcomeFailed},
		{name: "configuration", err: &syncer.Error{Category: syncer.ErrConfig}, failure: ops.FailureConfig, outcome: ops.OutcomeFailed},
		{name: "timeout", err: context.DeadlineExceeded, failure: ops.FailureTimeout, retryable: true, outcome: ops.OutcomeFailed},
		{name: "cancelled", err: context.Canceled, failure: ops.FailureCancelled, outcome: ops.OutcomeCancelled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ResultFromSync(syncer.Report{}, test.err, started, started.Add(time.Second), 0)
			if err != nil || result.Validate() != nil || result.Failure != test.failure || result.Retryable != test.retryable || result.Outcome != test.outcome {
				t.Fatal("runtime failure classification was inaccurate")
			}
		})
	}
}

func TestResultFromSyncRejectsInvalidReportAndRedactsUnknownError(t *testing.T) {
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	if _, err := ResultFromSync(syncer.Report{FeedsSucceeded: -1}, nil, started, started.Add(time.Second), 0); !errors.Is(err, ErrInvalidSyncReport) {
		t.Fatal("negative sync report was accepted")
	}
	const canary = "https://user:password-canary@example.invalid/198.51.100.23"
	result, err := ResultFromSync(syncer.Report{}, errors.New(canary), started, started.Add(time.Second), 0)
	if err != nil || result.Failure != ops.FailureRuntime || result.Validate() != nil {
		t.Fatal("unknown sync error was not mapped to a fixed runtime category")
	}
	if strings.Contains(string(result.Failure), canary) || strings.Contains(errString(err), canary) {
		t.Fatal("raw sync error crossed the operational result boundary")
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
