package ops

import (
	"errors"
	"testing"
	"time"
)

func TestEventValidateAcceptsClosedBoundedSyncEvent(t *testing.T) {
	event := Event{
		Code:      CodeSyncCompleted,
		Operation: OperationSync,
		Outcome:   OutcomeSuccess,
		Severity:  SeverityInfo,
		At:        time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
		Duration:  2 * time.Second,
		Counts: Counts{
			FeedsSucceeded: 3,
			Added:          4,
			Refreshed:      5,
			Removed:        1,
			Rejected:       2,
			LAPIRequests:   3,
		},
	}
	if err := event.Validate(); err != nil {
		t.Fatal("valid bounded event rejected")
	}
}

func TestEventValidateRejectsUnboundedOrInconsistentValues(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	invalid := []Event{
		{Code: Code("free-form"), Operation: OperationSync, Outcome: OutcomeSuccess, Severity: SeverityInfo, At: now},
		{Code: CodeFeedResult, Operation: OperationFeed, Feed: "198.51.100.23", Outcome: OutcomeFailed, Failure: FailureFeedDownload, Severity: SeverityWarning, At: now},
		{Code: CodeSyncCompleted, Operation: OperationSync, Outcome: OutcomeFailed, Severity: SeverityError, At: now},
		{Code: CodeSyncCompleted, Operation: OperationSync, Outcome: OutcomeSuccess, Failure: FailureInternal, Severity: SeverityInfo, At: now},
		{Code: CodeSchedulerRetry, Operation: OperationScheduler, Outcome: OutcomeRetrying, Failure: FailureLAPI, Severity: SeverityWarning, At: now, Attempt: 11},
		{Code: CodeSyncCompleted, Operation: OperationSync, Outcome: OutcomeSuccess, Severity: SeverityInfo, At: now, Counts: Counts{Added: -1}},
	}
	for _, event := range invalid {
		if err := event.Validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Fatal("unsafe or inconsistent event accepted")
		}
	}
}

func TestResultValidateBoundsFeedMetadata(t *testing.T) {
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	result := Result{
		Outcome:     OutcomeDegraded,
		Failure:     FailureFeedDownload,
		Retryable:   true,
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		Counts:      Counts{FeedsSucceeded: 1, FeedsFailed: 1},
		Feeds: []FeedResult{
			{Name: "firehol-level1", Outcome: OutcomeSuccess, Accepted: 10},
			{Name: "spamhaus-drop-ipv4", Outcome: OutcomeFailed, Failure: FailureFeedDownload},
		},
	}
	if err := result.Validate(); err != nil {
		t.Fatal("valid bounded result rejected")
	}
	result.Feeds[1].Name = "https://feed.example.invalid/private"
	if err := result.Validate(); !errors.Is(err, ErrInvalidResult) {
		t.Fatal("unbounded feed metadata accepted")
	}
}
