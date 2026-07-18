package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"crowdshield/internal/logsafe"
	"crowdshield/internal/ops"
)

type recordingObserver struct {
	events []ops.Event
}

func (o *recordingObserver) Observe(_ context.Context, event ops.Event) {
	o.events = append(o.events, event)
}

func TestEventFanoutLogsAndForwardsBoundedEvent(t *testing.T) {
	var output bytes.Buffer
	logger, err := logsafe.New(&output, "debug")
	if err != nil {
		t.Fatal("create safe logger")
	}
	first := &recordingObserver{}
	second := &recordingObserver{}
	fanout, err := NewEventFanout(logger, first, second)
	if err != nil {
		t.Fatal("create event fanout")
	}
	event := ops.Event{
		Code: ops.CodeSyncCompleted, Operation: ops.OperationSync,
		Outcome: ops.OutcomeSuccess, Severity: ops.SeverityInfo,
		At: time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC), Duration: 2 * time.Second,
		Counts: ops.Counts{FeedsSucceeded: 2, FeedsNotDue: 1, Added: 4, Refreshed: 3, Removed: 2, Rejected: 5, Skipped: 6, LAPIRequests: 7},
	}
	fanout.Observe(context.Background(), event)
	if len(first.events) != 1 || len(second.events) != 1 || first.events[0] != event || second.events[0] != event {
		t.Fatal("bounded event was not forwarded exactly once")
	}
	logLine := output.String()
	for _, expected := range []string{`"operation":"feed_sync"`, `"duration_ms":2000`, `"total":3`, `"added":4`, `"refreshed":3`, `"removed":2`, `"rejected":5`, `"skipped":6`, `"lapi_requests":7`, `"success":true`} {
		if !strings.Contains(logLine, expected) {
			t.Fatalf("safe log projection omitted %s", expected)
		}
	}
}

func TestEventFanoutMapsFailuresWithoutAcceptingRawText(t *testing.T) {
	var output bytes.Buffer
	logger, err := logsafe.New(&output, "debug")
	if err != nil {
		t.Fatal("create safe logger")
	}
	recorder := &recordingObserver{}
	fanout, err := NewEventFanout(logger, recorder)
	if err != nil {
		t.Fatal("create event fanout")
	}
	event := ops.Event{
		Code: ops.CodeSyncCompleted, Operation: ops.OperationSync,
		Outcome: ops.OutcomeFailed, Severity: ops.SeverityError,
		Failure: ops.FailureLAPIAuth, At: time.Now(),
	}
	fanout.Observe(context.Background(), event)
	line := output.String()
	if !strings.Contains(line, `"error_category":"lapi_auth"`) || !strings.Contains(line, `"success":false`) {
		t.Fatal("bounded failure was not projected accurately")
	}
	const canary = "https://user:password-canary@example.invalid/198.51.100.9"
	invalid := event
	invalid.Feed = canary
	fanout.Observe(context.Background(), invalid)
	if len(recorder.events) != 1 || strings.Contains(output.String(), canary) {
		t.Fatal("invalid arbitrary event data reached an observer surface")
	}
}

func TestEventFanoutRejectsMissingDependencies(t *testing.T) {
	if _, err := NewEventFanout(nil); err != ErrInvalidRuntimeOptions {
		t.Fatal("nil logger was accepted")
	}
	var output bytes.Buffer
	logger, err := logsafe.New(&output, "info")
	if err != nil {
		t.Fatal("create safe logger")
	}
	if _, err := NewEventFanout(logger, nil); err != ErrInvalidRuntimeOptions {
		t.Fatal("nil observer was accepted")
	}
}
