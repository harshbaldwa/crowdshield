package logsafe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoggerEmitsBoundedJSONFields(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(&output, "debug")
	if err != nil {
		t.Fatal("unable to create logger")
	}
	event := Event{
		Level:        LevelInfo,
		Operation:    OpFeedSync,
		Feed:         "spamhaus-drop-ipv4",
		Duration:     2 * time.Second,
		Total:        10,
		Added:        3,
		Refreshed:    4,
		Removed:      1,
		Rejected:     2,
		Skipped:      0,
		LAPIRequests: 2,
		Success:      true,
		Transaction:  TxCommitted,
	}
	if err := logger.Log(context.Background(), event); err != nil {
		t.Fatal("valid event rejected")
	}
	var got map[string]any
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal("logger did not emit JSON")
	}
	for _, key := range []string{"time", "level", "operation", "feed", "duration_ms", "total", "added", "refreshed", "removed", "rejected", "skipped", "success", "lapi_requests", "transaction"} {
		if _, ok := got[key]; !ok {
			t.Fatal("expected structured field missing")
		}
	}
	for _, forbidden := range []string{"error", "url", "value", "ip", "cidr", "token", "password", "job_id"} {
		if _, ok := got[forbidden]; ok {
			t.Fatal("forbidden field emitted")
		}
	}
}

func TestFailurePathsNeverEmitRawValues(t *testing.T) {
	canaries := []string{
		"198.51.100.23",
		"2001:db8::23/128",
		"credential-canary-do-not-emit",
		"Bearer token-canary-do-not-emit",
		"https://feed.example.invalid/private",
		`{"value":"198.51.100.23"}`,
	}
	var output bytes.Buffer
	logger, err := New(&output, "debug")
	if err != nil {
		t.Fatal("unable to create logger")
	}
	raw := errors.New(strings.Join(canaries, " "))
	if err := logger.Failure(context.Background(), OpLAPIRequest, "firehol-level1", CategoryLAPIRequest, raw); err != nil {
		t.Fatal("failure event rejected")
	}
	writer := logger.HTTPErrorWriter(context.Background())
	if _, err := writer.Write([]byte(strings.Join(canaries, " "))); err != nil {
		t.Fatal("HTTP error adapter failed")
	}
	text := output.String()
	for range canaries {
		// Index intentionally unused: avoid echoing a failed canary in test output.
	}
	for _, canary := range canaries {
		if strings.Contains(text, canary) {
			t.Fatal("raw failure data appeared in structured logs")
		}
	}
}

func TestGuardedPanicDoesNotEmitPanicValueOrStack(t *testing.T) {
	const canary = "panic-credential-canary-do-not-emit"
	var output bytes.Buffer
	logger, err := New(&output, "debug")
	if err != nil {
		t.Fatal("unable to create logger")
	}
	panicked := logger.Guard(context.Background(), OpRun, func() { panic(canary) })
	if !panicked {
		t.Fatal("panic was not reported")
	}
	if strings.Contains(output.String(), canary) || strings.Contains(output.String(), "goroutine") {
		t.Fatal("panic value or stack leaked")
	}
	if !strings.Contains(output.String(), string(CategoryPanic)) {
		t.Fatal("sanitized panic category missing")
	}
}

func TestLoggerRejectsUnboundedEventFields(t *testing.T) {
	var output bytes.Buffer
	logger, err := New(&output, "info")
	if err != nil {
		t.Fatal("unable to create logger")
	}
	invalid := []Event{
		{Level: LevelInfo, Operation: Operation("free-form-operation"), Success: true},
		{Level: LevelInfo, Operation: OpFeedSync, Feed: "198.51.100.23", Success: true},
		{Level: LevelInfo, Operation: OpFeedSync, Duration: -time.Second, Success: true},
		{Level: LevelInfo, Operation: OpFeedSync, Total: -1, Success: true},
		{Level: LevelError, Operation: OpFeedSync, ErrorCategory: ErrorCategory("raw-error-value"), Success: false},
	}
	for _, event := range invalid {
		if err := logger.Log(context.Background(), event); err == nil {
			t.Fatal("unbounded event was accepted")
		}
	}
	if output.Len() != 0 {
		t.Fatal("invalid event produced log output")
	}
}
