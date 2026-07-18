// Package ops defines the bounded operational vocabulary shared by runtime
// logging, metrics, readiness, notifications, and operator status output.
// It deliberately has no field capable of carrying raw errors, URLs, payloads,
// credentials, tokens, or network indicators.
package ops

import (
	"errors"
	"regexp"
	"time"
)

var (
	ErrInvalidEvent  = errors.New("invalid operational event")
	ErrInvalidResult = errors.New("invalid operational result")
	feedNamePattern  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
)

const (
	maxCount       = int64(100_000_000)
	maxDuration    = 7 * 24 * time.Hour
	maxFeedResults = 256
)

type Code string

const (
	CodeServiceStarting     Code = "service_starting"
	CodeServiceStarted      Code = "service_started"
	CodeServiceStopping     Code = "service_stopping"
	CodeServiceStopped      Code = "service_stopped"
	CodeRuntimeFatal        Code = "runtime_fatal"
	CodeSyncStarted         Code = "sync_started"
	CodeSyncCompleted       Code = "sync_completed"
	CodeFeedResult          Code = "feed_result"
	CodeLAPIStateChanged    Code = "lapi_state_changed"
	CodeSchedulerStarted    Code = "scheduler_started"
	CodeSchedulerRetry      Code = "scheduler_retry"
	CodeSchedulerRecovered  Code = "scheduler_recovered"
	CodeSchedulerStopped    Code = "scheduler_stopped"
	CodeHTTPStarted         Code = "http_started"
	CodeHTTPStopped         Code = "http_stopped"
	CodeNotificationResult  Code = "notification_result"
	CodeDatabaseStateChange Code = "database_state_changed"
	CodePruneCompleted      Code = "prune_completed"
)

type Operation string

const (
	OperationService      Operation = "service"
	OperationSync         Operation = "sync"
	OperationFeed         Operation = "feed"
	OperationLAPI         Operation = "lapi"
	OperationScheduler    Operation = "scheduler"
	OperationHTTP         Operation = "http"
	OperationNotification Operation = "notification"
	OperationDatabase     Operation = "database"
	OperationPrune        Operation = "prune"
)

type Outcome string

const (
	OutcomeStarted     Outcome = "started"
	OutcomeSuccess     Outcome = "success"
	OutcomeDegraded    Outcome = "degraded"
	OutcomeFailed      Outcome = "failed"
	OutcomeCancelled   Outcome = "cancelled"
	OutcomeNotDue      Outcome = "not_due"
	OutcomeNotModified Outcome = "not_modified"
	OutcomeRetrying    Outcome = "retrying"
	OutcomeRecovered   Outcome = "recovered"
	OutcomeAvailable   Outcome = "available"
	OutcomeUnavailable Outcome = "unavailable"
	OutcomeStale       Outcome = "stale"
	OutcomeStopped     Outcome = "stopped"
)

type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

type FailureCategory string

const (
	FailureConfig         FailureCategory = "config"
	FailureCredential     FailureCategory = "credential"
	FailureFeedDownload   FailureCategory = "feed_download"
	FailureFeedValidation FailureCategory = "feed_validation"
	FailureLAPIAuth       FailureCategory = "lapi_auth"
	FailureLAPI           FailureCategory = "lapi"
	FailureDatabase       FailureCategory = "database"
	FailureNotification   FailureCategory = "notification"
	FailureOwnership      FailureCategory = "ownership"
	FailureTimeout        FailureCategory = "timeout"
	FailureCancelled      FailureCategory = "cancelled"
	FailureRuntime        FailureCategory = "runtime"
	FailureInternal       FailureCategory = "internal"
)

type Counts struct {
	FeedsSucceeded  int64
	FeedsFailed     int64
	FeedsUnchanged  int64
	FeedsNotDue     int64
	Added           int64
	Refreshed       int64
	Removed         int64
	Rejected        int64
	Skipped         int64
	LAPIRequests    int64
	ActiveDecisions int64
}

func (c Counts) valid() bool {
	values := [...]int64{
		c.FeedsSucceeded, c.FeedsFailed, c.FeedsUnchanged, c.FeedsNotDue,
		c.Added, c.Refreshed, c.Removed, c.Rejected, c.Skipped,
		c.LAPIRequests, c.ActiveDecisions,
	}
	for _, value := range values {
		if value < 0 || value > maxCount {
			return false
		}
	}
	return true
}

// Validate checks that every aggregate count is non-negative and bounded.
func (c Counts) Validate() error {
	if !c.valid() {
		return ErrInvalidResult
	}
	return nil
}

type Event struct {
	Code      Code
	Operation Operation
	Feed      string
	Outcome   Outcome
	Severity  Severity
	Failure   FailureCategory
	At        time.Time
	Duration  time.Duration
	Attempt   int
	Counts    Counts
}

// ValidFeedName reports whether value is safe for bounded operational labels.
func ValidFeedName(value string) bool {
	return len(value) <= 64 && feedNamePattern.MatchString(value)
}

func validFeedName(value string) bool {
	return ValidFeedName(value)
}

func validFailure(value FailureCategory) bool {
	switch value {
	case FailureConfig, FailureCredential, FailureFeedDownload, FailureFeedValidation,
		FailureLAPIAuth, FailureLAPI, FailureDatabase, FailureNotification,
		FailureOwnership, FailureTimeout, FailureCancelled, FailureRuntime, FailureInternal:
		return true
	default:
		return false
	}
}

// ValidFailureCategory reports whether value belongs to the closed failure vocabulary.
func ValidFailureCategory(value FailureCategory) bool {
	return validFailure(value)
}

func validOutcome(value Outcome) bool {
	switch value {
	case OutcomeStarted, OutcomeSuccess, OutcomeDegraded, OutcomeFailed, OutcomeCancelled,
		OutcomeNotDue, OutcomeNotModified, OutcomeRetrying, OutcomeRecovered,
		OutcomeAvailable, OutcomeUnavailable, OutcomeStale, OutcomeStopped:
		return true
	default:
		return false
	}
}

func validSeverity(value Severity) bool {
	return value == SeverityInfo || value == SeverityWarning || value == SeverityError
}

func codeOperation(code Code) (Operation, bool) {
	switch code {
	case CodeServiceStarting, CodeServiceStarted, CodeServiceStopping, CodeServiceStopped, CodeRuntimeFatal:
		return OperationService, true
	case CodeSyncStarted, CodeSyncCompleted:
		return OperationSync, true
	case CodeFeedResult:
		return OperationFeed, true
	case CodeLAPIStateChanged:
		return OperationLAPI, true
	case CodeSchedulerStarted, CodeSchedulerRetry, CodeSchedulerRecovered, CodeSchedulerStopped:
		return OperationScheduler, true
	case CodeHTTPStarted, CodeHTTPStopped:
		return OperationHTTP, true
	case CodeNotificationResult:
		return OperationNotification, true
	case CodeDatabaseStateChange:
		return OperationDatabase, true
	case CodePruneCompleted:
		return OperationPrune, true
	default:
		return "", false
	}
}

func outcomeNeedsFailure(value Outcome) bool {
	switch value {
	case OutcomeDegraded, OutcomeFailed, OutcomeRetrying, OutcomeUnavailable, OutcomeStale, OutcomeCancelled:
		return true
	default:
		return false
	}
}

func (e Event) Validate() error {
	expected, known := codeOperation(e.Code)
	if !known || e.Operation != expected || !validOutcome(e.Outcome) || !validSeverity(e.Severity) || e.At.IsZero() {
		return ErrInvalidEvent
	}
	if e.Duration < 0 || e.Duration > maxDuration || e.Attempt < 0 || e.Attempt > 10 || !e.Counts.valid() {
		return ErrInvalidEvent
	}
	if e.Code == CodeSchedulerRetry && e.Attempt < 1 {
		return ErrInvalidEvent
	}
	if outcomeNeedsFailure(e.Outcome) {
		if !validFailure(e.Failure) {
			return ErrInvalidEvent
		}
		if e.Outcome == OutcomeCancelled && e.Failure != FailureCancelled {
			return ErrInvalidEvent
		}
	} else if e.Failure != "" {
		return ErrInvalidEvent
	}
	if e.Feed != "" {
		if !validFeedName(e.Feed) || (e.Operation != OperationFeed && e.Operation != OperationNotification) {
			return ErrInvalidEvent
		}
	} else if e.Code == CodeFeedResult {
		return ErrInvalidEvent
	}
	return nil
}

type FeedResult struct {
	Name     string
	Outcome  Outcome
	Failure  FailureCategory
	Accepted int64
	Rejected int64
}

func (r FeedResult) valid() bool {
	if !validFeedName(r.Name) || r.Accepted < 0 || r.Accepted > maxCount || r.Rejected < 0 || r.Rejected > maxCount {
		return false
	}
	switch r.Outcome {
	case OutcomeSuccess, OutcomeNotDue, OutcomeNotModified:
		return r.Failure == ""
	case OutcomeFailed, OutcomeDegraded:
		return validFailure(r.Failure)
	default:
		return false
	}
}

// Validate checks a per-feed result against the closed operational vocabulary.
func (r FeedResult) Validate() error {
	if !r.valid() {
		return ErrInvalidResult
	}
	return nil
}

type Result struct {
	Outcome     Outcome
	Failure     FailureCategory
	Retryable   bool
	StartedAt   time.Time
	CompletedAt time.Time
	Counts      Counts
	Feeds       []FeedResult
}

func (r Result) Validate() error {
	switch r.Outcome {
	case OutcomeSuccess:
		if r.Failure != "" || r.Retryable {
			return ErrInvalidResult
		}
	case OutcomeDegraded, OutcomeFailed:
		if !validFailure(r.Failure) {
			return ErrInvalidResult
		}
	case OutcomeCancelled:
		if r.Failure != FailureCancelled || r.Retryable {
			return ErrInvalidResult
		}
	default:
		return ErrInvalidResult
	}
	if r.StartedAt.IsZero() || r.CompletedAt.Before(r.StartedAt) || r.CompletedAt.Sub(r.StartedAt) > maxDuration || !r.Counts.valid() || len(r.Feeds) > maxFeedResults {
		return ErrInvalidResult
	}
	seen := make(map[string]struct{}, len(r.Feeds))
	for _, feed := range r.Feeds {
		if !feed.valid() {
			return ErrInvalidResult
		}
		if _, exists := seen[feed.Name]; exists {
			return ErrInvalidResult
		}
		seen[feed.Name] = struct{}{}
	}
	return nil
}
