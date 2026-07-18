package notify

import (
	"errors"
	"fmt"
	"time"

	"crowdshield/internal/ops"
)

var ErrInvalidNotice = errors.New("invalid notification notice")

type Kind string

const (
	KindStartup          Kind = "startup"
	KindFirstSuccess     Kind = "first_success"
	KindRoutineSuccess   Kind = "routine_success"
	KindRepeatedFailure  Kind = "repeated_failure"
	KindRecovery         Kind = "recovery"
	KindSuspiciousChange Kind = "suspicious_change"
	KindStaleSync        Kind = "stale_sync"
)

type Notice struct {
	Kind                Kind
	Severity            ops.Severity
	Feed                string
	Failure             ops.FailureCategory
	Counts              ops.Counts
	ConsecutiveFailures int
	At                  time.Time
}

func validSeverity(value ops.Severity) bool {
	return value == ops.SeverityInfo || value == ops.SeverityWarning || value == ops.SeverityError
}

func (n Notice) Validate() error {
	if n.At.IsZero() || !validSeverity(n.Severity) || n.Counts.Validate() != nil ||
		n.ConsecutiveFailures < 0 || n.ConsecutiveFailures > 100 {
		return ErrInvalidNotice
	}
	if n.Feed != "" && !ops.ValidFeedName(n.Feed) {
		return ErrInvalidNotice
	}
	switch n.Kind {
	case KindStartup, KindFirstSuccess, KindRoutineSuccess, KindStaleSync:
		if n.Feed != "" || n.Failure != "" || n.ConsecutiveFailures != 0 {
			return ErrInvalidNotice
		}
	case KindRepeatedFailure:
		if !ops.ValidFailureCategory(n.Failure) || n.ConsecutiveFailures < 1 {
			return ErrInvalidNotice
		}
	case KindRecovery:
		if !ops.ValidFailureCategory(n.Failure) || n.ConsecutiveFailures != 0 {
			return ErrInvalidNotice
		}
	case KindSuspiciousChange:
		if n.Feed == "" || n.Failure != "" || n.ConsecutiveFailures != 0 {
			return ErrInvalidNotice
		}
	default:
		return ErrInvalidNotice
	}
	return nil
}

type renderedNotice struct {
	title    string
	body     string
	priority string
	tags     string
}

func renderNotice(notice Notice) (renderedNotice, error) {
	if notice.Validate() != nil {
		return renderedNotice{}, ErrInvalidNotice
	}
	result := renderedNotice{priority: "3", tags: "shield"}
	switch notice.Severity {
	case ops.SeverityWarning:
		result.priority = "4"
	case ops.SeverityError:
		result.priority = "5"
	}
	at := notice.At.UTC().Format(time.RFC3339)
	switch notice.Kind {
	case KindStartup:
		result.title = "Crowdshield started"
		result.body = "Crowdshield service started at " + at + "."
	case KindFirstSuccess:
		result.title = "Crowdshield first synchronization"
		result.body = "Crowdshield completed its first safe synchronization at " + at + "."
	case KindRoutineSuccess:
		result.title = "Crowdshield synchronization"
		result.body = fmt.Sprintf(
			"Crowdshield synchronization completed at %s (feeds: %d, added: %d, refreshed: %d, removed: %d, rejected: %d).",
			at, notice.Counts.FeedsSucceeded, notice.Counts.Added, notice.Counts.Refreshed,
			notice.Counts.Removed, notice.Counts.Rejected,
		)
	case KindRepeatedFailure:
		result.title = "Crowdshield repeated failure"
		result.body = fmt.Sprintf("Crowdshield synchronization failed %d consecutive times at %s (category: %s)", notice.ConsecutiveFailures, at, notice.Failure)
		if notice.Feed != "" {
			result.body += "; feed: " + notice.Feed
		}
		result.body += "."
	case KindRecovery:
		result.title = "Crowdshield recovered"
		result.body = fmt.Sprintf("Crowdshield synchronization recovered at %s after a notified failure (category: %s)", at, notice.Failure)
		if notice.Feed != "" {
			result.body += "; feed: " + notice.Feed
		}
		result.body += "."
	case KindSuspiciousChange:
		result.title = "Crowdshield suspicious feed change"
		result.body = fmt.Sprintf(
			"Crowdshield rejected a suspicious feed change at %s (feed: %s, accepted: %d, rejected: %d).",
			at, notice.Feed, notice.Counts.Added, notice.Counts.Rejected,
		)
	case KindStaleSync:
		result.title = "Crowdshield synchronization stale"
		result.body = "Crowdshield has not completed a safe synchronization within the configured threshold as of " + at + "."
	}
	if len(result.title) > 128 || len(result.body) > 2048 || len(result.tags) > 64 {
		return renderedNotice{}, ErrInvalidNotice
	}
	return result, nil
}
