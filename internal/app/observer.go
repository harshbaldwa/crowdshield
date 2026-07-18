package app

import (
	"context"
	"errors"

	"crowdshield/internal/logsafe"
	"crowdshield/internal/ops"
)

var ErrInvalidRuntimeOptions = errors.New("invalid runtime options")

type EventObserver interface {
	Observe(context.Context, ops.Event)
}

type EventFanout struct {
	logger    *logsafe.Logger
	observers []EventObserver
}

func NewEventFanout(logger *logsafe.Logger, observers ...EventObserver) (*EventFanout, error) {
	if logger == nil {
		return nil, ErrInvalidRuntimeOptions
	}
	for _, observer := range observers {
		if observer == nil {
			return nil, ErrInvalidRuntimeOptions
		}
	}
	return &EventFanout{logger: logger, observers: append([]EventObserver(nil), observers...)}, nil
}

func logLevel(severity ops.Severity) logsafe.Level {
	switch severity {
	case ops.SeverityInfo:
		return logsafe.LevelInfo
	case ops.SeverityWarning:
		return logsafe.LevelWarn
	case ops.SeverityError:
		return logsafe.LevelError
	default:
		return logsafe.LevelError
	}
}

func logOperation(event ops.Event) logsafe.Operation {
	switch event.Operation {
	case ops.OperationService, ops.OperationScheduler:
		return logsafe.OpRun
	case ops.OperationSync:
		return logsafe.OpFeedSync
	case ops.OperationFeed:
		if event.Failure == ops.FailureFeedValidation {
			return logsafe.OpFeedValidate
		}
		return logsafe.OpFeedDownload
	case ops.OperationLAPI:
		if event.Failure == ops.FailureLAPIAuth {
			return logsafe.OpLAPIAuth
		}
		return logsafe.OpLAPIRequest
	case ops.OperationHTTP:
		return logsafe.OpHTTPServer
	case ops.OperationNotification:
		return logsafe.OpNotification
	case ops.OperationDatabase:
		return logsafe.OpDatabase
	case ops.OperationPrune:
		return logsafe.OpPrune
	default:
		return logsafe.OpRun
	}
}

func contextualInternalCategory(operation ops.Operation) logsafe.ErrorCategory {
	switch operation {
	case ops.OperationFeed:
		return logsafe.CategoryFeedDownload
	case ops.OperationLAPI:
		return logsafe.CategoryLAPIRequest
	case ops.OperationHTTP:
		return logsafe.CategoryHTTPInternal
	case ops.OperationNotification:
		return logsafe.CategoryNotification
	case ops.OperationDatabase:
		return logsafe.CategoryDatabase
	default:
		return logsafe.CategoryInternal
	}
}

func logCategory(event ops.Event) logsafe.ErrorCategory {
	switch event.Failure {
	case ops.FailureConfig:
		return logsafe.CategoryConfig
	case ops.FailureCredential:
		return logsafe.CategoryCredential
	case ops.FailureFeedDownload:
		return logsafe.CategoryFeedDownload
	case ops.FailureFeedValidation:
		return logsafe.CategoryFeedValidation
	case ops.FailureLAPIAuth:
		return logsafe.CategoryLAPIAuth
	case ops.FailureLAPI:
		return logsafe.CategoryLAPIRequest
	case ops.FailureDatabase:
		return logsafe.CategoryDatabase
	case ops.FailureNotification:
		return logsafe.CategoryNotification
	case ops.FailureOwnership:
		return logsafe.CategoryOwnership
	case ops.FailureTimeout, ops.FailureCancelled, ops.FailureRuntime, ops.FailureInternal:
		return contextualInternalCategory(event.Operation)
	default:
		return ""
	}
}

func boundedTotal(counts ops.Counts) int {
	return int(counts.FeedsSucceeded + counts.FeedsFailed + counts.FeedsUnchanged + counts.FeedsNotDue)
}

func (f *EventFanout) Observe(ctx context.Context, event ops.Event) {
	if f == nil || f.logger == nil || event.Validate() != nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	logEvent := logsafe.Event{
		Level: logLevel(event.Severity), Operation: logOperation(event), Feed: event.Feed,
		Duration: event.Duration, Total: boundedTotal(event.Counts),
		Added: int(event.Counts.Added), Refreshed: int(event.Counts.Refreshed),
		Removed: int(event.Counts.Removed), Rejected: int(event.Counts.Rejected),
		Skipped: int(event.Counts.Skipped), LAPIRequests: int(event.Counts.LAPIRequests),
		Success: event.Failure == "", ErrorCategory: logCategory(event),
	}
	_ = f.logger.Log(ctx, logEvent)
	for _, observer := range f.observers {
		observer.Observe(ctx, event)
	}
}
