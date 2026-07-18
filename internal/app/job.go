package app

import (
	"context"
	"errors"
	"time"

	"crowdshield/internal/feed"
	"crowdshield/internal/metrics"
	"crowdshield/internal/ops"
	"crowdshield/internal/state"
	"crowdshield/internal/syncer"
)

type SyncEngine interface {
	Run(context.Context, syncer.RunOptions) (syncer.Report, error)
}

type SyncState interface {
	BeginSyncRun(context.Context, state.SyncMode, string, time.Time) (int64, error)
	ListActiveDecisions(context.Context) ([]state.DecisionRecord, error)
	CompleteSyncRun(context.Context, int64, ops.Result) error
	RuntimeTimestamp(context.Context, state.RuntimeTimestampKey) (time.Time, bool, error)
}

type SyncMetrics interface {
	ObserveSync(metrics.Mode, ops.Result) error
}

type SyncHealth interface {
	RecordSync(ops.Result) error
}

type SyncNotifications interface {
	HandleSync(context.Context, ops.Result) []ops.Event
	SuspiciousChange(context.Context, string, ops.Counts) []ops.Event
	StaleSync(context.Context) []ops.Event
}

type SyncJobOptions struct {
	Engine        SyncEngine
	State         SyncState
	Metrics       SyncMetrics
	Health        SyncHealth
	Notifications SyncNotifications
	Observer      EventObserver
	Now           func() time.Time

	FinalizationTimeout time.Duration
	StaleAfter          time.Duration
}

type SyncJob struct {
	engine        SyncEngine
	state         SyncState
	metrics       SyncMetrics
	health        SyncHealth
	notifications SyncNotifications
	observer      EventObserver
	now           func() time.Time
	finalizeAfter time.Duration
	staleAfter    time.Duration
}

func NewSyncJob(options SyncJobOptions) (*SyncJob, error) {
	if options.Engine == nil || options.State == nil || options.Metrics == nil || options.Health == nil ||
		options.Notifications == nil || options.Observer == nil || options.Now == nil ||
		options.FinalizationTimeout <= 0 || options.FinalizationTimeout > time.Minute ||
		options.StaleAfter <= 0 || options.StaleAfter > 30*24*time.Hour {
		return nil, ErrInvalidRuntimeOptions
	}
	return &SyncJob{
		engine: options.Engine, state: options.State, metrics: options.Metrics,
		health: options.Health, notifications: options.Notifications,
		observer: options.Observer, now: options.Now, finalizeAfter: options.FinalizationTimeout,
		staleAfter: options.StaleAfter,
	}, nil
}

func normalizedCompletion(startedAt, completedAt time.Time) time.Time {
	completedAt = completedAt.UTC()
	if completedAt.Before(startedAt) || completedAt.Sub(startedAt) > 7*24*time.Hour {
		return startedAt
	}
	return completedAt
}

func fixedFailureResult(category ops.FailureCategory, retryable bool, startedAt, completedAt time.Time, previous ops.Result) ops.Result {
	result := ops.Result{
		Outcome: ops.OutcomeFailed, Failure: category, Retryable: retryable,
		StartedAt: startedAt, CompletedAt: completedAt,
		Counts: previous.Counts, Feeds: append([]ops.FeedResult(nil), previous.Feeds...),
	}
	if result.Validate() != nil {
		return ops.Result{
			Outcome: ops.OutcomeFailed, Failure: category, Retryable: retryable,
			StartedAt: startedAt, CompletedAt: completedAt,
		}
	}
	return result
}

func syncSeverity(result ops.Result) ops.Severity {
	switch result.Outcome {
	case ops.OutcomeSuccess:
		return ops.SeverityInfo
	case ops.OutcomeDegraded, ops.OutcomeCancelled:
		return ops.SeverityWarning
	default:
		return ops.SeverityError
	}
}

func feedSeverity(result ops.FeedResult) ops.Severity {
	if result.Outcome == ops.OutcomeFailed || result.Outcome == ops.OutcomeDegraded {
		return ops.SeverityWarning
	}
	return ops.SeverityInfo
}

func (j *SyncJob) emit(ctx context.Context, event ops.Event) {
	if event.Validate() == nil {
		j.observer.Observe(ctx, event)
	}
}

func (j *SyncJob) observeResult(ctx context.Context, report syncer.Report, runErr error, result ops.Result) {
	_ = j.metrics.ObserveSync(metrics.ModeEnforce, result)
	_ = j.health.RecordSync(result)
	for _, item := range result.Feeds {
		j.emit(ctx, ops.Event{
			Code: ops.CodeFeedResult, Operation: ops.OperationFeed, Feed: item.Name,
			Outcome: item.Outcome, Severity: feedSeverity(item), Failure: item.Failure,
			At: result.CompletedAt, Counts: ops.Counts{Rejected: item.Rejected},
		})
	}
	lapiAvailable := result.Outcome == ops.OutcomeSuccess ||
		(result.Outcome == ops.OutcomeDegraded &&
			(result.Failure == ops.FailureFeedDownload || result.Failure == ops.FailureFeedValidation))
	lapiUnavailable := result.Failure == ops.FailureLAPI || result.Failure == ops.FailureLAPIAuth ||
		(result.Failure == ops.FailureTimeout && syncer.IsCategory(runErr, syncer.ErrReconcile))
	if lapiAvailable {
		j.emit(ctx, ops.Event{
			Code: ops.CodeLAPIStateChanged, Operation: ops.OperationLAPI,
			Outcome: ops.OutcomeAvailable, Severity: ops.SeverityInfo, At: result.CompletedAt,
		})
	} else if lapiUnavailable {
		j.emit(ctx, ops.Event{
			Code: ops.CodeLAPIStateChanged, Operation: ops.OperationLAPI,
			Outcome: ops.OutcomeUnavailable, Severity: ops.SeverityError,
			Failure: result.Failure, At: result.CompletedAt,
		})
	}
	j.emit(ctx, ops.Event{
		Code: ops.CodeSyncCompleted, Operation: ops.OperationSync,
		Outcome: result.Outcome, Severity: syncSeverity(result), Failure: result.Failure,
		At: result.CompletedAt, Duration: result.CompletedAt.Sub(result.StartedAt), Counts: result.Counts,
	})
	if result.Outcome == ops.OutcomeCancelled {
		return
	}
	for _, item := range report.Feeds {
		if feed.ErrorCategory(item.ErrorClass) == feed.ErrSuspiciousChange {
			j.notifications.SuspiciousChange(ctx, item.Name, result.Counts)
		}
	}
	j.notifications.HandleSync(ctx, result)
	if result.Outcome == ops.OutcomeFailed || result.Outcome == ops.OutcomeDegraded {
		safe := result.Outcome == ops.OutcomeDegraded &&
			(result.Failure == ops.FailureFeedDownload || result.Failure == ops.FailureFeedValidation)
		if !safe && result.Failure != ops.FailureDatabase {
			lastSafe, found, err := j.state.RuntimeTimestamp(ctx, state.RuntimeLastSafeSync)
			if err == nil && found && !result.CompletedAt.Before(lastSafe) &&
				result.CompletedAt.Sub(lastSafe) >= j.staleAfter {
				j.notifications.StaleSync(ctx)
			}
		}
	}
}

func (j *SyncJob) Run(ctx context.Context) ops.Result {
	if ctx == nil {
		ctx = context.Background()
	}
	startedAt := j.now().UTC()
	j.emit(ctx, ops.Event{
		Code: ops.CodeSyncStarted, Operation: ops.OperationSync,
		Outcome: ops.OutcomeStarted, Severity: ops.SeverityInfo, At: startedAt,
	})
	if err := ctx.Err(); err != nil {
		completedAt := normalizedCompletion(startedAt, j.now())
		result := ops.Result{
			Outcome: ops.OutcomeCancelled, Failure: ops.FailureCancelled,
			StartedAt: startedAt, CompletedAt: completedAt,
		}
		j.observeResult(context.WithoutCancel(ctx), syncer.Report{}, err, result)
		return result
	}
	runID, err := j.state.BeginSyncRun(ctx, state.SyncModeEnforce, "", startedAt)
	if err != nil {
		completedAt := normalizedCompletion(startedAt, j.now())
		result := fixedFailureResult(ops.FailureDatabase, true, startedAt, completedAt, ops.Result{})
		j.observeResult(context.WithoutCancel(ctx), syncer.Report{}, err, result)
		return result
	}
	report, runErr := j.engine.Run(ctx, syncer.RunOptions{})
	activeDecisions := 0
	if !errors.Is(runErr, context.Canceled) {
		active, activeErr := j.state.ListActiveDecisions(ctx)
		if activeErr != nil {
			runErr = &syncer.Error{Category: syncer.ErrState}
		} else {
			activeDecisions = len(active)
		}
	}
	completedAt := normalizedCompletion(startedAt, j.now())
	result, conversionErr := ResultFromSync(report, runErr, startedAt, completedAt, activeDecisions)
	if conversionErr != nil {
		result = fixedFailureResult(ops.FailureInternal, false, startedAt, completedAt, ops.Result{})
	}
	finalizeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), j.finalizeAfter)
	completeErr := j.state.CompleteSyncRun(finalizeContext, runID, result)
	cancel()
	if completeErr != nil {
		result = fixedFailureResult(ops.FailureDatabase, true, startedAt, completedAt, result)
	}
	observeContext := context.WithoutCancel(ctx)
	j.observeResult(observeContext, report, runErr, result)
	return result
}
