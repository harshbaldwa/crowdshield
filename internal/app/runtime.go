package app

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"crowdshield/internal/ops"
	"crowdshield/internal/state"
)

var (
	ErrRuntimeAlreadyRun = errors.New("runtime already run")
	ErrRuntimeStartup    = errors.New("runtime startup failure")
	ErrRuntimeFailure    = errors.New("runtime worker failure")
	ErrRuntimeShutdown   = errors.New("runtime shutdown failure")
)

type RuntimeState interface {
	RecoverInterruptedSyncRuns(context.Context, time.Time) (int64, error)
	RuntimeTimestamp(context.Context, state.RuntimeTimestampKey) (time.Time, bool, error)
	PruneHistory(context.Context, time.Time, time.Duration) (state.PruneResult, error)
	ListActiveDecisions(context.Context) ([]state.DecisionRecord, error)
	Close() error
}

type Authenticator interface {
	Authenticate(context.Context) error
}

type RuntimeHealth interface {
	MarkConfiguration(bool)
	MarkCredentials(bool)
	MarkDatabase(bool)
	MarkLAPI(bool)
	MarkRuntimeFatal()
	MarkStopping()
	RecordSync(ops.Result) error
}

type RuntimeMetrics interface {
	SetActiveDecisions(int64) error
}

type RuntimeNotifications interface {
	Startup(context.Context) []ops.Event
	Close()
}

type SchedulerRunner interface {
	Run(context.Context) error
}

type HTTPRuntime interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
}

type IdleCloser interface {
	CloseIdleConnections()
}

type CredentialDestroyer interface {
	Destroy()
}

type RuntimeOptions struct {
	State         RuntimeState
	Authenticator Authenticator
	Health        RuntimeHealth
	Metrics       RuntimeMetrics
	Notifications RuntimeNotifications
	Scheduler     SchedulerRunner
	HTTP          HTTPRuntime
	Listener      net.Listener
	Observer      EventObserver
	IdleClosers   []IdleCloser
	Credentials   CredentialDestroyer
	Now           func() time.Time

	HistoryRetention time.Duration
	PruneInterval    time.Duration
}

type Runtime struct {
	state            RuntimeState
	authenticator    Authenticator
	health           RuntimeHealth
	metrics          RuntimeMetrics
	notifications    RuntimeNotifications
	scheduler        SchedulerRunner
	http             HTTPRuntime
	listener         net.Listener
	observer         EventObserver
	idleClosers      []IdleCloser
	credentials      CredentialDestroyer
	now              func() time.Time
	historyRetention time.Duration
	pruneInterval    time.Duration
	run              atomic.Bool
}

func NewRuntime(options RuntimeOptions) (*Runtime, error) {
	if options.State == nil || options.Authenticator == nil || options.Health == nil ||
		options.Metrics == nil || options.Notifications == nil || options.Scheduler == nil ||
		options.HTTP == nil || options.Listener == nil || options.Observer == nil ||
		options.Credentials == nil || options.Now == nil {
		return nil, ErrInvalidRuntimeOptions
	}
	if options.HistoryRetention < time.Hour || options.HistoryRetention > 10*365*24*time.Hour ||
		options.PruneInterval < time.Hour || options.PruneInterval > 30*24*time.Hour {
		return nil, ErrInvalidRuntimeOptions
	}
	for _, closer := range options.IdleClosers {
		if closer == nil {
			return nil, ErrInvalidRuntimeOptions
		}
	}
	return &Runtime{
		state: options.State, authenticator: options.Authenticator,
		health: options.Health, metrics: options.Metrics, notifications: options.Notifications,
		scheduler: options.Scheduler, http: options.HTTP, listener: options.Listener,
		observer: options.Observer, idleClosers: append([]IdleCloser(nil), options.IdleClosers...),
		credentials: options.Credentials, now: options.Now,
		historyRetention: options.HistoryRetention, pruneInterval: options.PruneInterval,
	}, nil
}

func (r *Runtime) emit(ctx context.Context, event ops.Event) {
	if event.Validate() == nil {
		r.observer.Observe(ctx, event)
	}
}

func (r *Runtime) event(code ops.Code, outcome ops.Outcome, severity ops.Severity, failure ops.FailureCategory, at time.Time) ops.Event {
	return ops.Event{
		Code: code, Operation: ops.OperationService, Outcome: outcome,
		Severity: severity, Failure: failure, At: at,
	}
}

func pruneRemoved(result state.PruneResult) (int64, bool) {
	values := [...]int64{
		result.SyncRuns, result.Operations, result.Decisions,
		result.Alerts, result.EnforcementObjects, result.FeedEntries,
	}
	var total int64
	for _, value := range values {
		if value < 0 || value > 100_000_000 || total > 100_000_000-value {
			return 0, false
		}
		total += value
	}
	return total, true
}

func (r *Runtime) bootstrap(ctx context.Context) error {
	now := r.now().UTC()
	if now.IsZero() || now.Unix() < 0 {
		return ErrRuntimeStartup
	}
	r.emit(ctx, r.event(ops.CodeServiceStarting, ops.OutcomeStarted, ops.SeverityInfo, "", now))
	r.health.MarkConfiguration(true)
	r.health.MarkCredentials(true)
	if _, err := r.state.RecoverInterruptedSyncRuns(ctx, now); err != nil {
		r.health.MarkDatabase(false)
		r.emit(ctx, ops.Event{
			Code: ops.CodeDatabaseStateChange, Operation: ops.OperationDatabase,
			Outcome: ops.OutcomeUnavailable, Severity: ops.SeverityError,
			Failure: ops.FailureDatabase, At: now,
		})
		return ErrRuntimeStartup
	}
	r.health.MarkDatabase(true)
	r.emit(ctx, ops.Event{
		Code: ops.CodeDatabaseStateChange, Operation: ops.OperationDatabase,
		Outcome: ops.OutcomeAvailable, Severity: ops.SeverityInfo, At: now,
	})
	lastSafe, found, err := r.state.RuntimeTimestamp(ctx, state.RuntimeLastSafeSync)
	if err != nil {
		r.health.MarkDatabase(false)
		r.emit(ctx, ops.Event{
			Code: ops.CodeDatabaseStateChange, Operation: ops.OperationDatabase,
			Outcome: ops.OutcomeUnavailable, Severity: ops.SeverityError,
			Failure: ops.FailureDatabase, At: now,
		})
		return ErrRuntimeStartup
	}
	if found {
		if r.health.RecordSync(ops.Result{
			Outcome: ops.OutcomeSuccess, StartedAt: lastSafe, CompletedAt: lastSafe,
		}) != nil {
			return ErrRuntimeStartup
		}
	}
	lastPrune, prunedBefore, err := r.state.RuntimeTimestamp(ctx, state.RuntimeLastPrune)
	if err != nil {
		r.health.MarkDatabase(false)
		r.emit(ctx, ops.Event{
			Code: ops.CodeDatabaseStateChange, Operation: ops.OperationDatabase,
			Outcome: ops.OutcomeUnavailable, Severity: ops.SeverityError,
			Failure: ops.FailureDatabase, At: now,
		})
		return ErrRuntimeStartup
	}
	if !prunedBefore || (!now.Before(lastPrune) && now.Sub(lastPrune) >= r.pruneInterval) {
		pruned, pruneErr := r.state.PruneHistory(ctx, now, r.historyRetention)
		removed, valid := pruneRemoved(pruned)
		if pruneErr != nil || !valid {
			r.health.MarkDatabase(false)
			r.emit(ctx, ops.Event{
				Code: ops.CodeDatabaseStateChange, Operation: ops.OperationDatabase,
				Outcome: ops.OutcomeUnavailable, Severity: ops.SeverityError,
				Failure: ops.FailureDatabase, At: now,
			})
			return ErrRuntimeStartup
		}
		r.emit(ctx, ops.Event{
			Code: ops.CodePruneCompleted, Operation: ops.OperationPrune,
			Outcome: ops.OutcomeSuccess, Severity: ops.SeverityInfo, At: now,
			Counts: ops.Counts{Removed: removed},
		})
	}
	active, err := r.state.ListActiveDecisions(ctx)
	if err != nil || r.metrics.SetActiveDecisions(int64(len(active))) != nil {
		return ErrRuntimeStartup
	}
	if err := r.authenticator.Authenticate(ctx); err != nil {
		r.health.MarkLAPI(false)
		r.emit(ctx, ops.Event{
			Code: ops.CodeLAPIStateChanged, Operation: ops.OperationLAPI,
			Outcome: ops.OutcomeUnavailable, Severity: ops.SeverityError,
			Failure: ops.FailureLAPIAuth, At: now,
		})
		return ErrRuntimeStartup
	}
	r.health.MarkLAPI(true)
	r.emit(ctx, ops.Event{
		Code: ops.CodeLAPIStateChanged, Operation: ops.OperationLAPI,
		Outcome: ops.OutcomeAvailable, Severity: ops.SeverityInfo, At: now,
	})
	r.notifications.Startup(ctx)
	r.emit(ctx, r.event(ops.CodeServiceStarted, ops.OutcomeSuccess, ops.SeverityInfo, "", now))
	return nil
}

func (r *Runtime) closeResources() error {
	_ = r.listener.Close()
	for _, closer := range r.idleClosers {
		closer.CloseIdleConnections()
	}
	closeErr := r.state.Close()
	r.credentials.Destroy()
	return closeErr
}

func (r *Runtime) failStartup(ctx context.Context) error {
	now := r.now().UTC()
	r.health.MarkRuntimeFatal()
	r.emit(context.WithoutCancel(ctx), r.event(
		ops.CodeRuntimeFatal, ops.OutcomeFailed, ops.SeverityError, ops.FailureRuntime, now,
	))
	r.notifications.Close()
	_ = r.closeResources()
	return ErrRuntimeStartup
}

func runRuntimeWorker(worker func() error) (result error) {
	if worker == nil {
		return ErrRuntimeFailure
	}
	defer func() {
		if recover() != nil {
			result = ErrRuntimeFailure
		}
	}()
	if worker() != nil {
		return ErrRuntimeFailure
	}
	return nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrInvalidRuntimeOptions
	}
	if !r.run.CompareAndSwap(false, true) {
		return ErrRuntimeAlreadyRun
	}
	if err := r.bootstrap(ctx); err != nil {
		return r.failStartup(ctx)
	}

	workerContext, cancelWorkers := context.WithCancel(context.WithoutCancel(ctx))
	schedulerDone := make(chan error, 1)
	httpDone := make(chan error, 1)
	go func() { httpDone <- runRuntimeWorker(func() error { return r.http.Serve(r.listener) }) }()
	go func() { schedulerDone <- runRuntimeWorker(func() error { return r.scheduler.Run(workerContext) }) }()

	var runtimeErr error
	schedulerFinished := false
	httpFinished := false
	select {
	case <-ctx.Done():
	case <-schedulerDone:
		schedulerFinished = true
		runtimeErr = ErrRuntimeFailure
	case <-httpDone:
		httpFinished = true
		runtimeErr = ErrRuntimeFailure
	}

	shutdownContext := context.WithoutCancel(ctx)
	now := r.now().UTC()
	if runtimeErr != nil {
		r.health.MarkRuntimeFatal()
		r.emit(shutdownContext, r.event(
			ops.CodeRuntimeFatal, ops.OutcomeFailed, ops.SeverityError, ops.FailureRuntime, now,
		))
	}
	r.health.MarkStopping()
	r.emit(shutdownContext, r.event(
		ops.CodeServiceStopping, ops.OutcomeStarted, ops.SeverityInfo, "", now,
	))
	cancelWorkers()
	if !schedulerFinished {
		if err := <-schedulerDone; err != nil && runtimeErr == nil {
			runtimeErr = ErrRuntimeFailure
		}
	}
	r.notifications.Close()
	shutdownErr := r.http.Shutdown(shutdownContext)
	if !httpFinished {
		if err := <-httpDone; err != nil && runtimeErr == nil {
			runtimeErr = ErrRuntimeFailure
		}
	}
	if r.closeResources() != nil || shutdownErr != nil {
		if runtimeErr == nil {
			runtimeErr = ErrRuntimeShutdown
		}
	}
	r.emit(shutdownContext, r.event(
		ops.CodeServiceStopped, ops.OutcomeStopped, ops.SeverityInfo, "", r.now().UTC(),
	))
	return runtimeErr
}
