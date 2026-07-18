package app

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"crowdshield/internal/ops"
	"crowdshield/internal/state"
)

type runtimeActions struct {
	mu     sync.Mutex
	values []string
}

func (a *runtimeActions) add(value string) {
	a.mu.Lock()
	a.values = append(a.values, value)
	a.mu.Unlock()
}

func (a *runtimeActions) snapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.values...)
}

func actionIndex(t *testing.T, values []string, wanted string) int {
	t.Helper()
	for index, value := range values {
		if value == wanted {
			return index
		}
	}
	t.Fatalf("missing runtime action %q in %v", wanted, values)
	return -1
}

type fakeRuntimeState struct {
	actions      *runtimeActions
	safeAt       time.Time
	lastPrune    time.Time
	timestampErr error
	active       []state.DecisionRecord
	closeErr     error
	pruneAt      time.Time
	retention    time.Duration
}

func (s *fakeRuntimeState) RecoverInterruptedSyncRuns(context.Context, time.Time) (int64, error) {
	s.actions.add("recover")
	return 1, nil
}

func (s *fakeRuntimeState) RuntimeTimestamp(_ context.Context, key state.RuntimeTimestampKey) (time.Time, bool, error) {
	switch key {
	case state.RuntimeLastSafeSync:
		s.actions.add("runtime_timestamp_safe")
	case state.RuntimeLastPrune:
		s.actions.add("runtime_timestamp_prune")
	}
	if s.timestampErr != nil {
		return time.Time{}, false, s.timestampErr
	}
	switch key {
	case state.RuntimeLastSafeSync:
		return s.safeAt, !s.safeAt.IsZero(), nil
	case state.RuntimeLastPrune:
		return s.lastPrune, !s.lastPrune.IsZero(), nil
	default:
		return time.Time{}, false, &state.Error{Category: state.ErrConstraint}
	}
}

func (s *fakeRuntimeState) PruneHistory(_ context.Context, now time.Time, retention time.Duration) (state.PruneResult, error) {
	s.actions.add("prune")
	s.pruneAt = now
	s.retention = retention
	return state.PruneResult{SyncRuns: 2, FeedEntries: 3}, nil
}

func (s *fakeRuntimeState) ListActiveDecisions(context.Context) ([]state.DecisionRecord, error) {
	s.actions.add("runtime_active")
	return append([]state.DecisionRecord(nil), s.active...), nil
}

func (s *fakeRuntimeState) Close() error {
	s.actions.add("store_close")
	return s.closeErr
}

type fakeAuthenticator struct {
	actions *runtimeActions
	err     error
}

func (a *fakeAuthenticator) Authenticate(context.Context) error {
	a.actions.add("authenticate")
	return a.err
}

type fakeRuntimeHealth struct{ actions *runtimeActions }

func (h *fakeRuntimeHealth) MarkConfiguration(bool) { h.actions.add("health_config") }
func (h *fakeRuntimeHealth) MarkCredentials(bool)   { h.actions.add("health_credentials") }
func (h *fakeRuntimeHealth) MarkDatabase(available bool) {
	if available {
		h.actions.add("health_database_available")
	} else {
		h.actions.add("health_database_unavailable")
	}
}
func (h *fakeRuntimeHealth) MarkLAPI(available bool) {
	if available {
		h.actions.add("health_lapi_available")
	} else {
		h.actions.add("health_lapi_unavailable")
	}
}
func (h *fakeRuntimeHealth) MarkRuntimeFatal() { h.actions.add("health_fatal") }
func (h *fakeRuntimeHealth) MarkStopping()     { h.actions.add("health_stopping") }
func (h *fakeRuntimeHealth) RecordSync(ops.Result) error {
	h.actions.add("health_restore_sync")
	return nil
}

type fakeRuntimeMetrics struct{ actions *runtimeActions }

func (m *fakeRuntimeMetrics) SetActiveDecisions(int64) error {
	m.actions.add("metrics_active")
	return nil
}

type fakeRuntimeNotifications struct{ actions *runtimeActions }

func (n *fakeRuntimeNotifications) Startup(context.Context) []ops.Event {
	n.actions.add("notify_startup")
	return nil
}
func (n *fakeRuntimeNotifications) Close() { n.actions.add("notify_close") }

type fakeSchedulerRunner struct {
	actions *runtimeActions
	started chan struct{}
}

func (s *fakeSchedulerRunner) Run(ctx context.Context) error {
	s.actions.add("scheduler_run")
	close(s.started)
	<-ctx.Done()
	s.actions.add("scheduler_stopped")
	return nil
}

type fakeHTTPRuntime struct {
	actions *runtimeActions
	started chan struct{}
	stop    chan struct{}
}

func (s *fakeHTTPRuntime) Serve(net.Listener) error {
	s.actions.add("http_serve")
	close(s.started)
	<-s.stop
	s.actions.add("http_stopped")
	return nil
}

func (s *fakeHTTPRuntime) Shutdown(context.Context) error {
	s.actions.add("http_shutdown")
	close(s.stop)
	return nil
}

type fakeListener struct {
	actions *runtimeActions
	closed  chan struct{}
	once    sync.Once
}

func (l *fakeListener) Accept() (net.Conn, error) { <-l.closed; return nil, net.ErrClosed }
func (l *fakeListener) Close() error {
	l.once.Do(func() {
		l.actions.add("listener_close")
		close(l.closed)
	})
	return nil
}
func (l *fakeListener) Addr() net.Addr { return fakeAddr("runtime") }

type fakeAddr string

func (a fakeAddr) Network() string { return string(a) }
func (a fakeAddr) String() string  { return string(a) }

type fakeIdleCloser struct{ actions *runtimeActions }

func (c *fakeIdleCloser) CloseIdleConnections() { c.actions.add("idle_close") }

type fakeCredentialDestroyer struct{ actions *runtimeActions }

func (c *fakeCredentialDestroyer) Destroy() { c.actions.add("credentials_destroy") }

type runtimeObserver struct{ actions *runtimeActions }

func (o *runtimeObserver) Observe(_ context.Context, event ops.Event) {
	o.actions.add("event:" + string(event.Code))
}

func TestRuntimeWorkerBoundaryDiscardsPanicPayload(t *testing.T) {
	const canary = "panic-payload-canary-do-not-emit"
	err := runRuntimeWorker(func() error { panic(canary) })
	if err != ErrRuntimeFailure || strings.Contains(err.Error(), canary) {
		t.Fatal("runtime worker panic was not reduced to the fixed failure")
	}
}

func TestRuntimeCancellationUsesOrderedShutdown(t *testing.T) {
	actions := &runtimeActions{}
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	stateStore := &fakeRuntimeState{actions: actions, safeAt: now.Add(-time.Hour), lastPrune: now, active: make([]state.DecisionRecord, 3)}
	scheduler := &fakeSchedulerRunner{actions: actions, started: make(chan struct{})}
	httpRuntime := &fakeHTTPRuntime{actions: actions, started: make(chan struct{}), stop: make(chan struct{})}
	listener := &fakeListener{actions: actions, closed: make(chan struct{})}
	runtime, err := NewRuntime(RuntimeOptions{
		State: stateStore, Authenticator: &fakeAuthenticator{actions: actions},
		Health: &fakeRuntimeHealth{actions: actions}, Metrics: &fakeRuntimeMetrics{actions: actions},
		Notifications: &fakeRuntimeNotifications{actions: actions}, Scheduler: scheduler,
		HTTP: httpRuntime, Listener: listener, Observer: &runtimeObserver{actions: actions},
		IdleClosers: []IdleCloser{&fakeIdleCloser{actions: actions}},
		Credentials: &fakeCredentialDestroyer{actions: actions}, Now: func() time.Time { return now },
		HistoryRetention: 30 * 24 * time.Hour, PruneInterval: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal("create runtime")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	<-scheduler.started
	<-httpRuntime.started
	cancel()
	if err := <-done; err != nil {
		t.Fatal("normal cancellation returned a runtime failure")
	}
	values := actions.snapshot()
	ordered := []string{
		"event:service_starting", "recover", "runtime_timestamp_safe", "health_restore_sync",
		"runtime_timestamp_prune", "runtime_active", "metrics_active", "authenticate", "notify_startup",
		"event:service_started", "event:service_stopping", "scheduler_stopped",
		"notify_close", "http_shutdown", "http_stopped", "listener_close",
		"idle_close", "store_close", "credentials_destroy", "event:service_stopped",
	}
	previous := -1
	for _, action := range ordered {
		index := actionIndex(t, values, action)
		if index <= previous {
			t.Fatalf("runtime shutdown/startup ordering violated for %q: %v", action, values)
		}
		previous = index
	}
	if actionIndex(t, values, "scheduler_run") > actionIndex(t, values, "event:service_stopping") ||
		actionIndex(t, values, "http_serve") > actionIndex(t, values, "event:service_stopping") {
		t.Fatal("runtime workers did not start before shutdown")
	}
}

func TestRuntimeStateRestoreFailureMarksDatabaseUnavailableAndCleansUp(t *testing.T) {
	actions := &runtimeActions{}
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	stateStore := &fakeRuntimeState{
		actions: actions, timestampErr: &state.Error{Category: state.ErrIntegrity},
	}
	listener := &fakeListener{actions: actions, closed: make(chan struct{})}
	runtime, err := NewRuntime(RuntimeOptions{
		State: stateStore, Authenticator: &fakeAuthenticator{actions: actions},
		Health: &fakeRuntimeHealth{actions: actions}, Metrics: &fakeRuntimeMetrics{actions: actions},
		Notifications: &fakeRuntimeNotifications{actions: actions},
		Scheduler:     &fakeSchedulerRunner{actions: actions, started: make(chan struct{})},
		HTTP:          &fakeHTTPRuntime{actions: actions, started: make(chan struct{}), stop: make(chan struct{})},
		Listener:      listener, Observer: &runtimeObserver{actions: actions},
		IdleClosers: []IdleCloser{&fakeIdleCloser{actions: actions}},
		Credentials: &fakeCredentialDestroyer{actions: actions}, Now: func() time.Time { return now },
		HistoryRetention: 30 * 24 * time.Hour, PruneInterval: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal("create runtime")
	}
	if err := runtime.Run(context.Background()); err != ErrRuntimeStartup {
		t.Fatal("state restoration failure did not return the fixed startup error")
	}
	values := actions.snapshot()
	for _, forbidden := range []string{"authenticate", "notify_startup", "scheduler_run", "http_serve", "event:service_started"} {
		for _, action := range values {
			if action == forbidden {
				t.Fatalf("startup continued after state restoration failure: %v", values)
			}
		}
	}
	ordered := []string{
		"runtime_timestamp_safe", "health_database_unavailable", "health_fatal",
		"event:runtime_fatal", "notify_close", "listener_close", "idle_close",
		"store_close", "credentials_destroy",
	}
	previous := -1
	for _, action := range ordered {
		index := actionIndex(t, values, action)
		if index <= previous {
			t.Fatalf("startup cleanup ordering violated for %q: %v", action, values)
		}
		previous = index
	}
}

func TestRuntimePrunesDueHistoryBeforeAuthentication(t *testing.T) {
	actions := &runtimeActions{}
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	retention := 30 * 24 * time.Hour
	stateStore := &fakeRuntimeState{actions: actions, lastPrune: now.Add(-25 * time.Hour)}
	runtime, err := NewRuntime(RuntimeOptions{
		State:         stateStore,
		Authenticator: &fakeAuthenticator{actions: actions, err: context.DeadlineExceeded},
		Health:        &fakeRuntimeHealth{actions: actions}, Metrics: &fakeRuntimeMetrics{actions: actions},
		Notifications: &fakeRuntimeNotifications{actions: actions},
		Scheduler:     &fakeSchedulerRunner{actions: actions, started: make(chan struct{})},
		HTTP:          &fakeHTTPRuntime{actions: actions, started: make(chan struct{}), stop: make(chan struct{})},
		Listener:      &fakeListener{actions: actions, closed: make(chan struct{})},
		Observer:      &runtimeObserver{actions: actions},
		IdleClosers:   []IdleCloser{&fakeIdleCloser{actions: actions}},
		Credentials:   &fakeCredentialDestroyer{actions: actions}, Now: func() time.Time { return now },
		HistoryRetention: retention, PruneInterval: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal("create runtime")
	}
	if err := runtime.Run(context.Background()); err != ErrRuntimeStartup {
		t.Fatal("expected fixed startup failure after injected auth failure")
	}
	if !stateStore.pruneAt.Equal(now) || stateStore.retention != retention {
		t.Fatal("runtime did not pass bounded retention settings to pruning")
	}
	values := actions.snapshot()
	pruneTimestamp := actionIndex(t, values, "runtime_timestamp_prune")
	prune := actionIndex(t, values, "prune")
	pruneEvent := actionIndex(t, values, "event:prune_completed")
	authenticate := actionIndex(t, values, "authenticate")
	if !(pruneTimestamp < prune && prune < pruneEvent && pruneEvent < authenticate) {
		t.Fatalf("history pruning did not complete before authentication: %v", values)
	}
}
