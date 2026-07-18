package notify

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"crowdshield/internal/ops"
)

type managerClock struct {
	mu  sync.Mutex
	now time.Time
}

func newManagerClock() *managerClock {
	return &managerClock{now: time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)}
}

func (c *managerClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *managerClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type memoryStateStore struct {
	mu      sync.Mutex
	states  map[StateKey]PersistentState
	loadErr error
	saveErr error
}

func newMemoryStateStore() *memoryStateStore {
	return &memoryStateStore{states: make(map[StateKey]PersistentState)}
}

func (s *memoryStateStore) Load(_ context.Context, key StateKey) (PersistentState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return PersistentState{}, false, s.loadErr
	}
	state, found := s.states[key]
	return state, found, nil
}

func (s *memoryStateStore) Save(_ context.Context, state PersistentState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	s.states[state.Key] = state
	return nil
}

type fakeTransport struct {
	mu      sync.Mutex
	notices []Notice
	err     error
}

func (t *fakeTransport) Send(_ context.Context, notice Notice) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.notices = append(t.notices, notice)
	return t.err
}

func (t *fakeTransport) Notices() []Notice {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Notice(nil), t.notices...)
}

func managerOptions(clock Clock, store StateStore, transport Transport) ManagerOptions {
	return ManagerOptions{
		Enabled: true, Clock: clock, Store: store, Transport: transport,
		MinimumSeverity: ops.SeverityInfo, FailureThreshold: 3, Cooldown: time.Hour,
		RecoveryNotifications: true, SuspiciousChangeNotifications: true,
		StaleSyncNotifications: true,
	}
}

func failedSync(clock Clock) ops.Result {
	now := clock.Now()
	return ops.Result{
		Outcome: ops.OutcomeDegraded, Failure: ops.FailureFeedDownload, Retryable: true,
		StartedAt: now.Add(-time.Second), CompletedAt: now,
		Counts: ops.Counts{FeedsFailed: 1},
		Feeds:  []ops.FeedResult{{Name: "feed-one", Outcome: ops.OutcomeFailed, Failure: ops.FailureFeedDownload}},
	}
}

func successfulManagerSync(clock Clock) ops.Result {
	now := clock.Now()
	return ops.Result{
		Outcome: ops.OutcomeSuccess, StartedAt: now.Add(-time.Second), CompletedAt: now,
		Counts: ops.Counts{FeedsSucceeded: 1, Added: 2, Refreshed: 3, Removed: 1},
	}
}

func assertEventsValid(t *testing.T, events []ops.Event) {
	t.Helper()
	for _, event := range events {
		if err := event.Validate(); err != nil {
			t.Fatal("notification manager emitted an invalid operational event")
		}
	}
}

func TestManagerThresholdPersistsDeduplicatesAndSendsOneRecovery(t *testing.T) {
	clock := newManagerClock()
	store := newMemoryStateStore()
	transport := &fakeTransport{}
	manager, err := NewManager(managerOptions(clock, store, transport))
	if err != nil {
		t.Fatal("valid notification manager options rejected")
	}
	for attempt := 1; attempt < 3; attempt++ {
		if events := manager.HandleSync(context.Background(), failedSync(clock)); len(events) != 0 {
			t.Fatal("notification sent before repeated-failure threshold")
		}
		clock.Advance(time.Minute)
	}
	events := manager.HandleSync(context.Background(), failedSync(clock))
	assertEventsValid(t, events)
	if len(events) != 1 || events[0].Outcome != ops.OutcomeSuccess {
		t.Fatal("threshold failure did not send exactly one notification")
	}
	notices := transport.Notices()
	if len(notices) != 1 || notices[0].Kind != KindRepeatedFailure || notices[0].ConsecutiveFailures != 3 {
		t.Fatal("repeated-failure notice was inaccurate")
	}

	restarted, err := NewManager(managerOptions(clock, store, transport))
	if err != nil {
		t.Fatal("reconstructed notification manager failed")
	}
	if events := restarted.HandleSync(context.Background(), failedSync(clock)); len(events) != 0 {
		t.Fatal("persisted notified failure was duplicated after restart")
	}
	events = restarted.HandleSync(context.Background(), successfulManagerSync(clock))
	assertEventsValid(t, events)
	if len(events) != 1 || events[0].Outcome != ops.OutcomeSuccess {
		t.Fatal("notified failure did not produce one recovery")
	}
	if events := restarted.HandleSync(context.Background(), successfulManagerSync(clock)); len(events) != 0 {
		t.Fatal("recovery notification repeated")
	}
	notices = transport.Notices()
	if len(notices) != 2 || notices[1].Kind != KindRecovery || notices[1].Failure != ops.FailureFeedDownload {
		t.Fatal("recovery notice did not match the notified failure")
	}
}

func TestManagerTransportAndStateFailuresNeverEscapeOrStorm(t *testing.T) {
	clock := newManagerClock()
	store := newMemoryStateStore()
	transport := &fakeTransport{err: errors.New("198.51.100.23 token-canary transport failure")}
	options := managerOptions(clock, store, transport)
	options.FailureThreshold = 1
	manager, err := NewManager(options)
	if err != nil {
		t.Fatal("valid failure-test manager rejected")
	}
	events := manager.HandleSync(context.Background(), failedSync(clock))
	assertEventsValid(t, events)
	if len(events) != 1 || events[0].Outcome != ops.OutcomeFailed || events[0].Failure != ops.FailureNotification {
		t.Fatal("transport failure did not become a fixed non-propagating event")
	}
	if events := manager.HandleSync(context.Background(), failedSync(clock)); len(events) != 0 {
		t.Fatal("failed transport retried inside cooldown")
	}
	clock.Advance(time.Hour)
	if events := manager.HandleSync(context.Background(), failedSync(clock)); len(events) != 1 {
		t.Fatal("failed transport was not retried after cooldown")
	}
	if len(transport.Notices()) != 2 {
		t.Fatal("transport failure caused missing retry or a retry storm")
	}

	store.saveErr = errors.New("password-canary state failure")
	transport.err = nil
	clock.Advance(time.Hour)
	events = manager.HandleSync(context.Background(), failedSync(clock))
	assertEventsValid(t, events)
	if len(events) != 1 || events[0].Failure != ops.FailureDatabase || len(transport.Notices()) != 2 {
		t.Fatal("state failure escaped its fixed category or allowed an unreserved send")
	}
}

func TestManagerSupportsStartupFirstSuccessSuspiciousStaleAndRoutinePolicies(t *testing.T) {
	clock := newManagerClock()
	store := newMemoryStateStore()
	transport := &fakeTransport{}
	options := managerOptions(clock, store, transport)
	options.StartupNotification = true
	options.FirstSuccessNotification = true
	manager, err := NewManager(options)
	if err != nil {
		t.Fatal("valid policy manager rejected")
	}
	if events := manager.Startup(context.Background()); len(events) != 1 {
		t.Fatal("enabled startup notification was not sent")
	}
	if events := manager.HandleSync(context.Background(), successfulManagerSync(clock)); len(events) != 1 {
		t.Fatal("enabled first-success notification was not sent")
	}
	if events := manager.HandleSync(context.Background(), successfulManagerSync(clock)); len(events) != 0 {
		t.Fatal("routine success was sent while disabled")
	}
	if events := manager.SuspiciousChange(context.Background(), "feed-one", ops.Counts{Added: 100, Rejected: 2}); len(events) != 1 {
		t.Fatal("enabled suspicious-change notification was not sent")
	}
	if events := manager.SuspiciousChange(context.Background(), "feed-one", ops.Counts{Added: 100, Rejected: 2}); len(events) != 0 {
		t.Fatal("suspicious-change notification ignored cooldown")
	}
	if events := manager.StaleSync(context.Background()); len(events) != 1 {
		t.Fatal("enabled stale-sync notification was not sent")
	}
	if events := manager.StaleSync(context.Background()); len(events) != 0 {
		t.Fatal("stale-sync notification was duplicated")
	}

	restarted, err := NewManager(options)
	if err != nil {
		t.Fatal("reconstructed policy manager failed")
	}
	if events := restarted.Startup(context.Background()); len(events) != 0 {
		t.Fatal("restart inside cooldown created a startup storm")
	}
	if events := restarted.StaleSync(context.Background()); len(events) != 0 {
		t.Fatal("stale notification repeated after restart")
	}
	if events := restarted.HandleSync(context.Background(), successfulManagerSync(clock)); len(events) != 0 {
		t.Fatal("first success repeated after restart")
	}
	if events := restarted.StaleSync(context.Background()); len(events) != 1 {
		t.Fatal("safe recovery did not re-arm stale notification")
	}

	kinds := make([]Kind, 0)
	for _, notice := range transport.Notices() {
		kinds = append(kinds, notice.Kind)
	}
	expected := []Kind{KindStartup, KindFirstSuccess, KindSuspiciousChange, KindStaleSync, KindStaleSync}
	if len(kinds) != len(expected) {
		t.Fatal("unexpected notification policy count")
	}
	for index := range expected {
		if kinds[index] != expected[index] {
			t.Fatal("notification policies emitted the wrong notice sequence")
		}
	}
}

func TestManagerRoutineSuccessHonorsSettingSeverityAndCooldown(t *testing.T) {
	clock := newManagerClock()
	store := newMemoryStateStore()
	transport := &fakeTransport{}
	options := managerOptions(clock, store, transport)
	options.RoutineSuccessNotification = true
	options.RecoveryNotifications = false
	manager, err := NewManager(options)
	if err != nil {
		t.Fatal("valid routine-success manager rejected")
	}
	if events := manager.HandleSync(context.Background(), successfulManagerSync(clock)); len(events) != 1 {
		t.Fatal("enabled routine success was not sent")
	}
	if events := manager.HandleSync(context.Background(), successfulManagerSync(clock)); len(events) != 0 {
		t.Fatal("routine success ignored cooldown")
	}
	clock.Advance(time.Hour)
	if events := manager.HandleSync(context.Background(), successfulManagerSync(clock)); len(events) != 1 {
		t.Fatal("routine success did not resume after cooldown")
	}

	warningOnly := managerOptions(clock, newMemoryStateStore(), &fakeTransport{})
	warningOnly.RoutineSuccessNotification = true
	warningOnly.MinimumSeverity = ops.SeverityWarning
	filtered, err := NewManager(warningOnly)
	if err != nil {
		t.Fatal("valid severity-filtered manager rejected")
	}
	if events := filtered.HandleSync(context.Background(), successfulManagerSync(clock)); len(events) != 0 {
		t.Fatal("minimum severity did not suppress informational routine success")
	}
}

func TestDisabledAndClosedManagersAreHarmless(t *testing.T) {
	clock := newManagerClock()
	disabled, err := NewManager(ManagerOptions{
		Enabled: false, Clock: clock, MinimumSeverity: ops.SeverityWarning,
		FailureThreshold: 3, Cooldown: time.Hour,
	})
	if err != nil {
		t.Fatal("disabled manager required network or persistence dependencies")
	}
	if events := disabled.HandleSync(context.Background(), failedSync(clock)); len(events) != 0 {
		t.Fatal("disabled manager emitted notification events")
	}

	transport := &fakeTransport{}
	enabled, err := NewManager(managerOptions(clock, newMemoryStateStore(), transport))
	if err != nil {
		t.Fatal("enabled close-test manager rejected")
	}
	enabled.Close()
	if events := enabled.Startup(context.Background()); len(events) != 0 {
		t.Fatal("closed manager sent a startup notification")
	}
	if events := enabled.HandleSync(context.Background(), failedSync(clock)); len(events) != 0 {
		t.Fatal("closed manager observed synchronization")
	}
	if events := enabled.SuspiciousChange(context.Background(), "feed-one", ops.Counts{Added: 1}); len(events) != 0 {
		t.Fatal("closed manager sent a suspicious-change notification")
	}
	if events := enabled.StaleSync(context.Background()); len(events) != 0 || len(transport.Notices()) != 0 {
		t.Fatal("closed manager performed network notification work")
	}
}
