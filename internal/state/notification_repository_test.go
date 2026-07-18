package state

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"crowdshield/internal/notify"
	"crowdshield/internal/ops"
)

var _ notify.StateStore = (*NotificationStateStore)(nil)

func TestNotificationStateRoundTripsAndUpsertsOnlyBoundedFields(t *testing.T) {
	store := openTestStore(t)
	repository := store.NotificationStates()
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	key := notify.StateKey{Kind: notify.KindRepeatedFailure}
	state := notify.PersistentState{
		Key: key, Failure: ops.FailureFeedDownload, Feed: "feed-one",
		ConsecutiveFailures: 3, Notified: true,
		LastAttempt: now, UpdatedAt: now,
	}
	if err := repository.Save(ctx, state); err != nil {
		t.Fatal("valid notification state was not saved")
	}
	loaded, found, err := repository.Load(ctx, key)
	if err != nil || !found || loaded.Key != state.Key || loaded.Failure != state.Failure ||
		loaded.Feed != state.Feed || loaded.ConsecutiveFailures != 3 || !loaded.Notified ||
		!loaded.LastAttempt.Equal(now) || !loaded.UpdatedAt.Equal(now) {
		t.Fatal("notification state did not round-trip")
	}
	state.ConsecutiveFailures = 4
	state.Notified = false
	state.RecoveryPending = true
	state.LastAttempt = now.Add(time.Hour)
	state.UpdatedAt = now.Add(time.Hour)
	if err := repository.Save(ctx, state); err != nil {
		t.Fatal("notification state upsert failed")
	}
	loaded, found, err = repository.Load(ctx, key)
	if err != nil || !found || loaded.ConsecutiveFailures != 4 || loaded.Notified || !loaded.RecoveryPending || !loaded.LastAttempt.Equal(now.Add(time.Hour)) {
		t.Fatal("notification state upsert was inaccurate")
	}
	_, found, err = repository.Load(ctx, notify.StateKey{Kind: notify.KindStaleSync})
	if err != nil || found {
		t.Fatal("missing notification state did not return a bounded miss")
	}
}

func TestNotificationStatePersistsAcrossStoreReopen(t *testing.T) {
	options := Options{
		Path:        filepath.Join(t.TempDir(), "notification-state.db"),
		BusyTimeout: time.Second, IntegrityCheck: true,
	}
	ctx := context.Background()
	store, err := Open(ctx, options)
	if err != nil {
		t.Fatal("notification persistence store did not open")
	}
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	state := notify.PersistentState{
		Key: notify.StateKey{Kind: notify.KindFirstSuccess}, Sent: true,
		LastAttempt: now, UpdatedAt: now,
	}
	if err := store.NotificationStates().Save(ctx, state); err != nil {
		t.Fatal("notification state save failed")
	}
	if err := store.Close(); err != nil {
		t.Fatal("notification persistence store did not close")
	}
	reopened, err := Open(ctx, options)
	if err != nil {
		t.Fatal("notification persistence store did not reopen")
	}
	defer reopened.Close()
	loaded, found, err := reopened.NotificationStates().Load(ctx, state.Key)
	if err != nil || !found || !loaded.Sent || !loaded.LastAttempt.Equal(now) {
		t.Fatal("notification state was not durable across reopen")
	}
}

func TestNotificationStateRejectsIndicatorBearingOrInvalidKeys(t *testing.T) {
	repository := openTestStore(t).NotificationStates()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	invalid := []notify.PersistentState{
		{Key: notify.StateKey{Kind: notify.KindSuspiciousChange, Feed: "198.51.100.23"}, UpdatedAt: now},
		{Key: notify.StateKey{Kind: notify.KindRepeatedFailure}, Failure: ops.FailureLAPI, Feed: "2001:db8::23", ConsecutiveFailures: 1, UpdatedAt: now},
		{Key: notify.StateKey{Kind: notify.KindRepeatedFailure}, Failure: ops.FailureCategory("password-canary"), ConsecutiveFailures: 1, UpdatedAt: now},
	}
	for _, state := range invalid {
		if err := repository.Save(context.Background(), state); err == nil || !IsCategory(err, ErrConstraint) {
			t.Fatal("unsafe notification state was accepted")
		}
	}
}

type notificationTestClock struct {
	now time.Time
}

func (c notificationTestClock) Now() time.Time { return c.now }

type notificationTestTransport struct {
	mu      sync.Mutex
	notices []notify.Notice
}

func (t *notificationTestTransport) Send(_ context.Context, notice notify.Notice) error {
	t.mu.Lock()
	t.notices = append(t.notices, notice)
	t.mu.Unlock()
	return nil
}

func (t *notificationTestTransport) Kinds() []notify.Kind {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]notify.Kind, len(t.notices))
	for index, notice := range t.notices {
		result[index] = notice.Kind
	}
	return result
}

func TestNotificationManagerDeduplicationSurvivesSQLiteReopen(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	clock := notificationTestClock{now: now}
	transport := &notificationTestTransport{}
	options := Options{
		Path:        filepath.Join(t.TempDir(), "notification-manager.db"),
		BusyTimeout: time.Second, IntegrityCheck: true,
	}
	newManager := func(store *Store) *notify.Manager {
		manager, err := notify.NewManager(notify.ManagerOptions{
			Enabled: true, Clock: clock, Store: store.NotificationStates(), Transport: transport,
			MinimumSeverity: ops.SeverityInfo, FailureThreshold: 1, Cooldown: time.Hour,
			RecoveryNotifications: true,
		})
		if err != nil {
			t.Fatal("SQLite-backed notification manager rejected")
		}
		return manager
	}
	failure := ops.Result{
		Outcome: ops.OutcomeFailed, Failure: ops.FailureLAPI, Retryable: true,
		StartedAt: now.Add(-time.Second), CompletedAt: now,
	}
	success := ops.Result{
		Outcome:   ops.OutcomeSuccess,
		StartedAt: now.Add(time.Minute - time.Second), CompletedAt: now.Add(time.Minute),
	}

	store, err := Open(ctx, options)
	if err != nil {
		t.Fatal("notification integration store did not open")
	}
	if events := newManager(store).HandleSync(ctx, failure); len(events) != 1 || events[0].Outcome != ops.OutcomeSuccess {
		t.Fatal("initial repeated-failure notification was not delivered")
	}
	if err := store.Close(); err != nil {
		t.Fatal("notification integration store did not close")
	}

	reopened, err := Open(ctx, options)
	if err != nil {
		t.Fatal("notification integration store did not reopen")
	}
	defer reopened.Close()
	restarted := newManager(reopened)
	if events := restarted.HandleSync(ctx, failure); len(events) != 0 {
		t.Fatal("notification was duplicated after SQLite reopen")
	}
	if events := restarted.HandleSync(ctx, success); len(events) != 1 || events[0].Outcome != ops.OutcomeSuccess {
		t.Fatal("persisted notified failure did not recover after reopen")
	}
	kinds := transport.Kinds()
	if len(kinds) != 2 || kinds[0] != notify.KindRepeatedFailure || kinds[1] != notify.KindRecovery {
		t.Fatal("SQLite-backed notification sequence was inaccurate")
	}
}
