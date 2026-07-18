package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"crowdshield/internal/metrics"
	"crowdshield/internal/ops"
	"crowdshield/internal/reconcile"
	"crowdshield/internal/state"
	"crowdshield/internal/syncer"
)

type fakeSyncEngine struct {
	actions *[]string
	report  syncer.Report
	err     error
	calls   int
}

func (e *fakeSyncEngine) Run(context.Context, syncer.RunOptions) (syncer.Report, error) {
	*e.actions = append(*e.actions, "engine")
	e.calls++
	return e.report, e.err
}

type fakeSyncState struct {
	actions            *[]string
	beginID            int64
	beginErr           error
	active             []state.DecisionRecord
	activeErr          error
	complete           ops.Result
	completeErr        error
	completeContextErr error
	lastSafe           time.Time
	runtimeErr         error
}

func (s *fakeSyncState) BeginSyncRun(_ context.Context, mode state.SyncMode, requestedFeed string, _ time.Time) (int64, error) {
	*s.actions = append(*s.actions, "begin")
	if mode != state.SyncModeEnforce || requestedFeed != "" {
		return 0, &state.Error{Category: state.ErrConstraint}
	}
	return s.beginID, s.beginErr
}

func (s *fakeSyncState) ListActiveDecisions(context.Context) ([]state.DecisionRecord, error) {
	*s.actions = append(*s.actions, "active")
	return append([]state.DecisionRecord(nil), s.active...), s.activeErr
}

func (s *fakeSyncState) CompleteSyncRun(ctx context.Context, _ int64, result ops.Result) error {
	*s.actions = append(*s.actions, "complete")
	s.complete = result
	s.completeContextErr = ctx.Err()
	return s.completeErr
}

func (s *fakeSyncState) RuntimeTimestamp(_ context.Context, key state.RuntimeTimestampKey) (time.Time, bool, error) {
	*s.actions = append(*s.actions, "runtime_safe")
	if key != state.RuntimeLastSafeSync {
		return time.Time{}, false, &state.Error{Category: state.ErrConstraint}
	}
	return s.lastSafe, !s.lastSafe.IsZero(), s.runtimeErr
}

type fakeSyncMetrics struct {
	actions *[]string
	result  ops.Result
}

func (m *fakeSyncMetrics) ObserveSync(mode metrics.Mode, result ops.Result) error {
	*m.actions = append(*m.actions, "metrics")
	if mode != metrics.ModeEnforce {
		return metrics.ErrInvalidObservation
	}
	m.result = result
	return nil
}

type fakeSyncHealth struct {
	actions *[]string
	result  ops.Result
}

func (h *fakeSyncHealth) RecordSync(result ops.Result) error {
	*h.actions = append(*h.actions, "health")
	h.result = result
	return nil
}

type fakeSyncNotifications struct {
	actions *[]string
	result  ops.Result
}

func (n *fakeSyncNotifications) HandleSync(_ context.Context, result ops.Result) []ops.Event {
	*n.actions = append(*n.actions, "notify")
	n.result = result
	return nil
}

func (n *fakeSyncNotifications) SuspiciousChange(context.Context, string, ops.Counts) []ops.Event {
	*n.actions = append(*n.actions, "suspicious")
	return nil
}

func (n *fakeSyncNotifications) StaleSync(context.Context) []ops.Event {
	*n.actions = append(*n.actions, "stale")
	return nil
}

type actionObserver struct {
	actions *[]string
	events  []ops.Event
}

func (o *actionObserver) Observe(_ context.Context, event ops.Event) {
	*o.actions = append(*o.actions, "event:"+string(event.Code))
	o.events = append(o.events, event)
}

func TestSyncJobPersistsBeforeObservingSuccessfulRun(t *testing.T) {
	actions := make([]string, 0)
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	times := []time.Time{started, started.Add(2 * time.Second)}
	nowIndex := 0
	now := func() time.Time {
		value := times[nowIndex]
		nowIndex++
		return value
	}
	engine := &fakeSyncEngine{actions: &actions, report: syncer.Report{
		FeedsSucceeded: 1,
		Feeds:          []syncer.FeedResult{{Name: "feed-one", Status: syncer.FeedSucceeded, Accepted: 20, Rejected: 2}},
		Reconcile:      reconcile.Report{Added: 3, LAPIRequests: 1},
	}}
	history := &fakeSyncState{actions: &actions, beginID: 7, active: make([]state.DecisionRecord, 4)}
	metricSink := &fakeSyncMetrics{actions: &actions}
	healthSink := &fakeSyncHealth{actions: &actions}
	notifications := &fakeSyncNotifications{actions: &actions}
	observer := &actionObserver{actions: &actions}
	job, err := NewSyncJob(SyncJobOptions{
		Engine: engine, State: history, Metrics: metricSink, Health: healthSink,
		Notifications: notifications, Observer: observer, Now: now,
		FinalizationTimeout: time.Second, StaleAfter: 12 * time.Hour,
	})
	if err != nil {
		t.Fatal("create sync job")
	}
	result := job.Run(context.Background())
	if result.Validate() != nil || result.Outcome != ops.OutcomeSuccess || result.Counts.ActiveDecisions != 4 || result.Counts.Added != 3 {
		t.Fatal("successful synchronization result was inaccurate")
	}
	expected := []string{
		"event:sync_started", "begin", "engine", "active", "complete",
		"metrics", "health", "event:feed_result", "event:lapi_state_changed",
		"event:sync_completed", "notify",
	}
	if len(actions) != len(expected) {
		t.Fatalf("unexpected action count: got %v", actions)
	}
	for index := range expected {
		if actions[index] != expected[index] {
			t.Fatalf("unexpected runtime ordering: got %v", actions)
		}
	}
	if !reflect.DeepEqual(history.complete, result) || !reflect.DeepEqual(metricSink.result, result) ||
		!reflect.DeepEqual(healthSink.result, result) || !reflect.DeepEqual(notifications.result, result) {
		t.Fatal("runtime sinks did not receive the same durable result")
	}
	if observer.events[len(observer.events)-1].Duration != 2*time.Second {
		t.Fatal("completion event omitted synchronization duration")
	}
}

func TestSyncJobCancellationFinalizesWithoutNotifying(t *testing.T) {
	actions := make([]string, 0)
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	times := []time.Time{started, started.Add(time.Second)}
	nowIndex := 0
	engine := &fakeSyncEngine{actions: &actions, err: context.Canceled}
	history := &fakeSyncState{actions: &actions, beginID: 11}
	metricSink := &fakeSyncMetrics{actions: &actions}
	healthSink := &fakeSyncHealth{actions: &actions}
	notifications := &fakeSyncNotifications{actions: &actions}
	observer := &actionObserver{actions: &actions}
	job, err := NewSyncJob(SyncJobOptions{
		Engine: engine, State: history, Metrics: metricSink, Health: healthSink,
		Notifications: notifications, Observer: observer,
		Now: func() time.Time {
			value := times[nowIndex]
			nowIndex++
			return value
		},
		FinalizationTimeout: time.Second, StaleAfter: 12 * time.Hour,
	})
	if err != nil {
		t.Fatal("create sync job")
	}
	result := job.Run(context.Background())
	if result.Outcome != ops.OutcomeCancelled || result.Failure != ops.FailureCancelled || result.Validate() != nil {
		t.Fatal("cancellation did not produce a bounded cancelled result")
	}
	if history.completeContextErr != nil {
		t.Fatal("cancelled synchronization used a cancelled history-finalization context")
	}
	for _, action := range actions {
		if action == "active" || action == "notify" || action == "suspicious" {
			t.Fatalf("cancellation performed forbidden follow-up action: %s", action)
		}
	}
}

func TestSyncJobNotifiesWhenPersistedSafeSyncIsStale(t *testing.T) {
	actions := make([]string, 0)
	started := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	times := []time.Time{started, started.Add(time.Second)}
	nowIndex := 0
	engine := &fakeSyncEngine{actions: &actions, err: errors.Join(
		&syncer.Error{Category: syncer.ErrReconcile},
		&reconcile.Error{Category: reconcile.ErrLAPI},
	)}
	history := &fakeSyncState{actions: &actions, beginID: 13, lastSafe: started.Add(-13 * time.Hour)}
	metricSink := &fakeSyncMetrics{actions: &actions}
	healthSink := &fakeSyncHealth{actions: &actions}
	notifications := &fakeSyncNotifications{actions: &actions}
	job, err := NewSyncJob(SyncJobOptions{
		Engine: engine, State: history, Metrics: metricSink, Health: healthSink,
		Notifications: notifications, Observer: &actionObserver{actions: &actions},
		Now: func() time.Time {
			value := times[nowIndex]
			nowIndex++
			return value
		},
		FinalizationTimeout: time.Second, StaleAfter: 12 * time.Hour,
	})
	if err != nil {
		t.Fatal("create sync job")
	}
	result := job.Run(context.Background())
	if result.Outcome != ops.OutcomeFailed || result.Failure != ops.FailureLAPI || result.Validate() != nil {
		t.Fatal("injected LAPI failure did not remain bounded")
	}
	notifyIndex, runtimeIndex, staleIndex := -1, -1, -1
	for index, action := range actions {
		switch action {
		case "notify":
			notifyIndex = index
		case "runtime_safe":
			runtimeIndex = index
		case "stale":
			staleIndex = index
		}
	}
	if notifyIndex < 0 || runtimeIndex <= notifyIndex || staleIndex <= runtimeIndex {
		t.Fatalf("stale notification evaluation ordering was wrong: %v", actions)
	}
}
