package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"crowdshield/internal/buildinfo"
	"crowdshield/internal/metrics"
	"crowdshield/internal/ops"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func successfulSync(clock Clock) ops.Result {
	completed := clock.Now()
	return ops.Result{
		Outcome:   ops.OutcomeSuccess,
		StartedAt: completed.Add(-time.Second), CompletedAt: completed,
	}
}

func degradedFeedSync(clock Clock) ops.Result {
	completed := clock.Now()
	return ops.Result{
		Outcome: ops.OutcomeDegraded, Failure: ops.FailureFeedDownload,
		StartedAt: completed.Add(-time.Second), CompletedAt: completed,
		Counts: ops.Counts{FeedsFailed: 1},
	}
}

func readyTracker(t *testing.T, clock *fakeClock) *Tracker {
	t.Helper()
	tracker, err := New(Options{Clock: clock, MaxSyncAge: time.Hour, LAPIOutageGrace: 15 * time.Minute})
	if err != nil {
		t.Fatal("valid readiness options rejected")
	}
	tracker.MarkConfiguration(true)
	tracker.MarkCredentials(true)
	tracker.MarkDatabase(true)
	tracker.MarkLAPI(true)
	if err := tracker.RecordSync(successfulSync(clock)); err != nil {
		t.Fatal("valid successful sync rejected")
	}
	return tracker
}

func responseFor(t *testing.T, handler http.Handler, path string) (*httptest.ResponseRecorder, Response) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil))
	var response Response
	if path == "/readyz" {
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal("readiness response was not valid JSON")
		}
	}
	return recorder, response
}

func TestHealthIsIndependentAndReadinessRequiresInitializedSuccessfulRuntime(t *testing.T) {
	clock := newFakeClock()
	tracker, err := New(Options{Clock: clock, MaxSyncAge: time.Hour, LAPIOutageGrace: 15 * time.Minute})
	if err != nil {
		t.Fatal("valid readiness options rejected")
	}
	registry, err := metrics.New(metrics.Options{Build: buildinfo.Current(), Feeds: []string{"feed-one"}})
	if err != nil {
		t.Fatal("valid metrics registry rejected")
	}
	handler, err := NewHandler(tracker, registry)
	if err != nil {
		t.Fatal("valid observability handler rejected")
	}

	health, _ := responseFor(t, handler, "/healthz")
	if health.Code != http.StatusOK || health.Body.String() != "{\"status\":\"alive\"}\n" {
		t.Fatal("health endpoint depended on runtime readiness")
	}
	before, state := responseFor(t, handler, "/readyz")
	if before.Code != http.StatusServiceUnavailable || state.Status != StatusNotReady || state.Reason != ReasonConfigurationPending {
		t.Fatal("startup readiness did not report configuration pending")
	}
	tracker.MarkConfiguration(true)
	tracker.MarkCredentials(true)
	tracker.MarkDatabase(true)
	tracker.MarkLAPI(true)
	pending, state := responseFor(t, handler, "/readyz")
	if pending.Code != http.StatusServiceUnavailable || state.Reason != ReasonSyncPending {
		t.Fatal("readiness did not require a successful synchronization")
	}
	if err := tracker.RecordSync(successfulSync(clock)); err != nil {
		t.Fatal("valid successful sync rejected")
	}
	ready, state := responseFor(t, handler, "/readyz")
	if ready.Code != http.StatusOK || state.Status != StatusReady || state.Reason != ReasonReady || state.Synchronization != ComponentCurrent {
		t.Fatal("successful initialized runtime did not become ready")
	}
	metricsResponse, _ := responseFor(t, handler, "/metrics")
	if metricsResponse.Code != http.StatusOK || !strings.Contains(metricsResponse.Body.String(), "# TYPE crowdshield_build_info gauge") {
		t.Fatal("observability router did not expose metrics")
	}
}

func TestReadinessBecomesStaleAndOptionalFeedFailureRefreshesSafeSuccess(t *testing.T) {
	clock := newFakeClock()
	tracker := readyTracker(t, clock)
	clock.Advance(59 * time.Minute)
	if err := tracker.RecordSync(degradedFeedSync(clock)); err != nil {
		t.Fatal("safe degraded feed sync rejected")
	}
	clock.Advance(2 * time.Minute)
	state := tracker.Snapshot()
	if state.Status != StatusReady || state.Synchronization != ComponentCurrent {
		t.Fatal("temporary optional-feed failure caused readiness to flap")
	}
	clock.Advance(59*time.Minute + time.Nanosecond)
	state = tracker.Snapshot()
	if state.Status != StatusNotReady || state.Reason != ReasonSyncStale || state.Synchronization != ComponentStale {
		t.Fatal("readiness did not become stale after the configured maximum age")
	}
}

func TestLAPIOutageGraceRecoveryAndFatalStates(t *testing.T) {
	clock := newFakeClock()
	tracker := readyTracker(t, clock)
	tracker.MarkLAPI(false)
	clock.Advance(15 * time.Minute)
	state := tracker.Snapshot()
	if state.Status != StatusReady || state.LAPI != ComponentGrace {
		t.Fatal("known LAPI outage did not remain ready within grace")
	}
	clock.Advance(time.Nanosecond)
	state = tracker.Snapshot()
	if state.Status != StatusNotReady || state.Reason != ReasonLAPIUnavailable || state.LAPI != ComponentUnavailable {
		t.Fatal("LAPI outage did not become unready after grace")
	}
	tracker.MarkLAPI(true)
	state = tracker.Snapshot()
	if state.Status != StatusReady || state.LAPI != ComponentAvailable {
		t.Fatal("LAPI recovery did not restore readiness")
	}
	tracker.MarkDatabase(false)
	state = tracker.Snapshot()
	if state.Status != StatusNotReady || state.Reason != ReasonDatabaseUnavailable {
		t.Fatal("database failure did not remove readiness")
	}
	tracker.MarkDatabase(true)
	tracker.MarkRuntimeFatal()
	state = tracker.Snapshot()
	if state.Status != StatusNotReady || state.Reason != ReasonRuntimeFatal || state.Runtime != ComponentFatal {
		t.Fatal("runtime fatal state did not dominate readiness")
	}
}

func TestReadinessResponsesAreFixedBoundedAndPrivate(t *testing.T) {
	clock := newFakeClock()
	tracker := readyTracker(t, clock)
	registry, err := metrics.New(metrics.Options{Build: buildinfo.Current(), Feeds: []string{"feed-one"}})
	if err != nil {
		t.Fatal("valid metrics registry rejected")
	}
	handler, err := NewHandler(tracker, registry)
	if err != nil {
		t.Fatal("valid observability handler rejected")
	}
	response, state := responseFor(t, handler, "/readyz")
	if response.Code != http.StatusOK {
		t.Fatal("ready response failed")
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal("readiness state could not be encoded")
	}
	if response.Body.String() != string(encoded)+"\n" {
		t.Fatal("readiness JSON was not deterministic")
	}
	if len(response.Body.Bytes()) > 512 {
		t.Fatal("readiness response was not bounded")
	}
	for _, canary := range []string{
		"198.51.100.23", "2001:db8::23", "198.51.100.0/24",
		"https://feed.example.invalid/private", "password-canary-do-not-emit",
		"token-canary-do-not-emit", "eyJhbGciOiJIUzI1NiJ9.canary.signature",
	} {
		if strings.Contains(response.Body.String(), canary) {
			t.Fatal("readiness response exposed a privacy canary")
		}
	}
	unsupported := httptest.NewRecorder()
	handler.ServeHTTP(unsupported, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/readyz", nil))
	if unsupported.Code != http.StatusMethodNotAllowed {
		t.Fatal("readiness endpoint accepted an unsupported method")
	}
}

func TestReadinessConcurrentUpdatesAndReads(t *testing.T) {
	clock := newFakeClock()
	tracker := readyTracker(t, clock)
	var workers sync.WaitGroup
	for index := 0; index < 32; index++ {
		workers.Add(1)
		go func(value int) {
			defer workers.Done()
			for iteration := 0; iteration < 100; iteration++ {
				tracker.MarkLAPI((value+iteration)%2 == 0)
				tracker.MarkDatabase(true)
				_ = tracker.RecordSync(successfulSync(clock))
				_ = tracker.Snapshot()
				tracker.Observe(context.Background(), ops.Event{
					Code: ops.CodeLAPIStateChanged, Operation: ops.OperationLAPI,
					Outcome: ops.OutcomeAvailable, Severity: ops.SeverityInfo, At: clock.Now(),
				})
			}
		}(index)
	}
	workers.Wait()
	tracker.MarkLAPI(true)
	if tracker.Snapshot().Status != StatusReady {
		t.Fatal("readiness did not recover after concurrent updates")
	}
}
