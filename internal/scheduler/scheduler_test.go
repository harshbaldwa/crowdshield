package scheduler

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"crowdshield/internal/ops"
)

type fakeTimer struct {
	clock   *fakeClock
	due     time.Time
	channel chan time.Time
	stopped bool
	fired   bool
}

func (t *fakeTimer) C() <-chan time.Time { return t.channel }

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.stopped || t.fired {
		return false
	}
	t.stopped = true
	t.clock.active--
	return true
}

type fakeClock struct {
	mu            sync.Mutex
	now           time.Time
	timers        []*fakeTimer
	created       []time.Duration
	createdSignal chan struct{}
	active        int
}

func newFakeClock() *fakeClock {
	return &fakeClock{
		now:           time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
		createdSignal: make(chan struct{}, 32),
	}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(delay time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &fakeTimer{clock: c, due: c.now.Add(delay), channel: make(chan time.Time, 1)}
	c.timers = append(c.timers, timer)
	c.created = append(c.created, delay)
	c.active++
	select {
	case c.createdSignal <- struct{}{}:
	default:
	}
	return timer
}

func (c *fakeClock) Advance(delay time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delay)
	var fire []*fakeTimer
	for _, timer := range c.timers {
		if !timer.stopped && !timer.fired && !timer.due.After(c.now) {
			timer.fired = true
			c.active--
			fire = append(fire, timer)
		}
	}
	c.mu.Unlock()
	for _, timer := range fire {
		timer.channel <- timer.due
	}
}

func (c *fakeClock) Created() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.created...)
}

func (c *fakeClock) ActiveTimers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

type fixedRandom struct{ value int64 }

func (r fixedRandom) Int63n(limit int64) int64 {
	if limit <= 0 {
		panic("invalid random limit")
	}
	return r.value % limit
}

func successfulResult(clock Clock) ops.Result {
	now := clock.Now()
	return ops.Result{Outcome: ops.OutcomeSuccess, StartedAt: now, CompletedAt: now}
}

func retryableResult(clock Clock, failure ops.FailureCategory) ops.Result {
	now := clock.Now()
	return ops.Result{
		Outcome: ops.OutcomeFailed, Failure: failure, Retryable: true,
		StartedAt: now, CompletedAt: now,
	}
}

func waitSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal(message)
	}
}

func waitCall(t *testing.T, calls <-chan int, message string) int {
	t.Helper()
	select {
	case value := <-calls:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal(message)
		return 0
	}
}

func waitRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop")
		return nil
	}
}

func waitTimerCreated(t *testing.T, clock *fakeClock) {
	t.Helper()
	select {
	case <-clock.createdSignal:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not create expected timer")
	}
}

func TestRunImmediatelyExecutesInitialJobAndCancelsCleanly(t *testing.T) {
	clock := newFakeClock()
	run := make(chan struct{}, 1)
	scheduler, err := New(Options{
		Clock:          clock,
		Random:         fixedRandom{},
		Interval:       6 * time.Hour,
		StartupJitter:  0,
		RunImmediately: true,
		Retry: RetryPolicy{
			MaxAttempts: 3, InitialBackoff: time.Second, MaxBackoff: time.Minute,
		},
		Job: func(context.Context) ops.Result {
			run <- struct{}{}
			return successfulResult(clock)
		},
	})
	if err != nil {
		t.Fatal("valid scheduler options rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitSignal(t, run, "immediate job did not run")
	cancel()
	if err := waitRun(t, done); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal("graceful cancellation returned an operational failure")
	}
}

func TestInitialRunDisabledWaitsForIntervalPlusStartupJitter(t *testing.T) {
	clock := newFakeClock()
	run := make(chan struct{}, 1)
	scheduler, err := New(Options{
		Clock: clock, Random: fixedRandom{value: int64(2 * time.Minute)},
		Interval: 6 * time.Hour, StartupJitter: 10 * time.Minute, RunImmediately: false,
		Retry: RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Second, MaxBackoff: time.Minute},
		Job: func(context.Context) ops.Result {
			run <- struct{}{}
			return successfulResult(clock)
		},
	})
	if err != nil {
		t.Fatal("valid delayed scheduler options rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitTimerCreated(t, clock)
	created := clock.Created()
	if len(created) != 1 || created[0] != 6*time.Hour+2*time.Minute {
		t.Fatal("initial delay did not include interval and deterministic jitter")
	}
	clock.Advance(6*time.Hour + 2*time.Minute - time.Nanosecond)
	select {
	case <-run:
		t.Fatal("initial job ran before its deadline")
	default:
	}
	clock.Advance(time.Nanosecond)
	waitSignal(t, run, "delayed initial job did not run at its deadline")
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Fatal("delayed scheduler did not cancel cleanly")
	}
}

func TestImmediateInitialRunHonorsStartupJitter(t *testing.T) {
	clock := newFakeClock()
	run := make(chan struct{}, 1)
	scheduler, err := New(Options{
		Clock: clock, Random: fixedRandom{value: int64(3 * time.Minute)},
		Interval: 6 * time.Hour, StartupJitter: 10 * time.Minute, RunImmediately: true,
		Retry: RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Second, MaxBackoff: time.Minute},
		Job: func(context.Context) ops.Result {
			run <- struct{}{}
			return successfulResult(clock)
		},
	})
	if err != nil {
		t.Fatal("valid jittered scheduler options rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitTimerCreated(t, clock)
	created := clock.Created()
	if len(created) != 1 || created[0] != 3*time.Minute {
		t.Fatal("immediate initial delay did not use deterministic startup jitter")
	}
	clock.Advance(3*time.Minute - time.Nanosecond)
	select {
	case <-run:
		t.Fatal("jittered initial job ran early")
	default:
	}
	clock.Advance(time.Nanosecond)
	waitSignal(t, run, "jittered initial job did not run at its deadline")
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Fatal("jittered scheduler did not cancel cleanly")
	}
}

func TestRegularCadenceRunsOncePerAnchoredInterval(t *testing.T) {
	clock := newFakeClock()
	run := make(chan struct{}, 4)
	scheduler, err := New(Options{
		Clock: clock, Random: fixedRandom{}, Interval: 6 * time.Hour,
		StartupJitter: 0, RunImmediately: true,
		Retry: RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Second, MaxBackoff: time.Minute},
		Job: func(context.Context) ops.Result {
			run <- struct{}{}
			return successfulResult(clock)
		},
	})
	if err != nil {
		t.Fatal("valid cadence scheduler options rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitSignal(t, run, "initial cadence job did not run")
	waitTimerCreated(t, clock)
	clock.Advance(6 * time.Hour)
	waitSignal(t, run, "second cadence job did not run")
	waitTimerCreated(t, clock)
	clock.Advance(6 * time.Hour)
	waitSignal(t, run, "third cadence job did not run")
	created := clock.Created()
	if len(created) < 2 || created[0] != 6*time.Hour || created[1] != 6*time.Hour {
		t.Fatal("regular cadence timers were not one fixed interval")
	}
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Fatal("cadence scheduler did not cancel cleanly")
	}
}

func TestLongRunningJobNeverOverlapsAndMissedCadenceIsSkipped(t *testing.T) {
	clock := newFakeClock()
	entered := make(chan struct{}, 4)
	releaseFirst := make(chan struct{})
	var runs atomic.Int32
	scheduler, err := New(Options{
		Clock: clock, Random: fixedRandom{}, Interval: time.Hour,
		StartupJitter: 0, RunImmediately: true,
		Retry: RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Second, MaxBackoff: time.Minute},
		Job: func(ctx context.Context) ops.Result {
			number := runs.Add(1)
			entered <- struct{}{}
			if number == 1 {
				select {
				case <-releaseFirst:
				case <-ctx.Done():
					now := clock.Now()
					return ops.Result{Outcome: ops.OutcomeCancelled, Failure: ops.FailureCancelled, StartedAt: now, CompletedAt: now}
				}
			}
			return successfulResult(clock)
		},
	})
	if err != nil {
		t.Fatal("valid non-overlap scheduler options rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitSignal(t, entered, "first long-running job did not start")
	clock.Advance(3*time.Hour + 30*time.Minute)
	if runs.Load() != 1 {
		t.Fatal("scheduler overlapped a still-running job")
	}
	close(releaseFirst)
	waitTimerCreated(t, clock)
	created := clock.Created()
	if len(created) != 1 || created[0] != 30*time.Minute {
		t.Fatal("missed cadence was replayed or drifted from its original anchor")
	}
	clock.Advance(30 * time.Minute)
	waitSignal(t, entered, "next future anchored job did not run")
	if runs.Load() != 2 {
		t.Fatal("scheduler ran more than one job at the next cadence")
	}
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Fatal("non-overlap scheduler did not cancel cleanly")
	}
}

func TestCancellationWhileIdleStopsOutstandingTimer(t *testing.T) {
	clock := newFakeClock()
	run := make(chan struct{}, 1)
	scheduler, err := New(Options{
		Clock: clock, Random: fixedRandom{}, Interval: time.Hour,
		StartupJitter: 0, RunImmediately: true,
		Retry: RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Second, MaxBackoff: time.Minute},
		Job: func(context.Context) ops.Result {
			run <- struct{}{}
			return successfulResult(clock)
		},
	})
	if err != nil {
		t.Fatal("valid idle-cancellation scheduler options rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitSignal(t, run, "initial idle-cancellation job did not run")
	waitTimerCreated(t, clock)
	if clock.ActiveTimers() != 1 {
		t.Fatal("scheduler did not have exactly one idle timer")
	}
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Fatal("idle scheduler cancellation returned an error")
	}
	if clock.ActiveTimers() != 0 {
		t.Fatal("idle scheduler left a timer active after cancellation")
	}
}

func TestTransientFailureRetriesRecoversResetsBackoffAndKeepsCadence(t *testing.T) {
	clock := newFakeClock()
	calls := make(chan int, 8)
	events := make(chan ops.Event, 16)
	var attempt atomic.Int32
	scheduler, err := New(Options{
		Clock: clock, Random: fixedRandom{}, Interval: time.Hour,
		StartupJitter: 0, RunImmediately: true,
		Retry:    RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Minute, MaxBackoff: 5 * time.Minute},
		Observer: ObserverFunc(func(_ context.Context, event ops.Event) { events <- event }),
		Job: func(context.Context) ops.Result {
			current := int(attempt.Add(1))
			calls <- current
			switch current {
			case 1, 2, 4:
				return retryableResult(clock, ops.FailureLAPI)
			default:
				return successfulResult(clock)
			}
		},
	})
	if err != nil {
		t.Fatal("valid retrying scheduler options rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()

	if got := <-calls; got != 1 {
		t.Fatal("unexpected first attempt")
	}
	waitTimerCreated(t, clock)
	if got := clock.Created(); len(got) != 1 || got[0] != time.Minute {
		t.Fatal("first retry did not use initial backoff")
	}
	clock.Advance(time.Minute)
	if got := <-calls; got != 2 {
		t.Fatal("unexpected second attempt")
	}
	waitTimerCreated(t, clock)
	if got := clock.Created(); len(got) != 2 || got[1] != 2*time.Minute {
		t.Fatal("second retry did not double backoff")
	}
	clock.Advance(2 * time.Minute)
	if got := <-calls; got != 3 {
		t.Fatal("recovery attempt did not run")
	}
	waitTimerCreated(t, clock)
	if got := clock.Created(); len(got) != 3 || got[2] != 57*time.Minute {
		t.Fatal("retries shifted the anchored regular cadence")
	}
	clock.Advance(57 * time.Minute)
	if got := <-calls; got != 4 {
		t.Fatal("next regular run did not occur at the original cadence")
	}
	waitTimerCreated(t, clock)
	if got := clock.Created(); len(got) != 4 || got[3] != time.Minute {
		t.Fatal("retry backoff did not reset after recovery")
	}
	clock.Advance(time.Minute)
	if got := <-calls; got != 5 {
		t.Fatal("post-reset recovery attempt did not run")
	}
	waitTimerCreated(t, clock)
	if got := clock.Created(); len(got) != 5 || got[4] != 59*time.Minute {
		t.Fatal("post-recovery schedule did not remain anchored")
	}

	var retries, recoveries int
	drain := true
	for drain {
		select {
		case event := <-events:
			if err := event.Validate(); err != nil {
				t.Fatal("scheduler emitted an invalid operational event")
			}
			switch event.Code {
			case ops.CodeSchedulerRetry:
				retries++
			case ops.CodeSchedulerRecovered:
				recoveries++
			}
		default:
			drain = false
		}
	}
	if retries != 3 || recoveries != 2 {
		t.Fatal("retry and recovery transitions were not emitted exactly once")
	}
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Fatal("retrying scheduler did not cancel cleanly")
	}
}

func TestCancellationWhileJobRunningPropagatesAndEmitsLifecycle(t *testing.T) {
	clock := newFakeClock()
	entered := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	events := make(chan ops.Event, 8)
	scheduler, err := New(Options{
		Clock: clock, Random: fixedRandom{}, Interval: time.Hour,
		StartupJitter: 0, RunImmediately: true,
		Retry:    RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Second, MaxBackoff: time.Minute},
		Observer: ObserverFunc(func(_ context.Context, event ops.Event) { events <- event }),
		Job: func(ctx context.Context) ops.Result {
			started := clock.Now()
			entered <- struct{}{}
			<-ctx.Done()
			cancelled <- struct{}{}
			return ops.Result{
				Outcome: ops.OutcomeCancelled, Failure: ops.FailureCancelled,
				StartedAt: started, CompletedAt: clock.Now(),
			}
		},
	})
	if err != nil {
		t.Fatal("valid running-cancellation scheduler options rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitSignal(t, entered, "running job did not start")
	cancel()
	waitSignal(t, cancelled, "in-flight job did not receive cancellation")
	if err := waitRun(t, done); err != nil {
		t.Fatal("running scheduler cancellation returned an error")
	}
	if clock.ActiveTimers() != 0 {
		t.Fatal("running cancellation left an active timer")
	}
	var startedEvents, stoppedEvents int
	drain := true
	for drain {
		select {
		case event := <-events:
			if err := event.Validate(); err != nil {
				t.Fatal("scheduler lifecycle event was invalid")
			}
			switch event.Code {
			case ops.CodeSchedulerStarted:
				startedEvents++
			case ops.CodeSchedulerStopped:
				stoppedEvents++
			}
		default:
			drain = false
		}
	}
	if startedEvents != 1 || stoppedEvents != 1 {
		t.Fatal("scheduler lifecycle was not emitted exactly once")
	}
}

func TestRetryBackoffCapsAtMaximumAndStopsAtAttemptLimit(t *testing.T) {
	clock := newFakeClock()
	calls := make(chan int, 8)
	var attempts atomic.Int32
	scheduler, err := New(Options{
		Clock: clock, Random: fixedRandom{}, Interval: time.Minute,
		StartupJitter: 0, RunImmediately: true,
		Retry: RetryPolicy{MaxAttempts: 5, InitialBackoff: 2 * time.Second, MaxBackoff: 5 * time.Second},
		Job: func(context.Context) ops.Result {
			current := int(attempts.Add(1))
			calls <- current
			return retryableResult(clock, ops.FailureFeedDownload)
		},
	})
	if err != nil {
		t.Fatal("valid capped-backoff scheduler options rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	if got := waitCall(t, calls, "first bounded retry attempt missing"); got != 1 {
		t.Fatal("unexpected first bounded retry attempt")
	}
	for index, delay := range []time.Duration{2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second} {
		waitTimerCreated(t, clock)
		created := clock.Created()
		if created[index] != delay {
			t.Fatal("retry delay did not obey exponential maximum")
		}
		clock.Advance(delay)
		if got := waitCall(t, calls, "bounded retry attempt missing"); got != index+2 {
			t.Fatal("unexpected bounded retry attempt number")
		}
	}
	waitTimerCreated(t, clock)
	created := clock.Created()
	if len(created) != 5 || created[4] != 44*time.Second {
		t.Fatal("attempt exhaustion did not return to the future anchored cadence")
	}
	select {
	case <-calls:
		t.Fatal("scheduler exceeded the configured retry attempt limit")
	default:
	}
	if clock.ActiveTimers() != 1 {
		t.Fatal("attempt exhaustion created duplicate timers")
	}
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Fatal("bounded-backoff scheduler did not cancel cleanly")
	}
}

func TestCancellationDuringStartupWaitDoesNotRunJob(t *testing.T) {
	clock := newFakeClock()
	var calls atomic.Int32
	scheduler, err := New(Options{
		Clock: clock, Random: fixedRandom{}, Interval: time.Hour,
		StartupJitter: 0, RunImmediately: false,
		Retry: RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Second, MaxBackoff: time.Minute},
		Job: func(context.Context) ops.Result {
			calls.Add(1)
			return successfulResult(clock)
		},
	})
	if err != nil {
		t.Fatal("valid startup-wait scheduler options rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitTimerCreated(t, clock)
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Fatal("startup-wait cancellation returned an error")
	}
	if calls.Load() != 0 || clock.ActiveTimers() != 0 {
		t.Fatal("startup cancellation ran work or left a timer")
	}
}

func TestConcurrentRunFailsFastWithoutStartingAnotherJob(t *testing.T) {
	clock := newFakeClock()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	scheduler, err := New(Options{
		Clock: clock, Random: fixedRandom{}, Interval: time.Hour,
		StartupJitter: 0, RunImmediately: true,
		Retry: RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Second, MaxBackoff: time.Minute},
		Job: func(ctx context.Context) ops.Result {
			calls.Add(1)
			entered <- struct{}{}
			select {
			case <-release:
				return successfulResult(clock)
			case <-ctx.Done():
				now := clock.Now()
				return ops.Result{Outcome: ops.OutcomeCancelled, Failure: ops.FailureCancelled, StartedAt: now, CompletedAt: now}
			}
		},
	})
	if err != nil {
		t.Fatal("valid concurrent-run scheduler options rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scheduler.Run(ctx) }()
	waitSignal(t, entered, "first concurrent-run job did not start")
	if err := scheduler.Run(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatal("second scheduler run did not fail fast")
	}
	if calls.Load() != 1 {
		t.Fatal("second scheduler run launched overlapping work")
	}
	close(release)
	cancel()
	if err := waitRun(t, done); err != nil {
		t.Fatal("first scheduler run did not stop cleanly")
	}
}
