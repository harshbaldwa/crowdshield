package scheduler

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"math/big"
	"sync/atomic"
	"time"

	"crowdshield/internal/ops"
)

var (
	ErrInvalidOptions = errors.New("invalid scheduler options")
	ErrAlreadyRunning = errors.New("scheduler already running")
	ErrInvalidResult  = errors.New("invalid scheduler job result")
)

type Timer interface {
	C() <-chan time.Time
	Stop() bool
}

type Clock interface {
	Now() time.Time
	NewTimer(time.Duration) Timer
}

type Random interface {
	Int63n(int64) int64
}

type Job func(context.Context) ops.Result

type Observer interface {
	Observe(context.Context, ops.Event)
}

type ObserverFunc func(context.Context, ops.Event)

func (f ObserverFunc) Observe(ctx context.Context, event ops.Event) {
	if f != nil {
		f(ctx, event)
	}
}

type noopObserver struct{}

func (noopObserver) Observe(context.Context, ops.Event) {}

type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

type Options struct {
	Clock          Clock
	Random         Random
	Interval       time.Duration
	StartupJitter  time.Duration
	RunImmediately bool
	Retry          RetryPolicy
	Job            Job
	Observer       Observer
}

type Scheduler struct {
	clock          Clock
	random         Random
	interval       time.Duration
	startupJitter  time.Duration
	runImmediately bool
	retry          RetryPolicy
	job            Job
	observer       Observer
	running        atomic.Bool
}

type systemClock struct{}

type systemTimer struct{ timer *time.Timer }

func (systemClock) Now() time.Time { return time.Now() }
func (systemClock) NewTimer(delay time.Duration) Timer {
	return systemTimer{timer: time.NewTimer(delay)}
}
func (t systemTimer) C() <-chan time.Time { return t.timer.C }
func (t systemTimer) Stop() bool          { return t.timer.Stop() }

type secureRandom struct{}

func (secureRandom) Int63n(limit int64) int64 {
	if limit <= 1 {
		return 0
	}
	value, err := cryptorand.Int(cryptorand.Reader, big.NewInt(limit))
	if err != nil {
		return 0
	}
	return value.Int64()
}

func validRetry(policy RetryPolicy) bool {
	return policy.MaxAttempts >= 1 && policy.MaxAttempts <= 10 &&
		policy.InitialBackoff > 0 && policy.MaxBackoff >= policy.InitialBackoff &&
		policy.MaxBackoff <= 24*time.Hour
}

func New(options Options) (*Scheduler, error) {
	if options.Interval <= 0 || options.Interval > 30*24*time.Hour ||
		options.StartupJitter < 0 || options.StartupJitter > options.Interval ||
		!validRetry(options.Retry) || options.Job == nil {
		return nil, ErrInvalidOptions
	}
	if options.Clock == nil {
		options.Clock = systemClock{}
	}
	if options.Random == nil {
		options.Random = secureRandom{}
	}
	if options.Observer == nil {
		options.Observer = noopObserver{}
	}
	return &Scheduler{
		clock: options.Clock, random: options.Random, interval: options.Interval,
		startupJitter: options.StartupJitter, runImmediately: options.RunImmediately,
		retry: options.Retry, job: options.Job, observer: options.Observer,
	}, nil
}

func (s *Scheduler) jitter() time.Duration {
	if s.startupJitter <= 0 {
		return 0
	}
	// Include both endpoints of the configured interval when representable.
	limit := s.startupJitter.Nanoseconds()
	if limit < int64(^uint64(0)>>1) {
		limit++
	}
	return time.Duration(s.random.Int63n(limit))
}

func (s *Scheduler) wait(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := s.clock.NewTimer(delay)
	select {
	case <-ctx.Done():
		timer.Stop()
		return false
	case <-timer.C():
		return true
	}
}

func (s *Scheduler) execute(ctx context.Context) (ops.Result, error) {
	result := s.job(ctx)
	if err := result.Validate(); err != nil {
		return ops.Result{}, ErrInvalidResult
	}
	return result, nil
}

func (s *Scheduler) emit(ctx context.Context, event ops.Event) {
	if event.Validate() == nil {
		s.observer.Observe(ctx, event)
	}
}

func (s *Scheduler) retryDelay(failedAttempt int) time.Duration {
	delay := s.retry.InitialBackoff
	for attempt := 1; attempt < failedAttempt && delay < s.retry.MaxBackoff; attempt++ {
		if delay > s.retry.MaxBackoff/2 {
			delay = s.retry.MaxBackoff
		} else {
			delay *= 2
		}
	}
	if delay > s.retry.MaxBackoff {
		return s.retry.MaxBackoff
	}
	return delay
}

func (s *Scheduler) executeCycle(ctx context.Context) error {
	hadFailure := false
	for attempt := 1; attempt <= s.retry.MaxAttempts; attempt++ {
		result, err := s.execute(ctx)
		if err != nil {
			return err
		}
		if ctx.Err() != nil || result.Outcome == ops.OutcomeCancelled {
			return nil
		}
		if result.Outcome == ops.OutcomeSuccess {
			if hadFailure {
				s.emit(ctx, ops.Event{
					Code: ops.CodeSchedulerRecovered, Operation: ops.OperationScheduler,
					Outcome: ops.OutcomeRecovered, Severity: ops.SeverityInfo,
					At: s.clock.Now(), Attempt: attempt,
				})
			}
			return nil
		}
		if !result.Retryable || attempt == s.retry.MaxAttempts {
			return nil
		}
		hadFailure = true
		s.emit(ctx, ops.Event{
			Code: ops.CodeSchedulerRetry, Operation: ops.OperationScheduler,
			Outcome: ops.OutcomeRetrying, Severity: ops.SeverityWarning,
			Failure: result.Failure, At: s.clock.Now(), Attempt: attempt + 1,
		})
		if !s.wait(ctx, s.retryDelay(attempt)) {
			return nil
		}
	}
	return nil
}

// Run executes jobs serially. Regular deadlines are anchored to the initial
// schedule; when a job or its bounded retries runs past one or more deadlines,
// missed runs are skipped rather than overlapped or replayed.
func (s *Scheduler) Run(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalidOptions
	}
	if !s.running.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	s.emit(ctx, ops.Event{
		Code: ops.CodeSchedulerStarted, Operation: ops.OperationScheduler,
		Outcome: ops.OutcomeStarted, Severity: ops.SeverityInfo, At: s.clock.Now(),
	})
	defer func() {
		s.emit(context.WithoutCancel(ctx), ops.Event{
			Code: ops.CodeSchedulerStopped, Operation: ops.OperationScheduler,
			Outcome: ops.OutcomeStopped, Severity: ops.SeverityInfo, At: s.clock.Now(),
		})
		s.running.Store(false)
	}()

	start := s.clock.Now()
	delay := s.jitter()
	if !s.runImmediately {
		delay += s.interval
	}
	deadline := start.Add(delay)
	if !s.wait(ctx, delay) {
		return nil
	}
	if err := s.executeCycle(ctx); err != nil {
		return err
	}
	for {
		deadline = deadline.Add(s.interval)
		now := s.clock.Now()
		for !deadline.After(now) {
			deadline = deadline.Add(s.interval)
		}
		if !s.wait(ctx, deadline.Sub(now)) {
			return nil
		}
		if err := s.executeCycle(ctx); err != nil {
			return err
		}
	}
}
