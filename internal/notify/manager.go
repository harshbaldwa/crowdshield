package notify

import (
	"context"
	"errors"
	"sync"
	"time"

	"crowdshield/internal/ops"
)

var ErrInvalidManager = errors.New("invalid notification manager")

type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type StateKey struct {
	Kind Kind
	Feed string
}

func (k StateKey) Validate() error {
	switch k.Kind {
	case KindStartup, KindFirstSuccess, KindRoutineSuccess, KindRepeatedFailure, KindRecovery, KindStaleSync:
		if k.Feed != "" {
			return ErrInvalidManager
		}
	case KindSuspiciousChange:
		if !ops.ValidFeedName(k.Feed) {
			return ErrInvalidManager
		}
	default:
		return ErrInvalidManager
	}
	return nil
}

type PersistentState struct {
	Key                 StateKey
	Failure             ops.FailureCategory
	Feed                string
	ConsecutiveFailures int
	Notified            bool
	RecoveryPending     bool
	Sent                bool
	LastAttempt         time.Time
	UpdatedAt           time.Time
}

func (s PersistentState) Validate() error {
	if s.Key.Validate() != nil || s.ConsecutiveFailures < 0 || s.ConsecutiveFailures > 100 {
		return ErrInvalidManager
	}
	if s.Feed != "" && !ops.ValidFeedName(s.Feed) {
		return ErrInvalidManager
	}
	if s.Failure != "" && !ops.ValidFailureCategory(s.Failure) {
		return ErrInvalidManager
	}
	if (s.ConsecutiveFailures > 0 || s.Notified || s.RecoveryPending) &&
		(s.Key.Kind != KindRepeatedFailure || !ops.ValidFailureCategory(s.Failure)) {
		return ErrInvalidManager
	}
	if !s.LastAttempt.IsZero() && s.UpdatedAt.IsZero() {
		return ErrInvalidManager
	}
	return nil
}

type StateStore interface {
	Load(context.Context, StateKey) (PersistentState, bool, error)
	Save(context.Context, PersistentState) error
}

type Observer interface {
	Observe(context.Context, ops.Event)
}

type noopObserver struct{}

func (noopObserver) Observe(context.Context, ops.Event) {}

type ManagerOptions struct {
	Enabled   bool
	Clock     Clock
	Store     StateStore
	Transport Transport
	Observer  Observer

	MinimumSeverity               ops.Severity
	FailureThreshold              int
	Cooldown                      time.Duration
	RecoveryNotifications         bool
	SuspiciousChangeNotifications bool
	StaleSyncNotifications        bool
	StartupNotification           bool
	FirstSuccessNotification      bool
	RoutineSuccessNotification    bool
}

type Manager struct {
	mu sync.Mutex

	enabled                       bool
	closed                        bool
	clock                         Clock
	store                         StateStore
	transport                     Transport
	observer                      Observer
	minimumSeverity               ops.Severity
	failureThreshold              int
	cooldown                      time.Duration
	recoveryNotifications         bool
	suspiciousChangeNotifications bool
	staleSyncNotifications        bool
	startupNotification           bool
	firstSuccessNotification      bool
	routineSuccessNotification    bool
}

func NewManager(options ManagerOptions) (*Manager, error) {
	if !validSeverity(options.MinimumSeverity) || options.FailureThreshold < 1 ||
		options.FailureThreshold > 100 || options.Cooldown <= 0 || options.Cooldown > 30*24*time.Hour {
		return nil, ErrInvalidManager
	}
	if options.Enabled && (options.Store == nil || options.Transport == nil) {
		return nil, ErrInvalidManager
	}
	if options.Clock == nil {
		options.Clock = systemClock{}
	}
	if options.Observer == nil {
		options.Observer = noopObserver{}
	}
	return &Manager{
		enabled: options.Enabled, clock: options.Clock, store: options.Store,
		transport: options.Transport, observer: options.Observer,
		minimumSeverity: options.MinimumSeverity, failureThreshold: options.FailureThreshold,
		cooldown: options.Cooldown, recoveryNotifications: options.RecoveryNotifications,
		suspiciousChangeNotifications: options.SuspiciousChangeNotifications,
		staleSyncNotifications:        options.StaleSyncNotifications,
		startupNotification:           options.StartupNotification,
		firstSuccessNotification:      options.FirstSuccessNotification,
		routineSuccessNotification:    options.RoutineSuccessNotification,
	}, nil
}

func severityRank(value ops.Severity) int {
	switch value {
	case ops.SeverityInfo:
		return 1
	case ops.SeverityWarning:
		return 2
	case ops.SeverityError:
		return 3
	default:
		return 0
	}
}

func (m *Manager) allowedSeverity(value ops.Severity) bool {
	return severityRank(value) >= severityRank(m.minimumSeverity)
}

func (m *Manager) event(ctx context.Context, notice Notice, outcome ops.Outcome, failure ops.FailureCategory) ops.Event {
	severity := notice.Severity
	if outcome == ops.OutcomeFailed {
		severity = ops.SeverityError
	}
	event := ops.Event{
		Code: ops.CodeNotificationResult, Operation: ops.OperationNotification,
		Feed: notice.Feed, Outcome: outcome, Severity: severity,
		Failure: failure, At: m.clock.Now(),
	}
	if event.Validate() == nil {
		m.observer.Observe(ctx, event)
	}
	return event
}

func (m *Manager) stateFailure(ctx context.Context, feed string) []ops.Event {
	notice := Notice{Kind: KindRepeatedFailure, Severity: ops.SeverityError, Feed: feed, Failure: ops.FailureDatabase, ConsecutiveFailures: 1, At: m.clock.Now()}
	return []ops.Event{m.event(ctx, notice, ops.OutcomeFailed, ops.FailureDatabase)}
}

func (m *Manager) load(ctx context.Context, key StateKey) (PersistentState, bool, error) {
	state, found, err := m.store.Load(ctx, key)
	if err != nil {
		return PersistentState{}, false, ErrInvalidManager
	}
	if !found {
		return PersistentState{Key: key}, false, nil
	}
	if state.Key != key || state.Validate() != nil {
		return PersistentState{}, false, ErrInvalidManager
	}
	return state, true, nil
}

func (m *Manager) save(ctx context.Context, state *PersistentState) error {
	state.UpdatedAt = m.clock.Now()
	if state.Validate() != nil || m.store.Save(ctx, *state) != nil {
		return ErrInvalidManager
	}
	return nil
}

func (m *Manager) withinCooldown(last, now time.Time) bool {
	if last.IsZero() {
		return false
	}
	if now.Before(last) {
		return true
	}
	return now.Sub(last) < m.cooldown
}

func (m *Manager) attempt(ctx context.Context, notice Notice, state *PersistentState, onSuccess func(*PersistentState)) []ops.Event {
	if !m.allowedSeverity(notice.Severity) {
		return nil
	}
	now := m.clock.Now()
	if m.withinCooldown(state.LastAttempt, now) {
		return nil
	}
	state.LastAttempt = now
	if err := m.save(ctx, state); err != nil {
		return m.stateFailure(ctx, notice.Feed)
	}
	if err := m.transport.Send(ctx, notice); err != nil {
		return []ops.Event{m.event(ctx, notice, ops.OutcomeFailed, ops.FailureNotification)}
	}
	if onSuccess != nil {
		onSuccess(state)
		if err := m.save(ctx, state); err != nil {
			return m.stateFailure(ctx, notice.Feed)
		}
	}
	return []ops.Event{m.event(ctx, notice, ops.OutcomeSuccess, "")}
}

func failedFeed(result ops.Result) string {
	for _, feed := range result.Feeds {
		if (feed.Outcome == ops.OutcomeFailed || feed.Outcome == ops.OutcomeDegraded) && feed.Failure == result.Failure {
			return feed.Name
		}
	}
	return ""
}

func (m *Manager) handleFailure(ctx context.Context, result ops.Result) []ops.Event {
	key := StateKey{Kind: KindRepeatedFailure}
	state, _, err := m.load(ctx, key)
	if err != nil {
		return m.stateFailure(ctx, failedFeed(result))
	}
	feed := failedFeed(result)
	if state.Failure != result.Failure || state.Feed != feed || state.RecoveryPending {
		state = PersistentState{Key: key, Failure: result.Failure, Feed: feed, ConsecutiveFailures: 1}
	} else if state.ConsecutiveFailures < 100 {
		state.ConsecutiveFailures++
	}
	if err := m.save(ctx, &state); err != nil {
		return m.stateFailure(ctx, feed)
	}
	if state.Notified || state.ConsecutiveFailures < m.failureThreshold {
		return nil
	}
	notice := Notice{
		Kind: KindRepeatedFailure, Severity: ops.SeverityWarning,
		Feed: feed, Failure: result.Failure,
		ConsecutiveFailures: state.ConsecutiveFailures, At: m.clock.Now(),
	}
	return m.attempt(ctx, notice, &state, func(current *PersistentState) {
		current.Notified = true
	})
}

func (m *Manager) clearFailure(ctx context.Context) []ops.Event {
	key := StateKey{Kind: KindRepeatedFailure}
	state, found, err := m.load(ctx, key)
	if err != nil {
		return m.stateFailure(ctx, "")
	}
	if !found || (state.ConsecutiveFailures == 0 && !state.Notified && !state.RecoveryPending) {
		return nil
	}
	if !m.recoveryNotifications || (!state.Notified && !state.RecoveryPending) {
		state = PersistentState{Key: key}
		if err := m.save(ctx, &state); err != nil {
			return m.stateFailure(ctx, "")
		}
		return nil
	}
	if !state.RecoveryPending {
		state.RecoveryPending = true
		state.Notified = false
		state.ConsecutiveFailures = 0
		state.LastAttempt = time.Time{}
		if err := m.save(ctx, &state); err != nil {
			return m.stateFailure(ctx, state.Feed)
		}
	}
	notice := Notice{
		Kind: KindRecovery, Severity: ops.SeverityInfo,
		Feed: state.Feed, Failure: state.Failure, At: m.clock.Now(),
	}
	return m.attempt(ctx, notice, &state, func(current *PersistentState) {
		*current = PersistentState{Key: key}
	})
}

func (m *Manager) clearStale(ctx context.Context) []ops.Event {
	key := StateKey{Kind: KindStaleSync}
	state, found, err := m.load(ctx, key)
	if err != nil {
		return m.stateFailure(ctx, "")
	}
	if !found || (!state.Sent && state.LastAttempt.IsZero()) {
		return nil
	}
	state = PersistentState{Key: key}
	if err := m.save(ctx, &state); err != nil {
		return m.stateFailure(ctx, "")
	}
	return nil
}

func (m *Manager) successPolicy(ctx context.Context, result ops.Result) []ops.Event {
	firstKey := StateKey{Kind: KindFirstSuccess}
	first, found, err := m.load(ctx, firstKey)
	if err != nil {
		return m.stateFailure(ctx, "")
	}
	if m.firstSuccessNotification && (!found || !first.Sent) {
		notice := Notice{Kind: KindFirstSuccess, Severity: ops.SeverityInfo, At: m.clock.Now()}
		return m.attempt(ctx, notice, &first, func(current *PersistentState) { current.Sent = true })
	}
	if !m.routineSuccessNotification {
		return nil
	}
	key := StateKey{Kind: KindRoutineSuccess}
	state, _, err := m.load(ctx, key)
	if err != nil {
		return m.stateFailure(ctx, "")
	}
	notice := Notice{Kind: KindRoutineSuccess, Severity: ops.SeverityInfo, Counts: result.Counts, At: m.clock.Now()}
	return m.attempt(ctx, notice, &state, nil)
}

func (m *Manager) HandleSync(ctx context.Context, result ops.Result) []ops.Event {
	if m == nil || ctx == nil || result.Validate() != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled || m.closed {
		return nil
	}
	var events []ops.Event
	if safeSynchronization(result) {
		events = append(events, m.clearStale(ctx)...)
	}
	if result.Outcome == ops.OutcomeFailed || result.Outcome == ops.OutcomeDegraded {
		events = append(events, m.handleFailure(ctx, result)...)
		return events
	}
	if result.Outcome != ops.OutcomeSuccess {
		return events
	}
	events = append(events, m.clearFailure(ctx)...)
	events = append(events, m.successPolicy(ctx, result)...)
	return events
}

func safeSynchronization(result ops.Result) bool {
	return result.Outcome == ops.OutcomeSuccess ||
		(result.Outcome == ops.OutcomeDegraded &&
			(result.Failure == ops.FailureFeedDownload || result.Failure == ops.FailureFeedValidation))
}

func (m *Manager) Startup(ctx context.Context) []ops.Event {
	if m == nil || ctx == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled || m.closed || !m.startupNotification {
		return nil
	}
	key := StateKey{Kind: KindStartup}
	state, _, err := m.load(ctx, key)
	if err != nil {
		return m.stateFailure(ctx, "")
	}
	notice := Notice{Kind: KindStartup, Severity: ops.SeverityInfo, At: m.clock.Now()}
	return m.attempt(ctx, notice, &state, nil)
}

func (m *Manager) SuspiciousChange(ctx context.Context, feed string, counts ops.Counts) []ops.Event {
	if m == nil || ctx == nil || !ops.ValidFeedName(feed) || counts.Validate() != nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled || m.closed || !m.suspiciousChangeNotifications {
		return nil
	}
	key := StateKey{Kind: KindSuspiciousChange, Feed: feed}
	state, _, err := m.load(ctx, key)
	if err != nil {
		return m.stateFailure(ctx, feed)
	}
	notice := Notice{Kind: KindSuspiciousChange, Severity: ops.SeverityWarning, Feed: feed, Counts: counts, At: m.clock.Now()}
	return m.attempt(ctx, notice, &state, nil)
}

func (m *Manager) StaleSync(ctx context.Context) []ops.Event {
	if m == nil || ctx == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled || m.closed || !m.staleSyncNotifications {
		return nil
	}
	key := StateKey{Kind: KindStaleSync}
	state, _, err := m.load(ctx, key)
	if err != nil {
		return m.stateFailure(ctx, "")
	}
	if state.Sent {
		return nil
	}
	notice := Notice{Kind: KindStaleSync, Severity: ops.SeverityWarning, At: m.clock.Now()}
	return m.attempt(ctx, notice, &state, func(current *PersistentState) { current.Sent = true })
}

func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
}
