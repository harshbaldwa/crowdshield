// Package health provides bounded, concurrency-safe liveness and readiness
// state without retaining arbitrary errors or sensitive runtime values.
package health

import (
	"context"
	"errors"
	"sync"
	"time"

	"crowdshield/internal/ops"
)

var ErrInvalidOptions = errors.New("invalid health options")
var ErrInvalidObservation = errors.New("invalid health observation")

type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type Status string

const (
	StatusReady    Status = "ready"
	StatusNotReady Status = "not_ready"
)

type Reason string

const (
	ReasonReady                  Reason = "ready"
	ReasonConfigurationPending   Reason = "configuration_pending"
	ReasonConfigurationInvalid   Reason = "configuration_invalid"
	ReasonCredentialsPending     Reason = "credentials_pending"
	ReasonCredentialsUnavailable Reason = "credentials_unavailable"
	ReasonDatabasePending        Reason = "database_pending"
	ReasonDatabaseUnavailable    Reason = "database_unavailable"
	ReasonLAPIPending            Reason = "lapi_pending"
	ReasonLAPIUnavailable        Reason = "lapi_unavailable"
	ReasonSyncPending            Reason = "sync_pending"
	ReasonSyncStale              Reason = "sync_stale"
	ReasonRuntimeFatal           Reason = "runtime_fatal"
	ReasonStopping               Reason = "stopping"
)

type Component string

const (
	ComponentPending     Component = "pending"
	ComponentValid       Component = "valid"
	ComponentInvalid     Component = "invalid"
	ComponentLoaded      Component = "loaded"
	ComponentAvailable   Component = "available"
	ComponentUnavailable Component = "unavailable"
	ComponentGrace       Component = "grace"
	ComponentCurrent     Component = "current"
	ComponentStale       Component = "stale"
	ComponentRunning     Component = "running"
	ComponentFatal       Component = "fatal"
	ComponentStopping    Component = "stopping"
)

// Response is intentionally fixed and contains only closed status categories.
type Response struct {
	Status          Status    `json:"status"`
	Reason          Reason    `json:"reason"`
	Configuration   Component `json:"configuration"`
	Credentials     Component `json:"credentials"`
	Database        Component `json:"database"`
	LAPI            Component `json:"lapi"`
	Synchronization Component `json:"synchronization"`
	Runtime         Component `json:"runtime"`
}

type Options struct {
	Clock           Clock
	MaxSyncAge      time.Duration
	LAPIOutageGrace time.Duration
}

type Tracker struct {
	mu sync.RWMutex

	clock           Clock
	maxSyncAge      time.Duration
	lapiOutageGrace time.Duration

	configuration Component
	credentials   Component
	database      Component
	lapi          Component
	runtime       Component
	lapiEverReady bool
	lapiOutageAt  time.Time
	lastSuccess   time.Time
}

func New(options Options) (*Tracker, error) {
	if options.MaxSyncAge <= 0 || options.MaxSyncAge > 30*24*time.Hour ||
		options.LAPIOutageGrace <= 0 || options.LAPIOutageGrace > options.MaxSyncAge {
		return nil, ErrInvalidOptions
	}
	if options.Clock == nil {
		options.Clock = systemClock{}
	}
	return &Tracker{
		clock: options.Clock, maxSyncAge: options.MaxSyncAge,
		lapiOutageGrace: options.LAPIOutageGrace,
		configuration:   ComponentPending, credentials: ComponentPending,
		database: ComponentPending, lapi: ComponentPending, runtime: ComponentRunning,
	}, nil
}

func (t *Tracker) MarkConfiguration(valid bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if valid {
		t.configuration = ComponentValid
	} else {
		t.configuration = ComponentInvalid
	}
	t.mu.Unlock()
}

func (t *Tracker) MarkCredentials(loaded bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if loaded {
		t.credentials = ComponentLoaded
	} else {
		t.credentials = ComponentUnavailable
	}
	t.mu.Unlock()
}

func (t *Tracker) MarkDatabase(available bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if available {
		t.database = ComponentAvailable
	} else {
		t.database = ComponentUnavailable
	}
	t.mu.Unlock()
}

func (t *Tracker) MarkLAPI(available bool) {
	if t == nil {
		return
	}
	now := t.clock.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if available {
		t.lapi = ComponentAvailable
		t.lapiEverReady = true
		t.lapiOutageAt = time.Time{}
		return
	}
	if t.lapi != ComponentUnavailable {
		t.lapiOutageAt = now
	}
	t.lapi = ComponentUnavailable
}

func (t *Tracker) MarkRuntimeFatal() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.runtime = ComponentFatal
	t.mu.Unlock()
}

func (t *Tracker) MarkStopping() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.runtime != ComponentFatal {
		t.runtime = ComponentStopping
	}
	t.mu.Unlock()
}

func safeSynchronization(result ops.Result) bool {
	if result.Outcome == ops.OutcomeSuccess {
		return true
	}
	return result.Outcome == ops.OutcomeDegraded &&
		(result.Failure == ops.FailureFeedDownload || result.Failure == ops.FailureFeedValidation)
}

func (t *Tracker) RecordSync(result ops.Result) error {
	if t == nil || result.Validate() != nil {
		return ErrInvalidObservation
	}
	if !safeSynchronization(result) {
		return nil
	}
	t.mu.Lock()
	if result.CompletedAt.After(t.lastSuccess) {
		t.lastSuccess = result.CompletedAt
	}
	t.mu.Unlock()
	return nil
}

func (t *Tracker) recordSafeSuccess(at time.Time) {
	if at.IsZero() {
		return
	}
	t.mu.Lock()
	if at.After(t.lastSuccess) {
		t.lastSuccess = at
	}
	t.mu.Unlock()
}

func (t *Tracker) ApplyEvent(event ops.Event) error {
	if t == nil || event.Validate() != nil {
		return ErrInvalidObservation
	}
	switch event.Code {
	case ops.CodeLAPIStateChanged:
		switch event.Outcome {
		case ops.OutcomeAvailable, ops.OutcomeRecovered:
			t.MarkLAPI(true)
		case ops.OutcomeUnavailable:
			t.MarkLAPI(false)
		}
	case ops.CodeDatabaseStateChange:
		switch event.Outcome {
		case ops.OutcomeAvailable, ops.OutcomeRecovered:
			t.MarkDatabase(true)
		case ops.OutcomeUnavailable, ops.OutcomeFailed:
			t.MarkDatabase(false)
		}
	case ops.CodeRuntimeFatal:
		t.MarkRuntimeFatal()
	case ops.CodeServiceStopping, ops.CodeServiceStopped:
		t.MarkStopping()
	case ops.CodeSyncCompleted:
		if event.Outcome == ops.OutcomeSuccess ||
			(event.Outcome == ops.OutcomeDegraded && (event.Failure == ops.FailureFeedDownload || event.Failure == ops.FailureFeedValidation)) {
			t.recordSafeSuccess(event.At)
		}
	}
	return nil
}

func (t *Tracker) Observe(_ context.Context, event ops.Event) {
	_ = t.ApplyEvent(event)
}

func baseResponse(t *Tracker) Response {
	return Response{
		Status: StatusNotReady, Configuration: t.configuration,
		Credentials: t.credentials, Database: t.database, LAPI: t.lapi,
		Synchronization: ComponentPending, Runtime: t.runtime,
	}
}

func (t *Tracker) Snapshot() Response {
	if t == nil {
		return Response{
			Status: StatusNotReady, Reason: ReasonRuntimeFatal,
			Configuration: ComponentPending, Credentials: ComponentPending,
			Database: ComponentPending, LAPI: ComponentPending,
			Synchronization: ComponentPending, Runtime: ComponentFatal,
		}
	}
	now := t.clock.Now()
	t.mu.RLock()
	response := baseResponse(t)
	lastSuccess := t.lastSuccess
	lapiEverReady := t.lapiEverReady
	lapiOutageAt := t.lapiOutageAt
	t.mu.RUnlock()

	if response.Runtime == ComponentFatal {
		response.Reason = ReasonRuntimeFatal
		return response
	}
	if response.Runtime == ComponentStopping {
		response.Reason = ReasonStopping
		return response
	}
	switch response.Configuration {
	case ComponentPending:
		response.Reason = ReasonConfigurationPending
		return response
	case ComponentInvalid:
		response.Reason = ReasonConfigurationInvalid
		return response
	}
	switch response.Credentials {
	case ComponentPending:
		response.Reason = ReasonCredentialsPending
		return response
	case ComponentUnavailable:
		response.Reason = ReasonCredentialsUnavailable
		return response
	}
	switch response.Database {
	case ComponentPending:
		response.Reason = ReasonDatabasePending
		return response
	case ComponentUnavailable:
		response.Reason = ReasonDatabaseUnavailable
		return response
	}
	switch response.LAPI {
	case ComponentPending:
		response.Reason = ReasonLAPIPending
		return response
	case ComponentUnavailable:
		withinGrace := lapiEverReady && !lapiOutageAt.IsZero() && now.Sub(lapiOutageAt) <= t.lapiOutageGrace
		if withinGrace {
			response.LAPI = ComponentGrace
		} else {
			response.Reason = ReasonLAPIUnavailable
			return response
		}
	}
	if lastSuccess.IsZero() {
		response.Reason = ReasonSyncPending
		return response
	}
	if now.Sub(lastSuccess) > t.maxSyncAge {
		response.Synchronization = ComponentStale
		response.Reason = ReasonSyncStale
		return response
	}
	response.Synchronization = ComponentCurrent
	response.Status = StatusReady
	response.Reason = ReasonReady
	return response
}
