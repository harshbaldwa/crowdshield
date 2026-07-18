package cli

import (
	"errors"
	"net/netip"
	"time"

	"crowdshield/internal/ops"
)

var ErrInvalidOperatorResult = errors.New("invalid operator result")

const maxOperatorCount = int64(100_000_000)

type ExplainKind string

const (
	ExplainIP    ExplainKind = "ip"
	ExplainRange ExplainKind = "range"
)

type ExplainResult struct {
	Canonical         string      `json:"canonical"`
	Kind              ExplainKind `json:"kind"`
	Desired           bool        `json:"desired"`
	Allowlisted       bool        `json:"allowlisted"`
	Covered           bool        `json:"covered"`
	CoveringPrefix    string      `json:"covering_prefix,omitempty"`
	Contributors      []string    `json:"contributors"`
	Owned             bool        `json:"owned"`
	OwnershipConflict bool        `json:"ownership_conflict"`
}

func (r ExplainResult) Validate() error {
	switch r.Kind {
	case ExplainIP:
		address, err := netip.ParseAddr(r.Canonical)
		if err != nil || address.Unmap().String() != r.Canonical {
			return ErrInvalidOperatorResult
		}
	case ExplainRange:
		prefix, err := netip.ParsePrefix(r.Canonical)
		if err != nil || prefix.Masked().String() != r.Canonical {
			return ErrInvalidOperatorResult
		}
	default:
		return ErrInvalidOperatorResult
	}
	if r.Covered {
		prefix, err := netip.ParsePrefix(r.CoveringPrefix)
		if err != nil || prefix.Masked().String() != r.CoveringPrefix {
			return ErrInvalidOperatorResult
		}
	} else if r.CoveringPrefix != "" {
		return ErrInvalidOperatorResult
	}
	if len(r.Contributors) > 256 {
		return ErrInvalidOperatorResult
	}
	for _, contributor := range r.Contributors {
		if !ops.ValidFeedName(contributor) {
			return ErrInvalidOperatorResult
		}
	}
	return nil
}

type StatusReason string

const (
	StatusReady       StatusReason = "ready"
	StatusSyncPending StatusReason = "sync_pending"
	StatusSyncStale   StatusReason = "sync_stale"
	StatusDatabase    StatusReason = "database_unavailable"
	StatusRuntime     StatusReason = "runtime_unavailable"
)

type FeedStatus struct {
	Name                string              `json:"name"`
	Enabled             bool                `json:"enabled"`
	LastSuccess         time.Time           `json:"-"`
	ConsecutiveFailures int                 `json:"consecutive_failures"`
	LastFailure         ops.FailureCategory `json:"last_failure,omitempty"`
}

func (f FeedStatus) Validate() error {
	if !ops.ValidFeedName(f.Name) || f.ConsecutiveFailures < 0 || f.ConsecutiveFailures > 100 {
		return ErrInvalidOperatorResult
	}
	if f.LastFailure != "" && !ops.ValidFailureCategory(f.LastFailure) {
		return ErrInvalidOperatorResult
	}
	if f.ConsecutiveFailures > 0 && f.LastFailure == "" {
		return ErrInvalidOperatorResult
	}
	return nil
}

type Status struct {
	Ready           bool
	Reason          StatusReason
	LastSafeSync    time.Time
	ActiveDecisions int64
	LastOutcome     ops.Outcome
	LastFailure     ops.FailureCategory
}

func validStatusOutcome(outcome ops.Outcome) bool {
	switch outcome {
	case "", ops.OutcomeSuccess, ops.OutcomeDegraded, ops.OutcomeFailed, ops.OutcomeCancelled:
		return true
	default:
		return false
	}
}

func (s Status) Validate() error {
	if s.ActiveDecisions < 0 || s.ActiveDecisions > maxOperatorCount || !validStatusOutcome(s.LastOutcome) {
		return ErrInvalidOperatorResult
	}
	if s.Ready {
		if s.Reason != StatusReady {
			return ErrInvalidOperatorResult
		}
	} else {
		switch s.Reason {
		case StatusSyncPending, StatusSyncStale, StatusDatabase, StatusRuntime:
		default:
			return ErrInvalidOperatorResult
		}
	}
	if s.LastFailure != "" && !ops.ValidFailureCategory(s.LastFailure) {
		return ErrInvalidOperatorResult
	}
	if s.LastOutcome == ops.OutcomeSuccess && s.LastFailure != "" {
		return ErrInvalidOperatorResult
	}
	if s.LastOutcome == "" && s.LastFailure != "" {
		return ErrInvalidOperatorResult
	}
	return nil
}
