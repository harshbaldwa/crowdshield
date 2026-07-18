package app

import (
	"context"
	"errors"
	"time"

	"crowdshield/internal/network"
	"crowdshield/internal/state"
)

var errOperatorReadOnly = errors.New("operator state is read-only")

type operatorDryStore interface {
	EnsureFeeds(context.Context, []state.FeedDefinition, time.Time) ([]state.FeedRecord, error)
	FeedByName(context.Context, string) (state.FeedRecord, error)
	ApplyFeedSnapshot(context.Context, string, state.FeedSnapshot, int, time.Time) (state.SnapshotResult, error)
	RecordFeedNotModified(context.Context, string, string, string, time.Time) error
	RecordFeedFailure(context.Context, string, string, time.Time, time.Time) error
	ListFeeds(context.Context) ([]state.FeedRecord, error)
	ListActiveEntries(context.Context) ([]state.StoredEntry, error)
	ApplyEnforcementPlan(context.Context, []network.Object, time.Time) ([]state.EnforcementRecord, error)
	ListEnforcementObjects(context.Context) ([]state.EnforcementRecord, error)
	ListActiveDecisions(context.Context) ([]state.DecisionRecord, error)
	ListLiveDecisions(context.Context) ([]state.DecisionRecord, error)
	MarkDecisionExpired(context.Context, int64, time.Time) error
	BeginOperation(context.Context, state.Operation) error
	OpenOperations(context.Context) ([]state.Operation, error)
	RecordVerifiedOperation(context.Context, string, state.VerifiedAlert, time.Time) ([]state.DecisionRecord, error)
	CompleteOperation(context.Context, string, time.Time) error
	SetOperationStatus(context.Context, string, state.OperationStatus, string, time.Time) error
	DecisionsForOperation(context.Context, string) ([]state.DecisionRecord, error)
}

type emptyOperatorStore struct{}

func (*emptyOperatorStore) EnsureFeeds(context.Context, []state.FeedDefinition, time.Time) ([]state.FeedRecord, error) {
	return nil, errOperatorReadOnly
}
func (*emptyOperatorStore) FeedByName(context.Context, string) (state.FeedRecord, error) {
	return state.FeedRecord{}, errOperatorReadOnly
}
func (*emptyOperatorStore) ApplyFeedSnapshot(context.Context, string, state.FeedSnapshot, int, time.Time) (state.SnapshotResult, error) {
	return state.SnapshotResult{}, errOperatorReadOnly
}
func (*emptyOperatorStore) RecordFeedNotModified(context.Context, string, string, string, time.Time) error {
	return errOperatorReadOnly
}
func (*emptyOperatorStore) RecordFeedFailure(context.Context, string, string, time.Time, time.Time) error {
	return errOperatorReadOnly
}
func (*emptyOperatorStore) ListFeeds(context.Context) ([]state.FeedRecord, error) { return nil, nil }
func (*emptyOperatorStore) ListActiveEntries(context.Context) ([]state.StoredEntry, error) {
	return nil, nil
}
func (*emptyOperatorStore) ApplyEnforcementPlan(context.Context, []network.Object, time.Time) ([]state.EnforcementRecord, error) {
	return nil, errOperatorReadOnly
}
func (*emptyOperatorStore) ListEnforcementObjects(context.Context) ([]state.EnforcementRecord, error) {
	return nil, nil
}
func (*emptyOperatorStore) ListActiveDecisions(context.Context) ([]state.DecisionRecord, error) {
	return nil, nil
}
func (*emptyOperatorStore) ListLiveDecisions(context.Context) ([]state.DecisionRecord, error) {
	return nil, nil
}
func (*emptyOperatorStore) MarkDecisionExpired(context.Context, int64, time.Time) error {
	return errOperatorReadOnly
}
func (*emptyOperatorStore) BeginOperation(context.Context, state.Operation) error {
	return errOperatorReadOnly
}
func (*emptyOperatorStore) OpenOperations(context.Context) ([]state.Operation, error) {
	return nil, nil
}
func (*emptyOperatorStore) RecordVerifiedOperation(context.Context, string, state.VerifiedAlert, time.Time) ([]state.DecisionRecord, error) {
	return nil, errOperatorReadOnly
}
func (*emptyOperatorStore) CompleteOperation(context.Context, string, time.Time) error {
	return errOperatorReadOnly
}
func (*emptyOperatorStore) SetOperationStatus(context.Context, string, state.OperationStatus, string, time.Time) error {
	return errOperatorReadOnly
}
func (*emptyOperatorStore) DecisionsForOperation(context.Context, string) ([]state.DecisionRecord, error) {
	return nil, nil
}
