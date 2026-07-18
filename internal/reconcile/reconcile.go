package reconcile

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"crowdshield/internal/lapi"
	"crowdshield/internal/network"
	"crowdshield/internal/state"
)

type stateStore interface {
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

type lapiClient interface {
	CreateAlert(context.Context, lapi.CreateRequest) (int64, error)
	GetAlert(context.Context, int64) (lapi.Alert, error)
	ExpireDecision(context.Context, int64) error
	FindOperation(context.Context, string, string) (lapi.Alert, bool, error)
}

type Options struct {
	Store         stateStore
	LAPI          lapiClient
	MachineID     string
	Duration      time.Duration
	RefreshBefore time.Duration
	BatchSize     int
	Now           func() time.Time
	Token         func() (string, error)
}

type RunOptions struct {
	Allowlists      []netip.Prefix
	FeedOrder       map[int64]int
	DryRun          bool
	OverrideEntries bool
	Entries         []state.StoredEntry
}

type Report struct {
	Added        int
	Refreshed    int
	Removed      int
	Recovered    int
	Rejected     int
	Skipped      int
	LAPIRequests int
}

type Reconciler struct {
	store         stateStore
	lapi          lapiClient
	machineID     string
	duration      time.Duration
	refreshBefore time.Duration
	batchSize     int
	now           func() time.Time
	token         func() (string, error)
	running       atomic.Bool
}

func secureToken() (string, error) {
	var body [16]byte
	if _, err := rand.Read(body[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(body[:]), nil
}

func New(options Options) (*Reconciler, error) {
	if options.Store == nil || options.LAPI == nil || options.MachineID == "" || len(options.MachineID) > 128 ||
		strings.IndexFunc(options.MachineID, unicode.IsControl) >= 0 || options.Duration < time.Minute || options.Duration > 7*24*time.Hour ||
		options.RefreshBefore <= 0 || options.RefreshBefore >= options.Duration || options.BatchSize < 1 || options.BatchSize > 500 {
		return nil, reconcileError(ErrContract, nil)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Token == nil {
		options.Token = secureToken
	}
	return &Reconciler{
		store: options.Store, lapi: options.LAPI, machineID: options.MachineID,
		duration: options.Duration, refreshBefore: options.RefreshBefore, batchSize: options.BatchSize,
		now: options.Now, token: options.Token,
	}, nil
}

func buildObjects(entries []state.StoredEntry, allowlists []netip.Prefix, order map[int64]int) ([]network.Object, network.Summary, error) {
	for index := range allowlists {
		if !allowlists[index].IsValid() || allowlists[index] != allowlists[index].Masked() {
			return nil, network.Summary{}, reconcileError(ErrContract, nil)
		}
	}
	derivedOrder := make(map[int64]int)
	nextOrder := 0
	candidates := make([]network.Candidate, 0, len(entries))
	for _, entry := range entries {
		feedOrder, exists := order[entry.FeedID]
		if !exists {
			feedOrder, exists = derivedOrder[entry.FeedID]
			if !exists {
				feedOrder = nextOrder
				derivedOrder[entry.FeedID] = feedOrder
				nextOrder++
			}
		}
		candidates = append(candidates, network.Candidate{
			Prefix: entry.Entry.Prefix, Kind: entry.Entry.Kind, FeedID: entry.FeedID,
			FeedName: entry.FeedName, FeedOrder: feedOrder,
		})
	}
	objects, summary := network.BuildDesired(candidates, allowlists)
	return objects, summary, nil
}

func objectValue(record state.EnforcementRecord) string {
	if record.Scope == network.ScopeIP {
		return record.Prefix.Addr().String()
	}
	return record.Prefix.String()
}

func primaryFeed(record state.EnforcementRecord) (int64, string, bool) {
	if record.PrimaryFeedID == nil {
		return 0, "", false
	}
	for _, source := range record.Sources {
		if source.FeedID == *record.PrimaryFeedID {
			return source.FeedID, source.FeedName, true
		}
	}
	return 0, "", false
}

func activeByObject(decisions []state.DecisionRecord) (map[int64]state.DecisionRecord, error) {
	result := make(map[int64]state.DecisionRecord, len(decisions))
	for _, decision := range decisions {
		if _, exists := result[decision.ObjectID]; exists {
			return nil, reconcileError(ErrState, nil)
		}
		result[decision.ObjectID] = decision
	}
	return result, nil
}

func (r *Reconciler) dryRun(ctx context.Context, objects []network.Object, report Report, now time.Time) (Report, error) {
	existing, err := r.store.ListEnforcementObjects(ctx)
	if err != nil {
		return report, reconcileError(ErrState, err)
	}
	decisions, err := r.store.ListActiveDecisions(ctx)
	if err != nil {
		return report, reconcileError(ErrState, err)
	}
	active, err := activeByObject(decisions)
	if err != nil {
		return report, err
	}
	existingByPrefix := make(map[netip.Prefix]state.EnforcementRecord, len(existing))
	for _, record := range existing {
		existingByPrefix[record.Prefix] = record
	}
	desiredIDs := make(map[int64]struct{})
	for _, object := range objects {
		if !object.Desired {
			report.Skipped++
			continue
		}
		record, exists := existingByPrefix[object.Prefix]
		if !exists {
			report.Added++
			continue
		}
		desiredIDs[record.ID] = struct{}{}
		decision, exists := active[record.ID]
		feedName := object.Primary.FeedName
		if !exists {
			report.Added++
		} else if feedName == "" || decision.ExpiresAt.Sub(now) <= r.refreshBefore || decision.Scope != object.Scope || decision.Value != expectedNetworkValue(object.Prefix, object.Scope) || decision.Scenario != "crowdshield/"+feedName {
			report.Refreshed++
		} else {
			report.Skipped++
		}
	}
	for objectID := range active {
		if _, desired := desiredIDs[objectID]; !desired {
			report.Removed++
		}
	}
	return report, nil
}

func expectedNetworkValue(prefix netip.Prefix, scope network.Scope) string {
	if scope == network.ScopeIP {
		return prefix.Addr().String()
	}
	return prefix.String()
}

func operationHash(kind state.OperationKind, feedID int64, duration time.Duration, actions []plannedAction) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(kind))
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], uint64(feedID))
	_, _ = hash.Write(buffer[:])
	binary.BigEndian.PutUint64(buffer[:], uint64(duration/time.Second))
	_, _ = hash.Write(buffer[:])
	for _, action := range actions {
		binary.BigEndian.PutUint64(buffer[:], uint64(action.object.ID))
		_, _ = hash.Write(buffer[:])
		_, _ = hash.Write([]byte(action.object.Scope))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(objectValue(action.object)))
		if action.old != nil {
			binary.BigEndian.PutUint64(buffer[:], uint64(action.old.ID))
			_, _ = hash.Write(buffer[:])
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type plannedAction struct {
	object state.EnforcementRecord
	old    *state.DecisionRecord
}

func (r *Reconciler) verifiedAlert(operation state.Operation, remote lapi.Alert, records map[int64]state.EnforcementRecord, now time.Time) (state.VerifiedAlert, error) {
	if remote.ID <= 0 || remote.MachineID != r.machineID || remote.Scenario != "crowdshield/"+operation.FeedName || remote.ScenarioHash != "crowdshield:"+operation.Token || len(remote.Decisions) != len(operation.Items) {
		return state.VerifiedAlert{}, reconcileError(ErrOwnership, nil)
	}
	expected := make(map[string]int64, len(operation.Items))
	for _, item := range operation.Items {
		record, exists := records[item.ObjectID]
		if !exists {
			return state.VerifiedAlert{}, reconcileError(ErrState, nil)
		}
		key := string(record.Scope) + "\x00" + objectValue(record)
		expected[key] = record.ID
	}
	verified := state.VerifiedAlert{
		AlertID: remote.ID, MachineID: remote.MachineID, Origin: "crowdshield", Scenario: remote.Scenario,
		Decisions: make([]state.VerifiedDecision, 0, len(remote.Decisions)),
	}
	seen := make(map[int64]struct{}, len(remote.Decisions))
	for _, decision := range remote.Decisions {
		key := decision.Scope + "\x00" + decision.Value
		objectID, exists := expected[key]
		if !exists || decision.ID <= 0 || decision.Origin != "crowdshield" || decision.Type != "ban" || decision.Scenario != remote.Scenario {
			return state.VerifiedAlert{}, reconcileError(ErrOwnership, nil)
		}
		if _, duplicate := seen[objectID]; duplicate {
			return state.VerifiedAlert{}, reconcileError(ErrOwnership, nil)
		}
		seen[objectID] = struct{}{}
		expires, err := time.Parse(time.RFC3339, decision.Until)
		if err != nil || !expires.After(now) {
			return state.VerifiedAlert{}, reconcileError(ErrOwnership, err)
		}
		verified.Decisions = append(verified.Decisions, state.VerifiedDecision{
			ObjectID: objectID, DecisionID: decision.ID, Origin: decision.Origin, Scenario: decision.Scenario,
			Scope: network.Scope(decision.Scope), Value: decision.Value, ExpiresAt: expires.UTC(),
		})
	}
	return verified, nil
}

func (r *Reconciler) expireOwned(ctx context.Context, decision state.DecisionRecord, now time.Time, report *Report) error {
	remote, err := r.lapi.GetAlert(ctx, decision.AlertID)
	report.LAPIRequests++
	if err != nil {
		if lapi.IsCategory(err, lapi.ErrNotFound) {
			if stateErr := r.store.MarkDecisionExpired(ctx, decision.ID, now); stateErr != nil {
				return reconcileError(ErrState, stateErr)
			}
			return nil
		}
		return reconcileError(ErrLAPI, err)
	}
	if remote.ID != decision.AlertID || remote.MachineID != r.machineID || remote.Scenario != decision.Scenario {
		return reconcileError(ErrOwnership, nil)
	}
	var matched *lapi.Decision
	for index := range remote.Decisions {
		candidate := &remote.Decisions[index]
		if candidate.ID == decision.DecisionID {
			matched = candidate
			break
		}
	}
	if matched == nil || matched.Origin != "crowdshield" || matched.Scenario != decision.Scenario || matched.Scope != string(decision.Scope) || matched.Value != decision.Value {
		return reconcileError(ErrOwnership, nil)
	}
	if matched.Until != "" {
		if expiry, parseErr := time.Parse(time.RFC3339, matched.Until); parseErr == nil && !expiry.After(now) {
			if err := r.store.MarkDecisionExpired(ctx, decision.ID, now); err != nil {
				return reconcileError(ErrState, err)
			}
			return nil
		}
	}
	if err := r.lapi.ExpireDecision(ctx, decision.DecisionID); err != nil && !lapi.IsCategory(err, lapi.ErrNotFound) {
		report.LAPIRequests++
		return reconcileError(ErrLAPI, err)
	}
	report.LAPIRequests++
	if err := r.store.MarkDecisionExpired(ctx, decision.ID, now); err != nil {
		return reconcileError(ErrState, err)
	}
	return nil
}

func (r *Reconciler) finishVerified(ctx context.Context, operation state.Operation, report *Report, now time.Time) error {
	for _, item := range operation.Items {
		if item.OldDecisionRowID == nil {
			continue
		}
		decisions, err := r.store.ListLiveDecisions(ctx)
		if err != nil {
			return reconcileError(ErrState, err)
		}
		var old *state.DecisionRecord
		for index := range decisions {
			if decisions[index].ID == *item.OldDecisionRowID {
				candidate := decisions[index]
				old = &candidate
				break
			}
		}
		if old != nil {
			if err := r.expireOwned(ctx, *old, now, report); err != nil {
				return err
			}
		}
	}
	if err := r.store.CompleteOperation(ctx, operation.Token, now); err != nil {
		return reconcileError(ErrState, err)
	}
	return nil
}

func (r *Reconciler) createForOperation(ctx context.Context, operation state.Operation, records map[int64]state.EnforcementRecord, report *Report, now time.Time) error {
	decisions := make([]lapi.DecisionInput, 0, len(operation.Items))
	for _, item := range operation.Items {
		record, exists := records[item.ObjectID]
		if !exists || !record.Desired {
			if err := r.store.SetOperationStatus(ctx, operation.Token, state.OperationFailed, "no_longer_desired", now); err != nil {
				return reconcileError(ErrState, err)
			}
			return nil
		}
		decisions = append(decisions, lapi.DecisionInput{Scope: string(record.Scope), Value: objectValue(record)})
	}
	alertID, err := r.lapi.CreateAlert(ctx, lapi.CreateRequest{
		FeedName: operation.FeedName, OperationToken: operation.Token, Duration: operation.Duration, Decisions: decisions,
	})
	report.LAPIRequests++
	if err != nil {
		_ = r.store.SetOperationStatus(ctx, operation.Token, state.OperationAmbiguous, "lapi_create", now)
		return reconcileError(ErrLAPI, err)
	}
	remote, err := r.lapi.GetAlert(ctx, alertID)
	report.LAPIRequests++
	if err != nil {
		_ = r.store.SetOperationStatus(ctx, operation.Token, state.OperationAmbiguous, "lapi_verify", now)
		return reconcileError(ErrLAPI, err)
	}
	verified, err := r.verifiedAlert(operation, remote, records, now)
	if err != nil {
		_ = r.store.SetOperationStatus(ctx, operation.Token, state.OperationAmbiguous, "ownership", now)
		return err
	}
	if _, err := r.store.RecordVerifiedOperation(ctx, operation.Token, verified, now); err != nil {
		return reconcileError(ErrState, err)
	}
	return r.finishVerified(ctx, operation, report, now)
}

func (r *Reconciler) recover(ctx context.Context, records map[int64]state.EnforcementRecord, report *Report, now time.Time) error {
	operations, err := r.store.OpenOperations(ctx)
	if err != nil {
		return reconcileError(ErrState, err)
	}
	for _, operation := range operations {
		if operation.Status == state.OperationVerified {
			if err := r.finishVerified(ctx, operation, report, now); err != nil {
				return err
			}
			report.Recovered += len(operation.Items)
			continue
		}
		remote, found, err := r.lapi.FindOperation(ctx, operation.FeedName, operation.Token)
		report.LAPIRequests++
		if err != nil {
			return reconcileError(ErrLAPI, err)
		}
		if found {
			verified, err := r.verifiedAlert(operation, remote, records, now)
			if err != nil {
				return err
			}
			if _, err := r.store.RecordVerifiedOperation(ctx, operation.Token, verified, now); err != nil {
				return reconcileError(ErrState, err)
			}
			if err := r.finishVerified(ctx, operation, report, now); err != nil {
				return err
			}
			report.Recovered += len(operation.Items)
			continue
		}
		if err := r.createForOperation(ctx, operation, records, report, now); err != nil {
			return err
		}
		report.Recovered += len(operation.Items)
	}
	return nil
}

func (r *Reconciler) newOperation(kind state.OperationKind, feedID int64, feedName string, actions []plannedAction, now time.Time) (state.Operation, error) {
	token, err := r.token()
	if err != nil || len(token) != 32 {
		return state.Operation{}, reconcileError(ErrToken, err)
	}
	items := make([]state.OperationItem, 0, len(actions))
	for _, action := range actions {
		item := state.OperationItem{ObjectID: action.object.ID}
		if action.old != nil {
			value := action.old.ID
			item.OldDecisionRowID = &value
		}
		items = append(items, item)
	}
	return state.Operation{
		Token: token, Kind: kind, FeedID: feedID, FeedName: feedName, Duration: r.duration,
		PayloadHash: operationHash(kind, feedID, r.duration, actions), Items: items, StartedAt: now,
	}, nil
}

type groupKey struct {
	kind     state.OperationKind
	feedID   int64
	feedName string
}

func (r *Reconciler) Run(ctx context.Context, options RunOptions) (Report, error) {
	if !r.running.CompareAndSwap(false, true) {
		return Report{}, reconcileError(ErrBusy, nil)
	}
	defer r.running.Store(false)
	now := r.now().UTC()
	if now.IsZero() {
		return Report{}, reconcileError(ErrContract, nil)
	}
	if options.OverrideEntries && !options.DryRun {
		return Report{}, reconcileError(ErrContract, nil)
	}
	entries := options.Entries
	if !options.OverrideEntries {
		var err error
		entries, err = r.store.ListActiveEntries(ctx)
		if err != nil {
			return Report{}, reconcileError(ErrState, err)
		}
	}
	objects, summary, err := buildObjects(entries, options.Allowlists, options.FeedOrder)
	if err != nil {
		return Report{}, err
	}
	report := Report{Rejected: summary.RejectedSafety}
	if options.DryRun {
		return r.dryRun(ctx, objects, report, now)
	}
	records, err := r.store.ApplyEnforcementPlan(ctx, objects, now)
	if err != nil {
		return report, reconcileError(ErrState, err)
	}
	recordByID := make(map[int64]state.EnforcementRecord, len(records))
	for _, record := range records {
		recordByID[record.ID] = record
		if !record.Desired {
			report.Skipped++
		}
	}
	if err := r.recover(ctx, recordByID, &report, now); err != nil {
		return report, err
	}
	activeList, err := r.store.ListActiveDecisions(ctx)
	if err != nil {
		return report, reconcileError(ErrState, err)
	}
	active, err := activeByObject(activeList)
	if err != nil {
		return report, err
	}
	groups := make(map[groupKey][]plannedAction)
	var removals []state.DecisionRecord
	for _, record := range records {
		decision, hasDecision := active[record.ID]
		if !record.Desired {
			if hasDecision {
				removals = append(removals, decision)
			}
			continue
		}
		feedID, feedName, ok := primaryFeed(record)
		if !ok {
			return report, reconcileError(ErrState, nil)
		}
		if hasDecision && !decision.ExpiresAt.After(now) {
			if err := r.store.MarkDecisionExpired(ctx, decision.ID, now); err != nil {
				return report, reconcileError(ErrState, err)
			}
			hasDecision = false
		}
		if !hasDecision {
			key := groupKey{kind: state.OperationCreate, feedID: feedID, feedName: feedName}
			groups[key] = append(groups[key], plannedAction{object: record})
			continue
		}
		if decision.ExpiresAt.Sub(now) <= r.refreshBefore || decision.Scope != record.Scope || decision.Value != objectValue(record) || decision.Scenario != "crowdshield/"+feedName {
			old := decision
			key := groupKey{kind: state.OperationRefresh, feedID: feedID, feedName: feedName}
			groups[key] = append(groups[key], plannedAction{object: record, old: &old})
		} else {
			report.Skipped++
		}
	}
	keys := make([]groupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(left, right groupKey) int {
		if left.feedName < right.feedName {
			return -1
		}
		if left.feedName > right.feedName {
			return 1
		}
		if left.kind < right.kind {
			return -1
		}
		if left.kind > right.kind {
			return 1
		}
		return 0
	})
	var firstError error
	for _, key := range keys {
		actions := groups[key]
		for start := 0; start < len(actions); start += r.batchSize {
			end := min(start+r.batchSize, len(actions))
			batch := actions[start:end]
			operation, err := r.newOperation(key.kind, key.feedID, key.feedName, batch, now)
			if err != nil {
				if firstError == nil {
					firstError = err
				}
				continue
			}
			if err := r.store.BeginOperation(ctx, operation); err != nil {
				if firstError == nil {
					firstError = reconcileError(ErrState, err)
				}
				continue
			}
			if err := r.createForOperation(ctx, operation, recordByID, &report, now); err != nil {
				if firstError == nil {
					firstError = err
				}
				continue
			}
			if key.kind == state.OperationCreate {
				report.Added += len(batch)
			} else {
				report.Refreshed += len(batch)
			}
		}
	}
	if firstError == nil {
		for _, decision := range removals {
			if err := r.expireOwned(ctx, decision, now, &report); err != nil {
				if firstError == nil {
					firstError = err
				}
				continue
			}
			report.Removed++
		}
	}
	return report, firstError
}
