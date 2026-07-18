package state

import (
	"context"
	"database/sql"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"

	"crowdshield/internal/network"
)

const SuppressionStale network.Suppression = "stale"

type EnforcementRecord struct {
	ID            int64
	Prefix        netip.Prefix
	Scope         network.Scope
	Desired       bool
	Suppression   network.Suppression
	PrimaryFeedID *int64
	Sources       []network.Contributor
}

func validBoundedText(value string, min, max int) bool {
	return len(value) >= min && len(value) <= max && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validateEnforcementObject(object network.Object) bool {
	prefix := object.Prefix.Masked()
	safe, _ := network.IsSafePrefix(prefix)
	if !safe || prefix != object.Prefix || len(object.Contributors) == 0 {
		return false
	}
	if object.Scope == network.ScopeIP {
		if prefix.Bits() != prefix.Addr().BitLen() {
			return false
		}
	} else if object.Scope != network.ScopeRange {
		return false
	}
	if object.Desired != (object.Suppression == network.SuppressedNone) {
		return false
	}
	primaryFound := false
	for _, source := range object.Contributors {
		if source.FeedID <= 0 || !stateFeedName.MatchString(source.FeedName) || (source.Kind != network.KindIP && source.Kind != network.KindRange) {
			return false
		}
		if source.FeedID == object.Primary.FeedID && source.Kind == object.Primary.Kind {
			primaryFound = true
		}
	}
	return primaryFound
}

func (s *Store) ApplyEnforcementPlan(ctx context.Context, objects []network.Object, now time.Time) ([]EnforcementRecord, error) {
	if s == nil || s.db == nil || now.IsZero() {
		return nil, stateError(ErrConstraint, nil)
	}
	seen := make(map[netip.Prefix]struct{}, len(objects))
	for _, object := range objects {
		if !validateEnforcementObject(object) {
			return nil, stateError(ErrConstraint, nil)
		}
		if _, exists := seen[object.Prefix]; exists {
			return nil, stateError(ErrConstraint, nil)
		}
		seen[object.Prefix] = struct{}{}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, stateError(ErrTransaction, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE enforcement_objects SET desired=0, suppression=?, primary_feed_id=NULL, updated_at=?`, string(SuppressionStale), unix(now)); err != nil {
		return nil, stateError(ErrQuery, err)
	}
	for _, object := range objects {
		family := 6
		if object.Prefix.Addr().Is4() {
			family = 4
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO enforcement_objects(prefix, family, prefix_bits, scope, desired, suppression, primary_feed_id, created_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(prefix) DO UPDATE SET
    family=excluded.family,
    prefix_bits=excluded.prefix_bits,
    scope=excluded.scope,
    desired=excluded.desired,
    suppression=excluded.suppression,
    primary_feed_id=excluded.primary_feed_id,
    updated_at=excluded.updated_at`,
			object.Prefix.String(), family, object.Prefix.Bits(), string(object.Scope), boolInt(object.Desired), string(object.Suppression), object.Primary.FeedID, unix(now), unix(now))
		if err != nil {
			return nil, stateError(ErrQuery, err)
		}
		var objectID int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM enforcement_objects WHERE prefix=?`, object.Prefix.String()).Scan(&objectID); err != nil {
			return nil, stateError(ErrQuery, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM enforcement_sources WHERE object_id=?`, objectID); err != nil {
			return nil, stateError(ErrQuery, err)
		}
		for _, source := range object.Contributors {
			if _, err := tx.ExecContext(ctx, `INSERT INTO enforcement_sources(object_id, feed_id, source_kind) VALUES(?, ?, ?)`, objectID, source.FeedID, int(source.Kind)); err != nil {
				return nil, stateError(ErrQuery, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, stateError(ErrTransaction, err)
	}
	return s.ListEnforcementObjects(ctx)
}

func (s *Store) ListEnforcementObjects(ctx context.Context) ([]EnforcementRecord, error) {
	if s == nil || s.db == nil {
		return nil, stateError(ErrConstraint, nil)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, prefix, family, prefix_bits, scope, desired, suppression, primary_feed_id
FROM enforcement_objects ORDER BY family, prefix_bits, prefix`)
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	var records []EnforcementRecord
	for rows.Next() {
		var record EnforcementRecord
		var raw, scope, suppression string
		var family, bits, desired int
		var primary sql.NullInt64
		if err := rows.Scan(&record.ID, &raw, &family, &bits, &scope, &desired, &suppression, &primary); err != nil {
			_ = rows.Close() //nolint:sqlclosecheck // explicit early close; the normal path checks Close below.
			return nil, stateError(ErrQuery, err)
		}
		prefix, err := network.NormalizePrefix(raw)
		if err != nil || prefix.Bits() != bits || (family == 4) != prefix.Addr().Is4() {
			_ = rows.Close()
			return nil, stateError(ErrIntegrity, err)
		}
		record.Prefix = prefix
		record.Scope = network.Scope(scope)
		record.Desired = desired == 1
		record.Suppression = network.Suppression(suppression)
		if primary.Valid {
			value := primary.Int64
			record.PrimaryFeedID = &value
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, stateError(ErrQuery, err)
	}
	if err := rows.Close(); err != nil {
		return nil, stateError(ErrQuery, err)
	}
	for index := range records {
		sourceRows, err := s.db.QueryContext(ctx, `
SELECT f.id, f.name, es.source_kind
FROM enforcement_sources es JOIN feeds f ON f.id=es.feed_id
WHERE es.object_id=? ORDER BY f.name, es.source_kind`, records[index].ID)
		if err != nil {
			return nil, stateError(ErrQuery, err)
		}
		for sourceRows.Next() {
			var source network.Contributor
			var kind int
			if err := sourceRows.Scan(&source.FeedID, &source.FeedName, &kind); err != nil {
				_ = sourceRows.Close() //nolint:sqlclosecheck // explicit early close; the normal path checks Close below.
				return nil, stateError(ErrQuery, err)
			}
			kindValue, kindErr := checkedNetworkKind(kind)
			if kindErr != nil {
				_ = sourceRows.Close()
				return nil, kindErr
			}
			source.Kind = kindValue
			records[index].Sources = append(records[index].Sources, source)
		}
		if err := sourceRows.Err(); err != nil {
			_ = sourceRows.Close()
			return nil, stateError(ErrQuery, err)
		}
		if err := sourceRows.Close(); err != nil {
			return nil, stateError(ErrQuery, err)
		}
	}
	return records, nil
}

type OperationKind string

type OperationStatus string

const (
	OperationCreate  OperationKind = "create"
	OperationRefresh OperationKind = "refresh"
	OperationExpire  OperationKind = "expire"
	OperationRecover OperationKind = "recover"

	OperationPending   OperationStatus = "pending"
	OperationVerified  OperationStatus = "verified"
	OperationCompleted OperationStatus = "completed"
	OperationFailed    OperationStatus = "failed"
	OperationAmbiguous OperationStatus = "ambiguous"
)

var stateOperationToken = regexp.MustCompile(`^[a-f0-9]{32}$`)

type OperationItem struct {
	ObjectID         int64
	OldDecisionRowID *int64
}

type Operation struct {
	Token       string
	Kind        OperationKind
	FeedID      int64
	FeedName    string
	Duration    time.Duration
	PayloadHash string
	Status      OperationStatus
	Items       []OperationItem
	StartedAt   time.Time
	CompletedAt *time.Time
}

func validOperation(operation Operation) bool {
	if !stateOperationToken.MatchString(operation.Token) || (operation.Kind != OperationCreate && operation.Kind != OperationRefresh && operation.Kind != OperationExpire && operation.Kind != OperationRecover) ||
		operation.FeedID <= 0 || operation.Duration < time.Second || operation.Duration > 7*24*time.Hour || !validHash(operation.PayloadHash) || len(operation.Items) == 0 || operation.StartedAt.IsZero() {
		return false
	}
	seen := make(map[int64]struct{}, len(operation.Items))
	for _, item := range operation.Items {
		if item.ObjectID <= 0 {
			return false
		}
		if _, exists := seen[item.ObjectID]; exists {
			return false
		}
		seen[item.ObjectID] = struct{}{}
		if operation.Kind == OperationCreate && item.OldDecisionRowID != nil {
			return false
		}
		if operation.Kind == OperationRefresh && item.OldDecisionRowID == nil {
			return false
		}
	}
	return true
}

func (s *Store) BeginOperation(ctx context.Context, operation Operation) error {
	if s == nil || s.db == nil || !validOperation(operation) {
		return stateError(ErrConstraint, nil)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return stateError(ErrTransaction, err)
	}
	defer func() { _ = tx.Rollback() }()
	var feedExists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM feeds WHERE id=?`, operation.FeedID).Scan(&feedExists); err != nil || feedExists != 1 {
		return stateError(ErrConstraint, err)
	}
	for _, item := range operation.Items {
		var primary sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT primary_feed_id FROM enforcement_objects WHERE id=?`, item.ObjectID).Scan(&primary); err != nil || !primary.Valid || primary.Int64 != operation.FeedID {
			return stateError(ErrConstraint, err)
		}
		if item.OldDecisionRowID != nil {
			var objectID int64
			var status string
			if err := tx.QueryRowContext(ctx, `SELECT object_id, status FROM lapi_decisions WHERE id=?`, *item.OldDecisionRowID).Scan(&objectID, &status); err != nil || objectID != item.ObjectID || status != string(DecisionActive) {
				return stateError(ErrConstraint, err)
			}
		}
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO lapi_operations(token, kind, feed_id, duration_seconds, payload_hash, status, started_at)
VALUES(?, ?, ?, ?, ?, ?, ?)`, operation.Token, string(operation.Kind), operation.FeedID, int64(operation.Duration/time.Second), operation.PayloadHash, string(OperationPending), unix(operation.StartedAt))
	if err != nil {
		return stateError(ErrQuery, err)
	}
	for _, item := range operation.Items {
		if _, err := tx.ExecContext(ctx, `INSERT INTO lapi_operation_items(operation_token, object_id, old_decision_row_id) VALUES(?, ?, ?)`, operation.Token, item.ObjectID, item.OldDecisionRowID); err != nil {
			return stateError(ErrQuery, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return stateError(ErrTransaction, err)
	}
	return nil
}

func (s *Store) OpenOperations(ctx context.Context) ([]Operation, error) {
	if s == nil || s.db == nil {
		return nil, stateError(ErrConstraint, nil)
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT o.token, o.kind, o.feed_id, f.name, o.duration_seconds, o.payload_hash, o.status, o.started_at, o.completed_at
FROM lapi_operations o JOIN feeds f ON f.id=o.feed_id
WHERE o.status IN ('pending', 'verified', 'ambiguous') ORDER BY o.started_at, o.token`)
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	var operations []Operation
	for rows.Next() {
		var operation Operation
		var durationSeconds, started int64
		var completed sql.NullInt64
		if err := rows.Scan(&operation.Token, &operation.Kind, &operation.FeedID, &operation.FeedName, &durationSeconds, &operation.PayloadHash, &operation.Status, &started, &completed); err != nil {
			_ = rows.Close() //nolint:sqlclosecheck // explicit early close; the normal path checks Close below.
			return nil, stateError(ErrQuery, err)
		}
		operation.Duration = time.Duration(durationSeconds) * time.Second
		operation.StartedAt = time.Unix(started, 0).UTC()
		if completed.Valid {
			value := time.Unix(completed.Int64, 0).UTC()
			operation.CompletedAt = &value
		}
		operations = append(operations, operation)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, stateError(ErrQuery, err)
	}
	if err := rows.Close(); err != nil {
		return nil, stateError(ErrQuery, err)
	}
	for index := range operations {
		itemRows, err := s.db.QueryContext(ctx, `SELECT object_id, old_decision_row_id FROM lapi_operation_items WHERE operation_token=? ORDER BY object_id`, operations[index].Token)
		if err != nil {
			return nil, stateError(ErrQuery, err)
		}
		for itemRows.Next() {
			var item OperationItem
			var old sql.NullInt64
			if err := itemRows.Scan(&item.ObjectID, &old); err != nil {
				_ = itemRows.Close() //nolint:sqlclosecheck // explicit early close; the normal path checks Close below.
				return nil, stateError(ErrQuery, err)
			}
			if old.Valid {
				value := old.Int64
				item.OldDecisionRowID = &value
			}
			operations[index].Items = append(operations[index].Items, item)
		}
		if err := itemRows.Err(); err != nil {
			_ = itemRows.Close() //nolint:sqlclosecheck // explicit early close; the normal path checks Close below.
			return nil, stateError(ErrQuery, err)
		}
		if err := itemRows.Close(); err != nil {
			return nil, stateError(ErrQuery, err)
		}
	}
	return operations, nil
}

type VerifiedDecision struct {
	ObjectID   int64
	DecisionID int64
	Origin     string
	Scenario   string
	Scope      network.Scope
	Value      string
	ExpiresAt  time.Time
}

type VerifiedAlert struct {
	AlertID   int64
	MachineID string
	Origin    string
	Scenario  string
	Decisions []VerifiedDecision
}

type DecisionStatus string

const (
	DecisionActive   DecisionStatus = "active"
	DecisionExpiring DecisionStatus = "expiring"
	DecisionExpired  DecisionStatus = "expired"
	DecisionOrphaned DecisionStatus = "orphaned"
)

type DecisionRecord struct {
	ID             int64
	ObjectID       int64
	AlertID        int64
	DecisionID     int64
	OperationToken string
	MachineID      string
	Origin         string
	Scenario       string
	Scope          network.Scope
	Value          string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	VerifiedAt     time.Time
	Status         DecisionStatus
	ReplacedByID   *int64
}

func expectedObjectValue(prefix netip.Prefix, scope network.Scope) string {
	if scope == network.ScopeIP {
		return prefix.Addr().String()
	}
	return prefix.String()
}

func queryOperationDecisions(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, token string) ([]DecisionRecord, error) {
	rows, err := queryer.QueryContext(ctx, `
SELECT d.id, d.object_id, a.alert_id, d.decision_id, a.operation_token, a.machine_id,
       d.origin, d.scenario, d.scope, d.value, d.created_at, d.expires_at,
       d.verified_at, d.status, d.replaced_by_id
FROM lapi_decisions d JOIN lapi_alerts a ON a.id=d.alert_row_id
WHERE a.operation_token=? ORDER BY d.object_id`, token)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var records []DecisionRecord
	for rows.Next() {
		record, err := scanDecision(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Store) RecordVerifiedOperation(ctx context.Context, token string, alert VerifiedAlert, now time.Time) ([]DecisionRecord, error) {
	if s == nil || s.db == nil || !stateOperationToken.MatchString(token) || now.IsZero() || alert.AlertID <= 0 || alert.Origin != "crowdshield" || !validBoundedText(alert.MachineID, 1, 128) {
		return nil, stateError(ErrConstraint, nil)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, stateError(ErrTransaction, err)
	}
	defer func() { _ = tx.Rollback() }()
	var kind OperationKind
	var feedName string
	var durationSeconds int64
	var status OperationStatus
	if err := tx.QueryRowContext(ctx, `
SELECT o.kind, f.name, o.duration_seconds, o.status
FROM lapi_operations o JOIN feeds f ON f.id=o.feed_id WHERE o.token=?`, token).Scan(&kind, &feedName, &durationSeconds, &status); err != nil {
		if err == sql.ErrNoRows {
			return nil, stateError(ErrNotFound, err)
		}
		return nil, stateError(ErrQuery, err)
	}
	if status == OperationVerified || status == OperationCompleted {
		records, err := queryOperationDecisions(ctx, tx, token)
		if err != nil || len(records) == 0 {
			return nil, stateError(ErrIntegrity, err)
		}
		if err := tx.Commit(); err != nil {
			return nil, stateError(ErrTransaction, err)
		}
		return records, nil
	}
	if status != OperationPending && status != OperationAmbiguous {
		return nil, stateError(ErrConstraint, nil)
	}
	expectedScenario := "crowdshield/" + feedName
	if alert.Scenario != expectedScenario || len(alert.Decisions) == 0 {
		return nil, stateError(ErrConstraint, nil)
	}
	itemRows, err := tx.QueryContext(ctx, `
SELECT i.object_id, i.old_decision_row_id, e.prefix, e.scope
FROM lapi_operation_items i JOIN enforcement_objects e ON e.id=i.object_id
WHERE i.operation_token=? ORDER BY i.object_id`, token)
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	type expectedItem struct {
		prefix netip.Prefix
		scope  network.Scope
		old    *int64
	}
	expected := make(map[int64]expectedItem)
	for itemRows.Next() {
		var objectID int64
		var old sql.NullInt64
		var raw, scope string
		if err := itemRows.Scan(&objectID, &old, &raw, &scope); err != nil {
			_ = itemRows.Close() //nolint:sqlclosecheck // explicit early close; the normal path checks Close below.
			return nil, stateError(ErrQuery, err)
		}
		prefix, err := network.NormalizePrefix(raw)
		if err != nil {
			_ = itemRows.Close() //nolint:sqlclosecheck // explicit early close; the normal path checks Close below.
			return nil, stateError(ErrIntegrity, err)
		}
		item := expectedItem{prefix: prefix, scope: network.Scope(scope)}
		if old.Valid {
			value := old.Int64
			item.old = &value
		}
		expected[objectID] = item
	}
	if err := itemRows.Err(); err != nil {
		_ = itemRows.Close()
		return nil, stateError(ErrQuery, err)
	}
	if err := itemRows.Close(); err != nil {
		return nil, stateError(ErrQuery, err)
	}
	if len(expected) != len(alert.Decisions) {
		return nil, stateError(ErrConstraint, nil)
	}
	seenObjects := make(map[int64]struct{}, len(alert.Decisions))
	seenDecisions := make(map[int64]struct{}, len(alert.Decisions))
	for _, decision := range alert.Decisions {
		item, exists := expected[decision.ObjectID]
		if !exists || decision.DecisionID <= 0 || decision.Origin != "crowdshield" || decision.Scenario != expectedScenario || decision.Scope != item.scope || decision.Value != expectedObjectValue(item.prefix, item.scope) ||
			!decision.ExpiresAt.After(now) || decision.ExpiresAt.After(now.Add(time.Duration(durationSeconds)*time.Second+10*time.Minute)) {
			return nil, stateError(ErrConstraint, nil)
		}
		if _, duplicate := seenObjects[decision.ObjectID]; duplicate {
			return nil, stateError(ErrConstraint, nil)
		}
		if _, duplicate := seenDecisions[decision.DecisionID]; duplicate {
			return nil, stateError(ErrConstraint, nil)
		}
		seenObjects[decision.ObjectID] = struct{}{}
		seenDecisions[decision.DecisionID] = struct{}{}
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO lapi_alerts(alert_id, operation_token, machine_id, origin, scenario, verified_at, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?)`, alert.AlertID, token, alert.MachineID, alert.Origin, alert.Scenario, unix(now), unix(now))
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	alertRowID, err := result.LastInsertId()
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	newRows := make(map[int64]int64, len(alert.Decisions))
	for _, decision := range alert.Decisions {
		result, err := tx.ExecContext(ctx, `
INSERT INTO lapi_decisions(object_id, alert_row_id, decision_id, origin, scenario, scope, value, created_at, expires_at, verified_at, status)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, decision.ObjectID, alertRowID, decision.DecisionID, decision.Origin, decision.Scenario, string(decision.Scope), decision.Value, unix(now), unix(decision.ExpiresAt), unix(now), string(DecisionActive))
		if err != nil {
			return nil, stateError(ErrQuery, err)
		}
		rowID, err := result.LastInsertId()
		if err != nil {
			return nil, stateError(ErrQuery, err)
		}
		newRows[decision.ObjectID] = rowID
	}
	for objectID, item := range expected {
		if item.old == nil {
			continue
		}
		result, err := tx.ExecContext(ctx, `UPDATE lapi_decisions SET status=?, replaced_by_id=? WHERE id=? AND object_id=? AND status=?`, string(DecisionExpiring), newRows[objectID], *item.old, objectID, string(DecisionActive))
		if err != nil {
			return nil, stateError(ErrQuery, err)
		}
		changed, _ := result.RowsAffected()
		if changed != 1 {
			return nil, stateError(ErrConstraint, nil)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE lapi_operations SET status=? WHERE token=?`, string(OperationVerified), token); err != nil {
		return nil, stateError(ErrQuery, err)
	}
	records, err := queryOperationDecisions(ctx, tx, token)
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, stateError(ErrTransaction, err)
	}
	return records, nil
}

func (s *Store) CompleteOperation(ctx context.Context, token string, now time.Time) error {
	if s == nil || s.db == nil || !stateOperationToken.MatchString(token) || now.IsZero() {
		return stateError(ErrConstraint, nil)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE lapi_operations SET status=?, completed_at=? WHERE token=? AND status IN ('verified', 'completed')`, string(OperationCompleted), unix(now), token)
	if err != nil {
		return stateError(ErrQuery, err)
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return stateError(ErrConstraint, nil)
	}
	return nil
}

func (s *Store) SetOperationStatus(ctx context.Context, token string, status OperationStatus, category string, now time.Time) error {
	if s == nil || s.db == nil || !stateOperationToken.MatchString(token) || now.IsZero() ||
		(status != OperationAmbiguous && status != OperationFailed) || (category != "" && !stateCategory.MatchString(category)) {
		return stateError(ErrConstraint, nil)
	}
	var completed any
	if status == OperationFailed {
		completed = unix(now)
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE lapi_operations SET status=?, completed_at=?, error_category=?
WHERE token=? AND status IN ('pending', 'ambiguous')`, string(status), completed, category, token)
	if err != nil {
		return stateError(ErrQuery, err)
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return stateError(ErrConstraint, nil)
	}
	return nil
}

func (s *Store) DecisionsForOperation(ctx context.Context, token string) ([]DecisionRecord, error) {
	if s == nil || s.db == nil || !stateOperationToken.MatchString(token) {
		return nil, stateError(ErrConstraint, nil)
	}
	records, err := queryOperationDecisions(ctx, s.db, token)
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	return records, nil
}

func scanDecision(row scanner) (DecisionRecord, error) {
	var record DecisionRecord
	var scope, status string
	var created, expires, verified int64
	var replaced sql.NullInt64
	if err := row.Scan(&record.ID, &record.ObjectID, &record.AlertID, &record.DecisionID, &record.OperationToken, &record.MachineID,
		&record.Origin, &record.Scenario, &scope, &record.Value, &created, &expires, &verified, &status, &replaced); err != nil {
		return DecisionRecord{}, err
	}
	record.Scope = network.Scope(scope)
	record.Status = DecisionStatus(status)
	record.CreatedAt = time.Unix(created, 0).UTC()
	record.ExpiresAt = time.Unix(expires, 0).UTC()
	record.VerifiedAt = time.Unix(verified, 0).UTC()
	if replaced.Valid {
		value := replaced.Int64
		record.ReplacedByID = &value
	}
	return record, nil
}

const decisionSelect = `
SELECT d.id, d.object_id, a.alert_id, d.decision_id, a.operation_token, a.machine_id,
       d.origin, d.scenario, d.scope, d.value, d.created_at, d.expires_at,
       d.verified_at, d.status, d.replaced_by_id
FROM lapi_decisions d JOIN lapi_alerts a ON a.id=d.alert_row_id`

func (s *Store) ListActiveDecisions(ctx context.Context) ([]DecisionRecord, error) {
	if s == nil || s.db == nil {
		return nil, stateError(ErrConstraint, nil)
	}
	rows, err := s.db.QueryContext(ctx, decisionSelect+` WHERE d.status=? ORDER BY d.object_id, d.id`, string(DecisionActive))
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	defer func() { _ = rows.Close() }()
	var records []DecisionRecord
	for rows.Next() {
		record, err := scanDecision(rows)
		if err != nil {
			return nil, stateError(ErrQuery, err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, stateError(ErrQuery, err)
	}
	return records, nil
}

func (s *Store) ListLiveDecisions(ctx context.Context) ([]DecisionRecord, error) {
	if s == nil || s.db == nil {
		return nil, stateError(ErrConstraint, nil)
	}
	rows, err := s.db.QueryContext(ctx, decisionSelect+` WHERE d.status IN ('active', 'expiring') ORDER BY d.object_id, d.id`)
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	defer func() { _ = rows.Close() }()
	var records []DecisionRecord
	for rows.Next() {
		record, err := scanDecision(rows)
		if err != nil {
			return nil, stateError(ErrQuery, err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, stateError(ErrQuery, err)
	}
	return records, nil
}

func (s *Store) DecisionByRowID(ctx context.Context, rowID int64) (DecisionRecord, error) {
	if s == nil || s.db == nil || rowID <= 0 {
		return DecisionRecord{}, stateError(ErrConstraint, nil)
	}
	record, err := scanDecision(s.db.QueryRowContext(ctx, decisionSelect+` WHERE d.id=?`, rowID))
	if err != nil {
		if err == sql.ErrNoRows {
			return DecisionRecord{}, stateError(ErrNotFound, err)
		}
		return DecisionRecord{}, stateError(ErrQuery, err)
	}
	return record, nil
}

func (s *Store) MarkDecisionExpired(ctx context.Context, rowID int64, now time.Time) error {
	if s == nil || s.db == nil || rowID <= 0 || now.IsZero() {
		return stateError(ErrConstraint, nil)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE lapi_decisions SET status=?, verified_at=? WHERE id=? AND status IN ('active', 'expiring')`, string(DecisionExpired), unix(now), rowID)
	if err != nil {
		return stateError(ErrQuery, err)
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return stateError(ErrConstraint, nil)
	}
	return nil
}
