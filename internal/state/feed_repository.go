package state

import (
	"context"
	"database/sql"
	"encoding/hex"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"crowdshield/internal/feed"
	"crowdshield/internal/network"
)

var (
	stateFeedName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	stateCategory = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

type FeedDefinition struct {
	Name           string
	URLHash        string
	DefinitionHash string
	Enabled        bool
}

type FeedRecord struct {
	ID                  int64
	Name                string
	URLHash             string
	DefinitionHash      string
	Enabled             bool
	ETag                string
	LastModified        string
	LastAttempt         *time.Time
	LastSuccess         *time.Time
	LastGoodVersion     string
	AcceptedEntries     int
	RejectedEntries     int
	ConsecutiveFailures int
	NextAttempt         *time.Time
	LastErrorCategory   string
}

type FeedSnapshot struct {
	Version      string
	ETag         string
	LastModified string
	Entries      []feed.Entry
	Rejected     int
}

type SnapshotResult struct {
	Added       int
	Reactivated int
	Missing     int
	Deactivated int
}

type StoredEntry struct {
	FeedID      int64
	FeedName    string
	Entry       feed.Entry
	FirstSeen   time.Time
	LastSeen    time.Time
	MissingRuns int
	Active      bool
}

type stateEntryKey struct {
	prefix netip.Prefix
	kind   network.Kind
}

func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validFeedDefinition(definition FeedDefinition) bool {
	return len(definition.Name) <= 64 && stateFeedName.MatchString(definition.Name) && validHash(definition.URLHash) && validHash(definition.DefinitionHash)
}

func unix(value time.Time) int64 { return value.UTC().Unix() }

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

type scanner interface {
	Scan(...any) error
}

func scanFeed(row scanner) (FeedRecord, error) {
	var record FeedRecord
	var enabled int
	var lastAttempt, lastSuccess, nextAttempt sql.NullInt64
	err := row.Scan(
		&record.ID, &record.Name, &record.URLHash, &record.DefinitionHash, &enabled,
		&record.ETag, &record.LastModified, &lastAttempt, &lastSuccess,
		&record.LastGoodVersion, &record.AcceptedEntries, &record.RejectedEntries,
		&record.ConsecutiveFailures, &nextAttempt, &record.LastErrorCategory,
	)
	if err != nil {
		return FeedRecord{}, err
	}
	record.Enabled = enabled == 1
	if lastAttempt.Valid {
		value := time.Unix(lastAttempt.Int64, 0).UTC()
		record.LastAttempt = &value
	}
	if lastSuccess.Valid {
		value := time.Unix(lastSuccess.Int64, 0).UTC()
		record.LastSuccess = &value
	}
	if nextAttempt.Valid {
		value := time.Unix(nextAttempt.Int64, 0).UTC()
		record.NextAttempt = &value
	}
	return record, nil
}

const feedSelect = `
SELECT id, name, url_hash, definition_hash, enabled, etag, last_modified,
       last_attempt_at, last_success_at, last_good_version, accepted_entries,
       rejected_entries, consecutive_failures, next_attempt_at, last_error_category
FROM feeds`

func (s *Store) EnsureFeeds(ctx context.Context, definitions []FeedDefinition, now time.Time) ([]FeedRecord, error) {
	if s == nil || s.db == nil || len(definitions) == 0 || now.IsZero() {
		return nil, stateError(ErrConstraint, nil)
	}
	seen := make(map[string]struct{}, len(definitions))
	for _, definition := range definitions {
		if !validFeedDefinition(definition) {
			return nil, stateError(ErrConstraint, nil)
		}
		if _, exists := seen[definition.Name]; exists {
			return nil, stateError(ErrConstraint, nil)
		}
		seen[definition.Name] = struct{}{}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, stateError(ErrTransaction, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE feeds SET enabled=0 WHERE enabled<>0`); err != nil {
		return nil, stateError(ErrQuery, err)
	}
	for _, definition := range definitions {
		_, err := tx.ExecContext(ctx, `
INSERT INTO feeds(name, url_hash, definition_hash, enabled, created_at, updated_at)
VALUES(?, ?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET
    url_hash=excluded.url_hash,
    definition_hash=excluded.definition_hash,
    enabled=excluded.enabled,
    updated_at=excluded.updated_at`,
			definition.Name, definition.URLHash, definition.DefinitionHash, boolInt(definition.Enabled), unix(now), unix(now))
		if err != nil {
			return nil, stateError(ErrQuery, err)
		}
	}
	records := make([]FeedRecord, 0, len(definitions))
	for _, definition := range definitions {
		record, err := scanFeed(tx.QueryRowContext(ctx, feedSelect+` WHERE name=?`, definition.Name))
		if err != nil {
			return nil, stateError(ErrQuery, err)
		}
		records = append(records, record)
	}
	if err := tx.Commit(); err != nil {
		return nil, stateError(ErrTransaction, err)
	}
	return records, nil
}

func (s *Store) FeedByName(ctx context.Context, name string) (FeedRecord, error) {
	if s == nil || s.db == nil || !stateFeedName.MatchString(name) {
		return FeedRecord{}, stateError(ErrConstraint, nil)
	}
	record, err := scanFeed(s.db.QueryRowContext(ctx, feedSelect+` WHERE name=?`, name))
	if err != nil {
		if err == sql.ErrNoRows {
			return FeedRecord{}, stateError(ErrNotFound, err)
		}
		return FeedRecord{}, stateError(ErrQuery, err)
	}
	return record, nil
}

func (s *Store) ListFeeds(ctx context.Context) ([]FeedRecord, error) {
	if s == nil || s.db == nil {
		return nil, stateError(ErrConstraint, nil)
	}
	rows, err := s.db.QueryContext(ctx, feedSelect+` ORDER BY id`)
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	defer func() { _ = rows.Close() }()
	records := make([]FeedRecord, 0)
	for rows.Next() {
		record, err := scanFeed(rows)
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

type existingEntry struct {
	active      bool
	missingRuns int
}

func validValidator(value string, max int) bool {
	return len(value) <= max && !strings.ContainsAny(value, "\r\n\x00")
}

func validateSnapshot(snapshot FeedSnapshot, grace int) error {
	if !validHash(snapshot.Version) || grace < 1 || grace > 100 || snapshot.Rejected < 0 || !validValidator(snapshot.ETag, 256) || !validValidator(snapshot.LastModified, 128) {
		return stateError(ErrConstraint, nil)
	}
	seen := make(map[stateEntryKey]struct{}, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		prefix := entry.Prefix.Masked()
		safe, _ := network.IsSafePrefix(prefix)
		if !safe || network.ValidateKind(prefix, entry.Kind) != nil {
			return stateError(ErrConstraint, nil)
		}
		key := stateEntryKey{prefix: prefix, kind: entry.Kind}
		if _, exists := seen[key]; exists {
			return stateError(ErrConstraint, nil)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (s *Store) ApplyFeedSnapshot(ctx context.Context, name string, snapshot FeedSnapshot, grace int, now time.Time) (SnapshotResult, error) {
	if s == nil || s.db == nil || !stateFeedName.MatchString(name) || now.IsZero() {
		return SnapshotResult{}, stateError(ErrConstraint, nil)
	}
	if err := validateSnapshot(snapshot, grace); err != nil {
		return SnapshotResult{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SnapshotResult{}, stateError(ErrTransaction, err)
	}
	defer func() { _ = tx.Rollback() }()
	var feedID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM feeds WHERE name=?`, name).Scan(&feedID); err != nil {
		if err == sql.ErrNoRows {
			return SnapshotResult{}, stateError(ErrNotFound, err)
		}
		return SnapshotResult{}, stateError(ErrQuery, err)
	}

	existing := make(map[stateEntryKey]existingEntry)
	rows, err := tx.QueryContext(ctx, `SELECT prefix, kind, active, missing_runs FROM feed_entries WHERE feed_id=?`, feedID)
	if err != nil {
		return SnapshotResult{}, stateError(ErrQuery, err)
	}
	for rows.Next() {
		var raw string
		var kindValue, active, missing int
		if err := rows.Scan(&raw, &kindValue, &active, &missing); err != nil {
			_ = rows.Close() //nolint:sqlclosecheck // explicit early close; the normal path checks Close below.
			return SnapshotResult{}, stateError(ErrQuery, err)
		}
		prefix, err := network.NormalizePrefix(raw)
		if err != nil {
			_ = rows.Close() //nolint:sqlclosecheck // explicit early close; the normal path checks Close below.
			return SnapshotResult{}, stateError(ErrIntegrity, err)
		}
		kind, err := checkedNetworkKind(kindValue)
		if err != nil {
			_ = rows.Close() //nolint:sqlclosecheck // explicit early close; the normal path checks Close below.
			return SnapshotResult{}, err
		}
		existing[stateEntryKey{prefix: prefix, kind: kind}] = existingEntry{active: active == 1, missingRuns: missing}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return SnapshotResult{}, stateError(ErrQuery, err)
	}
	if err := rows.Close(); err != nil {
		return SnapshotResult{}, stateError(ErrQuery, err)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE feed_entries SET missing_runs=missing_runs+1 WHERE feed_id=? AND active=1`, feedID); err != nil {
		return SnapshotResult{}, stateError(ErrQuery, err)
	}
	present := make(map[stateEntryKey]struct{}, len(snapshot.Entries))
	result := SnapshotResult{}
	for _, entry := range snapshot.Entries {
		prefix := entry.Prefix.Masked()
		key := stateEntryKey{prefix: prefix, kind: entry.Kind}
		present[key] = struct{}{}
		previous, exists := existing[key]
		if !exists {
			result.Added++
		} else if !previous.active {
			result.Reactivated++
		}
		family := 6
		if prefix.Addr().Is4() {
			family = 4
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO feed_entries(feed_id, prefix, family, prefix_bits, kind, first_seen_at, last_seen_at, missing_runs, active)
VALUES(?, ?, ?, ?, ?, ?, ?, 0, 1)
ON CONFLICT(feed_id, prefix, kind) DO UPDATE SET
    family=excluded.family,
    prefix_bits=excluded.prefix_bits,
    last_seen_at=excluded.last_seen_at,
    missing_runs=0,
    active=1`,
			feedID, prefix.String(), family, prefix.Bits(), int(entry.Kind), unix(now), unix(now))
		if err != nil {
			return SnapshotResult{}, stateError(ErrQuery, err)
		}
	}
	for key, previous := range existing {
		if _, exists := present[key]; !exists && previous.active {
			result.Missing++
		}
	}
	change, err := tx.ExecContext(ctx, `UPDATE feed_entries SET active=0 WHERE feed_id=? AND active=1 AND missing_runs>=?`, feedID, grace)
	if err != nil {
		return SnapshotResult{}, stateError(ErrQuery, err)
	}
	deactivated, err := change.RowsAffected()
	if err != nil {
		return SnapshotResult{}, stateError(ErrQuery, err)
	}
	result.Deactivated = int(deactivated)
	_, err = tx.ExecContext(ctx, `
UPDATE feeds SET
    etag=?, last_modified=?, last_attempt_at=?, last_success_at=?,
    last_good_version=?, accepted_entries=?, rejected_entries=?,
    consecutive_failures=0, next_attempt_at=NULL, last_error_category='', updated_at=?
WHERE id=?`,
		snapshot.ETag, snapshot.LastModified, unix(now), unix(now), snapshot.Version,
		len(snapshot.Entries), snapshot.Rejected, unix(now), feedID)
	if err != nil {
		return SnapshotResult{}, stateError(ErrQuery, err)
	}
	if err := tx.Commit(); err != nil {
		return SnapshotResult{}, stateError(ErrTransaction, err)
	}
	return result, nil
}

func (s *Store) RecordFeedFailure(ctx context.Context, name, category string, now, nextAttempt time.Time) error {
	if s == nil || s.db == nil || !stateFeedName.MatchString(name) || !stateCategory.MatchString(category) || now.IsZero() || nextAttempt.Before(now) {
		return stateError(ErrConstraint, nil)
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE feeds SET
    last_attempt_at=?, consecutive_failures=consecutive_failures+1,
    next_attempt_at=?, last_error_category=?, updated_at=?
WHERE name=?`, unix(now), unix(nextAttempt), category, unix(now), name)
	if err != nil {
		return stateError(ErrQuery, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return stateError(ErrQuery, err)
	}
	if rows != 1 {
		return stateError(ErrNotFound, nil)
	}
	return nil
}

func (s *Store) RecordFeedNotModified(ctx context.Context, name, etag, lastModified string, now time.Time) error {
	if s == nil || s.db == nil || !stateFeedName.MatchString(name) || now.IsZero() || !validValidator(etag, 256) || !validValidator(lastModified, 128) {
		return stateError(ErrConstraint, nil)
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE feeds SET
    etag=CASE WHEN ?='' THEN etag ELSE ? END,
    last_modified=CASE WHEN ?='' THEN last_modified ELSE ? END,
    last_attempt_at=?, last_success_at=?, consecutive_failures=0,
    next_attempt_at=NULL, last_error_category='', updated_at=?
WHERE name=? AND last_good_version<>''`,
		etag, etag, lastModified, lastModified, unix(now), unix(now), unix(now), name)
	if err != nil {
		return stateError(ErrQuery, err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return stateError(ErrQuery, err)
	}
	if changed != 1 {
		return stateError(ErrConstraint, nil)
	}
	return nil
}

func scanStoredEntry(row scanner) (StoredEntry, error) {
	var result StoredEntry
	var raw string
	var family, bits, kindValue, active int
	var firstSeen, lastSeen int64
	if err := row.Scan(&result.FeedID, &result.FeedName, &raw, &family, &bits, &kindValue, &firstSeen, &lastSeen, &result.MissingRuns, &active); err != nil {
		return StoredEntry{}, err
	}
	prefix, err := network.NormalizePrefix(raw)
	if err != nil || prefix.Bits() != bits || (family == 4) != prefix.Addr().Is4() {
		return StoredEntry{}, stateError(ErrIntegrity, err)
	}
	kind, err := checkedNetworkKind(kindValue)
	if err != nil || network.ValidateKind(prefix, kind) != nil {
		return StoredEntry{}, stateError(ErrIntegrity, err)
	}
	result.Entry = feed.Entry{Prefix: prefix, Kind: kind}
	result.FirstSeen = time.Unix(firstSeen, 0).UTC()
	result.LastSeen = time.Unix(lastSeen, 0).UTC()
	result.Active = active == 1
	return result, nil
}

const entrySelect = `
SELECT f.id, f.name, e.prefix, e.family, e.prefix_bits, e.kind,
       e.first_seen_at, e.last_seen_at, e.missing_runs, e.active
FROM feed_entries e JOIN feeds f ON f.id=e.feed_id`

func queryEntries(ctx context.Context, db *sql.DB, query string, args ...any) ([]StoredEntry, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, stateError(ErrQuery, err)
	}
	defer func() { _ = rows.Close() }()
	var entries []StoredEntry
	for rows.Next() {
		entry, err := scanStoredEntry(rows)
		if err != nil {
			return nil, stateError(ErrIntegrity, err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, stateError(ErrQuery, err)
	}
	return entries, nil
}

func (s *Store) ListFeedEntries(ctx context.Context, name string, includeInactive bool) ([]StoredEntry, error) {
	if s == nil || s.db == nil || !stateFeedName.MatchString(name) {
		return nil, stateError(ErrConstraint, nil)
	}
	query := entrySelect + ` WHERE f.name=?`
	if !includeInactive {
		query += ` AND e.active=1`
	}
	query += ` ORDER BY e.family, e.prefix, e.kind`
	return queryEntries(ctx, s.db, query, name)
}

func (s *Store) ListActiveEntries(ctx context.Context) ([]StoredEntry, error) {
	if s == nil || s.db == nil {
		return nil, stateError(ErrConstraint, nil)
	}
	return queryEntries(ctx, s.db, entrySelect+` WHERE e.active=1 AND f.enabled=1 ORDER BY f.name, e.family, e.prefix, e.kind`)
}
