package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crowdshield/migrations"
	_ "modernc.org/sqlite"
)

func checksum(sqlText string) string {
	hash := sha256.Sum256([]byte(sqlText))
	return hex.EncodeToString(hash[:])
}

func testOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		Path:           filepath.Join(t.TempDir(), "crowdshield.db"),
		BusyTimeout:    time.Second,
		IntegrityCheck: true,
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(context.Background(), testOptions(t))
	if err != nil {
		t.Fatal("unable to open test store")
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestOpenReadOnlyNeverCreatesOrMutatesDatabase(t *testing.T) {
	ctx := context.Background()
	missing := filepath.Join(t.TempDir(), "missing.db")
	options := Options{Path: missing, BusyTimeout: time.Second, IntegrityCheck: true}
	if _, err := OpenReadOnly(ctx, options); err == nil || !IsCategory(err, ErrOpen) {
		t.Fatal("read-only open accepted a missing database")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("read-only open created a missing database")
	}

	options = testOptions(t)
	writable, err := Open(ctx, options)
	if err != nil {
		t.Fatal("unable to create initialized database")
	}
	if err := writable.Close(); err != nil {
		t.Fatal("unable to close initialized database")
	}
	if err := os.Chmod(options.Path, 0o400); err != nil {
		t.Fatal("unable to set mutation canary mode")
	}
	before, err := os.ReadFile(options.Path)
	if err != nil {
		t.Fatal("unable to read database before read-only open")
	}
	readOnly, err := OpenReadOnly(ctx, options)
	if err != nil {
		t.Fatal("unable to open initialized database read-only")
	}
	if _, err := readOnly.db.ExecContext(ctx, "DELETE FROM runtime_state"); err == nil {
		t.Fatal("read-only store accepted a write")
	}
	if err := readOnly.Close(); err != nil {
		t.Fatal("unable to close read-only database")
	}
	after, err := os.ReadFile(options.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("read-only open changed database bytes")
	}
	info, err := os.Stat(options.Path)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatal("read-only open changed database permissions")
	}
}

func TestOpenAppliesSchemaAndRequiredPragmas(t *testing.T) {
	store := openTestStore(t)
	if version, err := store.SchemaVersion(context.Background()); err != nil || version != 2 {
		t.Fatal("unexpected schema version")
	}
	var foreignKeys int
	if err := store.db.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Fatal("foreign keys not enabled")
	}
	var journal string
	if err := store.db.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&journal); err != nil || journal != "wal" {
		t.Fatal("WAL mode not enabled")
	}
	if store.db.Stats().MaxOpenConnections != 1 {
		t.Fatal("SQLite connection count is not bounded")
	}
	if err := store.QuickCheck(context.Background()); err != nil {
		t.Fatal("quick_check failed on fresh database")
	}
}

func TestForeignKeyEnforcementIsLive(t *testing.T) {
	store := openTestStore(t)
	_, err := store.db.ExecContext(context.Background(), `
		INSERT INTO feed_entries(feed_id, prefix, family, prefix_bits, kind, first_seen_at, last_seen_at)
		VALUES(999, '8.8.8.0/24', 4, 24, 2, 1, 1)`)
	if err == nil {
		t.Fatal("foreign-key violation accepted")
	}
}

func TestMigrationFailureRollsBackAtomically(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "migration.db"))
	if err != nil {
		t.Fatal("unable to open migration database")
	}
	defer db.Close()
	firstSQL := "CREATE TABLE first_table(id INTEGER PRIMARY KEY);"
	first := migrations.Migration{Version: 1, Name: "001_first.sql", SQL: firstSQL, Checksum: checksum(firstSQL)}
	if err := Migrate(context.Background(), db, []migrations.Migration{first}); err != nil {
		t.Fatal("first migration failed")
	}
	secondSQL := "CREATE TABLE half_applied(id INTEGER PRIMARY KEY); INSERT INTO missing_table VALUES(1);"
	second := migrations.Migration{Version: 2, Name: "002_broken.sql", SQL: secondSQL, Checksum: checksum(secondSQL)}
	if err := Migrate(context.Background(), db, []migrations.Migration{first, second}); err == nil {
		t.Fatal("broken migration succeeded")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='half_applied'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed migration left partial schema")
	}
	var version int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != 1 {
		t.Fatal("failed migration changed recorded version")
	}
}

func TestMigrationChecksumMismatchFailsClosed(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "checksum.db"))
	if err != nil {
		t.Fatal("unable to open migration database")
	}
	defer db.Close()
	body := "CREATE TABLE stable(id INTEGER PRIMARY KEY);"
	original := migrations.Migration{Version: 1, Name: "001_stable.sql", SQL: body, Checksum: checksum(body)}
	if err := Migrate(context.Background(), db, []migrations.Migration{original}); err != nil {
		t.Fatal("initial migration failed")
	}
	changed := original
	changed.Checksum = checksum(body + " ")
	if err := Migrate(context.Background(), db, []migrations.Migration{changed}); err == nil || !IsCategory(err, ErrMigration) {
		t.Fatal("migration checksum drift accepted")
	}
}

func TestOpenRejectsCorruptDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(path, []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatal("unable to create corruption fixture")
	}
	_, err := Open(context.Background(), Options{Path: path, BusyTimeout: time.Second, IntegrityCheck: true})
	if err == nil {
		t.Fatal("corrupt database accepted")
	}
	if !IsCategory(err, ErrOpen) && !IsCategory(err, ErrIntegrity) && !IsCategory(err, ErrMigration) {
		t.Fatal("corruption returned an unbounded error class")
	}
}

func TestStateErrorDoesNotExposeDriverDetails(t *testing.T) {
	const canary = "database-path-canary-do-not-emit"
	err := stateError(ErrQuery, errors.New(canary))
	if strings.Contains(err.Error(), canary) {
		t.Fatal("state error disclosed driver details")
	}
}
