package state

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"crowdshield/migrations"
	_ "modernc.org/sqlite"
)

type Options struct {
	Path           string
	BusyTimeout    time.Duration
	IntegrityCheck bool
}

type Store struct {
	db *sql.DB
}

func dataSourceName(options Options) (string, error) {
	if options.Path == "" || !filepath.IsAbs(options.Path) || options.BusyTimeout <= 0 || options.BusyTimeout > time.Minute {
		return "", stateError(ErrOpen, nil)
	}
	location := &url.URL{Scheme: "file", Path: options.Path}
	query := location.Query()
	query.Set("mode", "rwc")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", options.BusyTimeout.Milliseconds()))
	query.Add("_pragma", "trusted_schema(0)")
	location.RawQuery = query.Encode()
	return location.String(), nil
}

func Open(ctx context.Context, options Options) (*Store, error) {
	dsn, err := dataSourceName(options)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, stateError(ErrOpen, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	cleanup := func(category ErrorCategory, cause error) (*Store, error) {
		_ = db.Close()
		return nil, stateError(category, cause)
	}
	if err := db.PingContext(ctx); err != nil {
		return cleanup(ErrOpen, err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode=WAL`); err != nil {
		return cleanup(ErrOpen, err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA synchronous=NORMAL`); err != nil {
		return cleanup(ErrOpen, err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA temp_store=MEMORY`); err != nil {
		return cleanup(ErrOpen, err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA secure_delete=ON`); err != nil {
		return cleanup(ErrOpen, err)
	}
	all, err := migrations.All()
	if err != nil {
		return cleanup(ErrMigration, err)
	}
	if err := Migrate(ctx, db, all); err != nil {
		_ = db.Close()
		return nil, err
	}
	store := &Store{db: db}
	if options.IntegrityCheck {
		if err := store.QuickCheck(ctx); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if err := os.Chmod(options.Path, 0o600); err != nil {
		_ = db.Close()
		return nil, stateError(ErrOpen, err)
	}
	return store, nil
}

func readOnlyDataSourceName(options Options) (string, error) {
	if options.Path == "" || !filepath.IsAbs(options.Path) || options.BusyTimeout <= 0 || options.BusyTimeout > time.Minute {
		return "", stateError(ErrOpen, nil)
	}
	info, err := os.Lstat(options.Path)
	if err != nil || !info.Mode().IsRegular() {
		return "", stateError(ErrOpen, err)
	}
	location := &url.URL{Scheme: "file", Path: options.Path}
	query := location.Query()
	query.Set("mode", "ro")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", options.BusyTimeout.Milliseconds()))
	query.Add("_pragma", "query_only(1)")
	query.Add("_pragma", "trusted_schema(0)")
	location.RawQuery = query.Encode()
	return location.String(), nil
}

func verifyReadOnlyMigrations(ctx context.Context, db *sql.DB) error {
	all, err := migrations.All()
	if err != nil {
		return stateError(ErrMigration, err)
	}
	rows, err := db.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return stateError(ErrMigration, err)
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		if index >= len(all) {
			return stateError(ErrMigration, nil)
		}
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil || version != all[index].Version || checksum != all[index].Checksum {
			return stateError(ErrMigration, err)
		}
		index++
	}
	if err := rows.Err(); err != nil || index != len(all) {
		return stateError(ErrMigration, err)
	}
	return nil
}

func OpenReadOnly(ctx context.Context, options Options) (*Store, error) {
	if ctx == nil {
		return nil, stateError(ErrOpen, nil)
	}
	dsn, err := readOnlyDataSourceName(options)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, stateError(ErrOpen, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	cleanup := func(category ErrorCategory, cause error) (*Store, error) {
		_ = db.Close()
		return nil, stateError(category, cause)
	}
	if err := db.PingContext(ctx); err != nil {
		return cleanup(ErrOpen, err)
	}
	if err := verifyReadOnlyMigrations(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	store := &Store{db: db}
	if options.IntegrityCheck {
		if err := store.QuickCheck(ctx); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	if err := s.db.Close(); err != nil {
		return stateError(ErrOpen, err)
	}
	return nil
}

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, stateError(ErrQuery, nil)
	}
	var version sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, stateError(ErrQuery, err)
	}
	if !version.Valid {
		return 0, nil
	}
	return int(version.Int64), nil
}

func (s *Store) QuickCheck(ctx context.Context) error {
	if s == nil || s.db == nil {
		return stateError(ErrIntegrity, nil)
	}
	rows, err := s.db.QueryContext(ctx, `PRAGMA quick_check`)
	if err != nil {
		return stateError(ErrIntegrity, err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		if count > 100 {
			return stateError(ErrIntegrity, nil)
		}
		var result string
		if err := rows.Scan(&result); err != nil || result != "ok" {
			return stateError(ErrIntegrity, err)
		}
	}
	if err := rows.Err(); err != nil || count != 1 {
		return stateError(ErrIntegrity, err)
	}
	return nil
}
