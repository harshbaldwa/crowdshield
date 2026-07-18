package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"sort"
	"time"

	"crowdshield/migrations"
)

const migrationTableSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at INTEGER NOT NULL
) STRICT;`

func validateMigrations(items []migrations.Migration) error {
	if len(items) == 0 {
		return stateError(ErrMigration, nil)
	}
	copyItems := append([]migrations.Migration(nil), items...)
	sort.Slice(copyItems, func(i, j int) bool { return copyItems[i].Version < copyItems[j].Version })
	for index, item := range copyItems {
		hash := sha256.Sum256([]byte(item.SQL))
		if item.Version != index+1 || item.Name == "" || item.SQL == "" || item.Checksum != hex.EncodeToString(hash[:]) {
			return stateError(ErrMigration, nil)
		}
		if item.Version != items[index].Version {
			return stateError(ErrMigration, nil)
		}
	}
	return nil
}

// Migrate verifies immutable checksums and applies all pending migrations in
// one transaction. Any failed statement rolls back the entire pending batch.
func Migrate(ctx context.Context, db *sql.DB, items []migrations.Migration) error {
	if db == nil {
		return stateError(ErrMigration, nil)
	}
	if err := validateMigrations(items); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return stateError(ErrMigration, err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, migrationTableSQL); err != nil {
		return stateError(ErrMigration, err)
	}
	rows, err := tx.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return stateError(ErrMigration, err)
	}
	applied := make(map[int]string)
	for rows.Next() {
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			rows.Close()
			return stateError(ErrMigration, err)
		}
		applied[version] = checksum
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return stateError(ErrMigration, err)
	}
	if err := rows.Close(); err != nil {
		return stateError(ErrMigration, err)
	}
	for version, checksum := range applied {
		if version < 1 || version > len(items) || items[version-1].Checksum != checksum {
			return stateError(ErrMigration, nil)
		}
	}
	for _, item := range items {
		if _, exists := applied[item.Version]; exists {
			continue
		}
		if _, err := tx.ExecContext(ctx, item.SQL); err != nil {
			return stateError(ErrMigration, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES(?, ?, ?, ?)`,
			item.Version, item.Name, item.Checksum, time.Now().UTC().Unix()); err != nil {
			return stateError(ErrMigration, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return stateError(ErrMigration, err)
	}
	return nil
}
