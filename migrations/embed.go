// Package migrations exposes the ordered, embedded Crowdshield SQLite schema.
package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed *.sql
var files embed.FS

type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

func All() ([]Migration, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations")
	}
	migrations := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		parts := strings.SplitN(entry.Name(), "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid migration name")
		}
		version, err := strconv.Atoi(parts[0])
		if err != nil || version < 1 {
			return nil, fmt.Errorf("invalid migration version")
		}
		body, err := files.ReadFile(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read embedded migration")
		}
		hash := sha256.Sum256(body)
		migrations = append(migrations, Migration{
			Version: version, Name: entry.Name(), SQL: string(body), Checksum: hex.EncodeToString(hash[:]),
		})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	for index, migration := range migrations {
		if migration.Version != index+1 || migration.SQL == "" || migration.Checksum == "" {
			return nil, fmt.Errorf("non-sequential embedded migrations")
		}
	}
	if len(migrations) == 0 {
		return nil, fmt.Errorf("no embedded migrations")
	}
	return migrations, nil
}
