package migrations

import (
	"strings"
	"testing"
)

func TestEmbeddedMigrationsAreSequentialAndChecksummed(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal("embedded migrations invalid")
	}
	if len(all) != 2 || all[0].Version != 1 || all[1].Version != 2 || len(all[0].Checksum) != 64 || len(all[1].Checksum) != 64 {
		t.Fatal("unexpected migration sequence")
	}
	for _, table := range []string{"feeds", "feed_entries", "enforcement_objects", "lapi_decisions", "lapi_operations", "lapi_operation_items", "sync_runs", "notification_state"} {
		if !strings.Contains(all[0].SQL, "CREATE TABLE "+table) {
			t.Fatal("required state table missing")
		}
	}
	if !strings.Contains(all[1].SQL, "CREATE TABLE notification_delivery_state") {
		t.Fatal("bounded notification delivery state table missing")
	}
	for _, forbidden := range []string{"password TEXT", "credential TEXT", "credentials_file", "api_key", "secret TEXT"} {
		for _, migration := range all {
			if strings.Contains(strings.ToLower(migration.SQL), forbidden) {
				t.Fatal("secret-shaped storage column found")
			}
		}
	}
}
