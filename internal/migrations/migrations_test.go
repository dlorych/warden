package migrations

import (
	"os"
	"strings"
	"testing"
)

func TestInitialMigrationIsEmbeddedAndForwardOnly(t *testing.T) {
	raw, err := Files.ReadFile("00001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	if !strings.HasPrefix(sql, "-- +goose Up") {
		t.Fatal("initial migration is not a Goose up migration")
	}
	if strings.Contains(sql, "+goose Down") {
		t.Fatal("schema migrations must be forward-only")
	}
	if strings.Contains(sql, "audit_events") {
		t.Fatal("Audit Log schema belongs to a later migration")
	}
	if CurrentVersion != 3 {
		t.Fatalf("CurrentVersion = %d, want 3", CurrentVersion)
	}
}

func TestAuditMigrationIsAppendOnlyAndInitializesOnce(t *testing.T) {
	raw, err := Files.ReadFile("00003_audit_events.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, marker := range []string{"CREATE TABLE IF NOT EXISTS audit_events", "BEFORE UPDATE OR DELETE", "BEFORE TRUNCATE", "GRANT SELECT, INSERT ON audit_events TO warden_runtime", "audit.initialized", "'success'"} {
		if !strings.Contains(sql, marker) {
			t.Fatalf("audit migration missing %q", marker)
		}
	}
	if strings.Contains(sql, "+goose Down") {
		t.Fatal("audit migration must be forward-only")
	}
	if strings.Count(sql, "'audit.initialized'") != 1 {
		t.Fatalf("expected exactly one initialization insert, count=%d", strings.Count(sql, "'audit.initialized'"))
	}
	if strings.Contains(sql, "GRANT UPDATE ON audit_events") || strings.Contains(sql, "GRANT DELETE ON audit_events") || strings.Contains(sql, "GRANT TRUNCATE ON audit_events") {
		t.Fatal("runtime received a mutation grant on audit_events")
	}
}

func TestSessionRolesMigrationInvalidatesLegacySessionsAndIsReplaySafe(t *testing.T) {
	raw, err := Files.ReadFile("00002_session_roles.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	steps := []string{
		"ALTER TABLE sessions ADD COLUMN IF NOT EXISTS roles_json jsonb;",
		"DELETE FROM sessions WHERE roles_json IS NULL;",
		"ALTER TABLE sessions ALTER COLUMN roles_json SET DEFAULT '[]'::jsonb;",
		"ALTER TABLE sessions ALTER COLUMN roles_json SET NOT NULL;",
	}
	last := -1
	for _, step := range steps {
		at := strings.Index(sql, step)
		if at < 0 {
			t.Fatalf("session roles migration missing %q", step)
		}
		if at <= last {
			t.Fatalf("session roles migration steps are out of order around %q", step)
		}
		last = at
	}
	if strings.Contains(sql, "DELETE FROM sessions;") {
		t.Fatal("session roles migration must not unconditionally delete sessions on replay")
	}
	if strings.Contains(sql, "+goose Down") {
		t.Fatal("session roles migration must be forward-only")
	}
}

func TestPostgresBootstrapRemovesInheritedRuntimeTemporaryPrivilege(t *testing.T) {
	raw, err := os.ReadFile("../../dev/postgres/bootstrap.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	if !strings.Contains(sql, "REVOKE TEMPORARY ON DATABASE warden FROM PUBLIC;") {
		t.Fatal("bootstrap must revoke PUBLIC TEMPORARY so warden_runtime has no effective temporary privilege")
	}
}
