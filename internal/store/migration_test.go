package store

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

func legacyFixture(t *testing.T, path string) *sql.DB {
	t.Helper()
	if err := privateFile(path); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f, err := fs.Sub(migrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, db, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.UpTo(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("legacy-login"))
	invite := sha256.Sum256([]byte("legacy-invitation"))
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO users VALUES (?, ?, ?, ?)", []any{"fixture-user", "fixture", 0, 3}},
		{"INSERT INTO users VALUES (?, ?, ?, ?)", []any{"disabled-user", "disabled", 1, 8}},
		{"INSERT INTO credentials VALUES (?, ?, ?, ?)", []any{[]byte("fixture-key"), "fixture-user", []byte(`{"signCount":7}`), 11}},
		{"INSERT INTO logins VALUES (?, ?, ?, ?, ?)", []any{"fixture-login", "fixture-user", []byte("fixture-key"), hash[:], time.Now().Add(time.Hour).UnixMilli()}},
		{"INSERT INTO invitations VALUES (?, ?, ?, ?)", []any{"fixture-user", invite[:], time.Now().Add(time.Hour).UnixMilli(), 3}},
	} {
		if _, err = db.ExecContext(t.Context(), statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestLegacyUpgradeRestoreAndRollbackRehearsal(t *testing.T) {
	dir := t.TempDir()
	path, rollbackPath := filepath.Join(dir, "admission.db"), filepath.Join(dir, "rollback-v1.db")
	legacy := legacyFixture(t, path)
	if err := privateFile(rollbackPath); err != nil {
		t.Fatal(err)
	}
	// Make the rollback snapshot before a current Store can migrate it.
	if _, err := legacy.ExecContext(t.Context(), "VACUUM INTO ?", rollbackPath); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	rollback, err := sql.Open("sqlite", rollbackPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rollback.Close() })
	if _, err = rollback.ExecContext(t.Context(), "BEGIN IMMEDIATE; DELETE FROM logins; DELETE FROM invitations; COMMIT;"); err != nil {
		t.Fatal(err)
	}
	s, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	user, err := s.UserByName(t.Context(), "fixture")
	if err != nil || user.Generation != 3 || len(user.Credentials) != 1 || user.Credentials[0].Version != 11 || string(user.Credentials[0].Data) != `{"signCount":7}` {
		t.Fatalf("upgrade changed account or counter state: %+v %v", user, err)
	}
	disabled, err := s.UserByName(t.Context(), "disabled")
	if err != nil || !disabled.Disabled || disabled.Generation != 8 {
		t.Fatal("upgrade changed disabled account state")
	}
	login, err := s.Admission(t.Context(), "legacy-login", time.Now())
	if err != nil || login.Kind != "terminal" || login.ClientID != "" {
		t.Fatal("legacy login did not receive terminal defaults")
	}
	if _, err = s.CreateLogin(t.Context(), LoginInput{User: user, Credential: user.Credentials[0], Secret: "native-fixture", Kind: "native", ClientID: "fixture-client", Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal("upgraded schema rejected native login", err)
	}
	user, err = s.UserByName(t.Context(), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	snapshotPath := filepath.Join(dir, "snapshot-v2.db")
	if err = s.Backup(t.Context(), snapshotPath); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(t.Context(), snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restored.Close() })
	got, err := restored.UserByName(t.Context(), "fixture")
	if err != nil || !reflect.DeepEqual(user, got) {
		t.Fatal("restore changed account or credential versions")
	}
	got, err = restored.UserByName(t.Context(), "disabled")
	if err != nil || !reflect.DeepEqual(disabled, got) {
		t.Fatal("restore changed disabled account state")
	}
	invite := sha256.Sum256([]byte("legacy-invitation"))
	if _, err = restored.Invitation(t.Context(), invite[:], time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("restore revived an invitation")
	}
	for _, secret := range []string{"legacy-login", "native-fixture"} {
		if _, err = restored.Admission(t.Context(), secret, time.Now()); !errors.Is(err, ErrDenied) {
			t.Fatal("restore revived a login")
		}
	}
	for _, check := range []struct {
		sql  string
		want int
	}{
		{"SELECT max(version_id) FROM goose_db_version WHERE is_applied=1", 1},
		{"SELECT count(*) FROM pragma_table_info('logins') WHERE name IN ('kind', 'client_id')", 0},
		{"SELECT count(*) FROM logins", 0},
		{"SELECT count(*) FROM invitations", 0},
		{"SELECT version FROM credentials WHERE user_id='fixture-user'", 11},
		{"SELECT generation FROM users WHERE id='fixture-user'", 3},
	} {
		var gotValue int
		if err = rollback.QueryRowContext(t.Context(), check.sql).Scan(&gotValue); err != nil || gotValue != check.want {
			t.Fatalf("rollback check %q: %d, want %d (%v)", check.sql, gotValue, check.want, err)
		}
	}
}
