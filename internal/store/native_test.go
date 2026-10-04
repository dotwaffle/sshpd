package store

import (
	"crypto/sha256"
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
)

func TestNativeAdmissionExpiryPreservesLogoutAndKeyScope(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	u = addFixtureKey(t, s, u, "invite", "key")
	login, err := s.CreateLogin(t.Context(), LoginInput{User: u, Credential: u.Credentials[0], Secret: "native-fixture", Kind: "native", ClientID: "installation-fixture", Expires: time.Now().Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Prune(t.Context(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Admission(t.Context(), "native-fixture", time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("expired native admission accepted", err)
	}
	if _, err = s.AdmissionByID(t.Context(), login.ID, time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("expired login admitted by ticket", err)
	}
	if id, lookupErr := s.NativeLogoutIdentity(t.Context(), "native-fixture"); lookupErr != nil || id != login.ID {
		t.Fatal("expired login lost logout identity", lookupErr)
	}
	ids, err := s.RemoveCredential(t.Context(), u.ID, u.Credentials[0].ID)
	if err != nil || len(ids) != 1 || ids[0] != login.ID {
		t.Fatal("expired login lost key revocation scope", ids, err)
	}
	if _, err := s.NativeLogoutIdentity(t.Context(), "native-fixture"); !errors.Is(err, ErrDenied) {
		t.Fatal("removed key retained logout authority", err)
	}
}

func TestNativeMigrationPreservesExistingBrowserGrant(t *testing.T) {
	s := testStore(t)
	f, err := fs.Sub(migrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, s.db, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.DownTo(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	u = addFixtureKey(t, s, u, "invite", "key")
	hash := sha256.Sum256([]byte("browser-fixture"))
	_, err = s.db.ExecContext(t.Context(), "INSERT INTO logins (id, user_id, credential_id, secret_hash, expires) VALUES (?, ?, ?, ?, ?)", "legacy-login", u.ID, u.Credentials[0].ID, hash[:], time.Now().Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	login, err := s.Admission(t.Context(), "browser-fixture", time.Now())
	if err != nil || login.ID != "legacy-login" || login.Kind != "terminal" || login.ClientID != "" {
		t.Fatal("migration changed browser admission", login, err)
	}
	if _, err = s.NativeLogoutIdentity(t.Context(), "browser-fixture"); !errors.Is(err, ErrDenied) {
		t.Fatal("browser grant gained native logout authority", err)
	}
}

func TestNativeStartupPrunesOnlyExpiredLogoutRecords(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	addFixtureKey(t, s, u, "invite", "key")
	for _, test := range []struct {
		secret string
		expiry time.Time
	}{
		{secret: "expired-native", expiry: time.Now().Add(-time.Minute)},
		{secret: "valid-native", expiry: time.Now().Add(time.Hour)},
	} {
		current, lookupErr := s.UserByName(t.Context(), "alice")
		if lookupErr != nil {
			t.Fatal(lookupErr)
		}
		if _, createErr := s.CreateLogin(t.Context(), LoginInput{User: current, Credential: current.Credentials[0], Secret: test.secret, Kind: "native", ClientID: "fixture", Expires: test.expiry}); createErr != nil {
			t.Fatal(createErr)
		}
	}
	if err = s.PruneAtStartup(t.Context(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.NativeLogoutIdentity(t.Context(), "expired-native"); !errors.Is(err, ErrDenied) {
		t.Fatal("expired logout record retained", err)
	}
	if _, err = s.Admission(t.Context(), "valid-native", time.Now()); err != nil {
		t.Fatal("startup revoked current grant", err)
	}
}
