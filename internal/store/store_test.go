package store

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "admission.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func addFixtureKey(t *testing.T, s *Store, user User, secret, id string) User {
	t.Helper()
	if err := s.Invite(t.Context(), user.ID, secret, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(secret))
	if err := s.Register(t.Context(), user, hash[:], Credential{ID: []byte(id), Data: []byte("test fixture")}, time.Now()); err != nil {
		t.Fatal(err)
	}
	u, err := s.UserByName(t.Context(), user.Name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func fixtureLogin(t *testing.T, s *Store, user User, credential Credential, secret string) Login {
	t.Helper()
	login, err := s.CreateLogin(t.Context(), LoginInput{User: user, Credential: credential, Secret: secret, Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return login
}

func TestInvitationReplacementRollbackAndSingleUse(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	u = addFixtureKey(t, s, u, "first-invite", "first-key")
	for _, secret := range []string{"old-invite", "replacement"} {
		if err = s.Invite(t.Context(), u.ID, secret, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	old := sha256.Sum256([]byte("old-invite"))
	if _, err = s.Invitation(t.Context(), old[:], time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("replacement did not invalidate invitation")
	}
	hash := sha256.Sum256([]byte("replacement"))
	// Reading the invitation must not consume it.
	for range 2 {
		if _, err = s.Invitation(t.Context(), hash[:], time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.Register(t.Context(), u, hash[:], u.Credentials[0], time.Now()); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err = s.Invitation(t.Context(), hash[:], time.Now()); err != nil {
		t.Fatal("failed registration consumed invitation")
	}
	if err = s.Register(t.Context(), u, hash[:], Credential{ID: []byte("second-key"), Data: []byte("fixture")}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Invitation(t.Context(), hash[:], time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("invitation reused")
	}
	u, err = s.UserByName(t.Context(), "alice")
	if err != nil || len(u.Credentials) != 2 {
		t.Fatal("adding a key replaced prior key")
	}
}

func TestConcurrentInvitationConsumptionHasOneWinner(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Invite(t.Context(), u.ID, "invite", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("invite"))
	var winners atomic.Int32
	var workers sync.WaitGroup
	start := make(chan struct{})
	for _, id := range []string{"key-one", "key-two"} {
		workers.Go(func() {
			<-start
			registerErr := s.Register(t.Context(), u, hash[:], Credential{ID: []byte(id), Data: []byte("fixture")}, time.Now())
			if registerErr == nil {
				winners.Add(1)
			} else if !errors.Is(registerErr, ErrDenied) {
				t.Errorf("registration: %v", registerErr)
			}
		})
	}
	close(start)
	workers.Wait()
	if winners.Load() != 1 {
		t.Fatal("invitation did not have exactly one winner")
	}
}

func TestCredentialRemovalAndLogoutScope(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	u = addFixtureKey(t, s, u, "invite-one", "key-one")
	u = addFixtureKey(t, s, u, "invite-two", "key-two")
	first := fixtureLogin(t, s, u, u.Credentials[0], "first-login")
	second := fixtureLogin(t, s, u, u.Credentials[1], "second-login")
	ids, err := s.RemoveCredential(t.Context(), u.ID, u.Credentials[0].ID)
	if err != nil || len(ids) != 1 || ids[0] != first.ID {
		t.Fatalf("affected logins: %v %v", ids, err)
	}
	if _, err = s.Admission(t.Context(), "first-login", time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("removed key retained login")
	}
	if login, admissionErr := s.Admission(t.Context(), "second-login", time.Now()); admissionErr != nil || login.ID != second.ID {
		t.Fatal("other key login revoked")
	}
	if err = s.Logout(t.Context(), second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Admission(t.Context(), "second-login", time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("logout retained login")
	}
}

func TestRecoveryFencesStaleCeremoniesAndGrants(t *testing.T) {
	for _, action := range []string{"disable", "recover", "delete"} {
		t.Run(action, func(t *testing.T) {
			s := testStore(t)
			u, err := s.CreateUser(t.Context(), "alice")
			if err != nil {
				t.Fatal(err)
			}
			u = addFixtureKey(t, s, u, "invite", "key")
			fixtureLogin(t, s, u, u.Credentials[0], "login")
			if err = s.Invite(t.Context(), u.ID, "pending", time.Now().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if err = s.ChangeUser(t.Context(), u.ID, action); err != nil {
				t.Fatal(err)
			}
			if _, err = s.Admission(t.Context(), "login", time.Now()); !errors.Is(err, ErrDenied) {
				t.Fatal("account change retained login")
			}
			if _, err = s.CreateLogin(t.Context(), LoginInput{User: u, Credential: u.Credentials[0], Secret: "late", Expires: time.Now().Add(time.Hour)}); !errors.Is(err, ErrDenied) {
				t.Fatal("late assertion survived account change")
			}
			hash := sha256.Sum256([]byte("pending"))
			if err = s.Register(t.Context(), u, hash[:], Credential{ID: []byte("late-key"), Data: []byte("fixture")}, time.Now()); !errors.Is(err, ErrDenied) {
				t.Fatal("late enrollment survived account change")
			}
		})
	}
}

func TestStaleCredentialUpdateDoesNotCreateLogin(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	u = addFixtureKey(t, s, u, "invite", "key")
	fixtureLogin(t, s, u, u.Credentials[0], "first")
	if _, err = s.CreateLogin(t.Context(), LoginInput{User: u, Credential: u.Credentials[0], Secret: "stale", Expires: time.Now().Add(time.Hour)}); !errors.Is(err, ErrDenied) {
		t.Fatal("stale credential update succeeded")
	}
	if _, err = s.Admission(t.Context(), "stale", time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("failed update committed a login")
	}
}

func TestMigrationReopenAndSecretExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admission.db")
	s, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	u = addFixtureKey(t, s, u, "invite", "key")
	fixtureLogin(t, s, u, u.Credentials[0], "secret")
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err = s.Admission(t.Context(), "secret", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Admission(t.Context(), "secret", time.Now().Add(2*time.Hour)); !errors.Is(err, ErrDenied) {
		t.Fatal("expired admission succeeded")
	}
	if s.Stats().MaxOpenConnections != 1 {
		t.Fatal("database pool is not bounded")
	}
}

func TestBackupPreservesAccountsWithoutRestoringGrants(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	u = addFixtureKey(t, s, u, "invite", "key")
	fixtureLogin(t, s, u, u.Credentials[0], "login")
	if err = s.Invite(t.Context(), u.ID, "pending", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.db")
	if err = s.Backup(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { snapshot.Close() })
	restored, err := snapshot.UserByName(t.Context(), "alice")
	if err != nil || len(restored.Credentials) != 1 {
		t.Fatal("backup lost passkey account")
	}
	if _, err = snapshot.Admission(t.Context(), "login", time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("backup restored admission grant")
	}
	hash := sha256.Sum256([]byte("pending"))
	if _, err = snapshot.Invitation(t.Context(), hash[:], time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("backup restored invitation")
	}
	if _, err = s.Admission(t.Context(), "login", time.Now()); err != nil {
		t.Fatal("backup revoked current server login")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("backup is not private")
	}
	if err = s.Backup(t.Context(), path); !errors.Is(err, os.ErrExist) {
		t.Fatal("backup overwrote existing snapshot")
	}
}

func TestPruneExpiresInvitationsAndPreservesRevocation(t *testing.T) {
	s := testStore(t)
	u, err := s.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	u = addFixtureKey(t, s, u, "invite", "key")
	fixtureLogin(t, s, u, u.Credentials[0], "login")
	if err = s.Invite(t.Context(), u.ID, "pending", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err = s.Prune(t.Context(), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Admission(t.Context(), "login", time.Now().Add(2*time.Hour)); !errors.Is(err, ErrDenied) {
		t.Fatal("expired grant admitted")
	}
	hash := sha256.Sum256([]byte("pending"))
	if _, err = s.Invitation(t.Context(), hash[:], time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("expired invitation retained")
	}
	u, err = s.UserByName(t.Context(), "alice")
	if err != nil || len(u.Credentials) != 1 {
		t.Fatal("cleanup removed account or passkey")
	}
	ids, err := s.RemoveCredential(t.Context(), u.ID, u.Credentials[0].ID)
	if err != nil || len(ids) != 1 {
		t.Fatal("expired login lost key revocation scope", ids, err)
	}
}
