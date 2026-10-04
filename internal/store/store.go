// Package store persists passkeys and admission grants in SQLite.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"time"
	"unicode"

	"github.com/pressly/goose/v3"
	"modernc.org/sqlite"

	"github.com/dotwaffle/sshpd/internal/store/queries"
)

//go:generate sqlc generate -f ../../sqlc.yaml

//go:embed migrations/*.sql
var migrations embed.FS

// ErrDenied includes missing, expired, revoked, and stale admission records.
var ErrDenied = errors.New("admission record unavailable")

// User is an owned snapshot. Generation fences recovery and account changes.
type User struct {
	ID, Name    string
	Disabled    bool
	Generation  int64
	Credentials []Credential
}

// Credential holds an opaque WebAuthn record and its update version.
type Credential struct {
	ID, Data []byte
	Version  int64
}

// Login identifies a stored admission without exposing its secret.
type Login struct {
	ID, UserID, Kind, ClientID string
	Expires                    time.Time
}

// Store owns one database connection. Transactions never include network waits.
type Store struct {
	db *sql.DB
	q  *queries.Queries
}

// Open installs per-connection pragmas, verifies them, and migrates before use.
// The caller supplies an absolute path in an owner-only directory.
func Open(ctx context.Context, path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("database path must be absolute")
	}
	if err := privateFile(path); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: path}
	params := url.Values{"_txlock": {"immediate"}, "_pragma": {
		"journal_mode(WAL)", "busy_timeout(5000)", "foreign_keys(ON)", "synchronous(FULL)",
	}}
	u.RawQuery = params.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, q: queries.New(db)}
	if err = s.initialize(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func privateFile(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("database must be a private regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	//nolint:gosec // The server supplies its database path in a private state directory.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create database: %w", err)
	}
	return f.Close()
}

func (s *Store) initialize(ctx context.Context) error {
	for _, setting := range []struct{ name, want string }{
		{"journal_mode", "wal"}, {"busy_timeout", "5000"}, {"foreign_keys", "1"}, {"synchronous", "2"},
	} {
		var got string
		if err := s.db.QueryRowContext(ctx, "PRAGMA "+setting.name).Scan(&got); err != nil {
			return err
		}
		if got != setting.want {
			return fmt.Errorf("database pragma %s did not take effect", setting.name)
		}
	}
	f, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectSQLite3, s.db, f)
	if err != nil {
		return fmt.Errorf("create migrations: %w", err)
	}
	if _, err = provider.Up(ctx); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	return nil
}

// Close releases the database connection.
func (s *Store) Close() error { return s.db.Close() }

// Stats exposes connection-pool waits without identity labels.
func (s *Store) Stats() sql.DBStats { return s.db.Stats() }

func (s *Store) transact(ctx context.Context, work func(*queries.Queries) error) error {
	var err error
	for attempt := range 3 {
		err = s.attempt(ctx, work)
		var busy *sqlite.Error
		if !errors.As(err, &busy) || busy.Code()&0xff != 5 || ctx.Err() != nil {
			return err
		}
		timer := time.NewTimer(time.Duration(10*(attempt+1)) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return err
}

func (s *Store) attempt(ctx context.Context, work func(*queries.Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := work(s.q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit()
}

func userSnapshot(ctx context.Context, q *queries.Queries, row queries.User) (User, error) {
	u := User{ID: row.ID, Name: row.Name, Disabled: row.Disabled != 0, Generation: row.Generation}
	keys, err := q.Credentials(ctx, row.ID)
	if err != nil {
		return User{}, err
	}
	for _, k := range keys {
		u.Credentials = append(u.Credentials, Credential{ID: k.ID, Data: k.Data, Version: k.Version})
	}
	return u, nil
}

// CreateUser creates an enabled account without passkeys.
func (s *Store) CreateUser(ctx context.Context, name string) (User, error) {
	if len(name) < 1 || len(name) > 64 {
		return User{}, errors.New("invalid user name")
	}
	for _, c := range name {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '.' && c != '-' && c != '_' && c != '@' {
			return User{}, errors.New("invalid user name")
		}
	}
	row, err := s.q.CreateUser(ctx, queries.CreateUserParams{ID: rand.Text(), Name: name})
	if err != nil {
		return User{}, err
	}
	return userSnapshot(ctx, s.q, row)
}

// UserByName returns an account and all its stored credentials.
func (s *Store) UserByName(ctx context.Context, name string) (User, error) {
	row, err := s.q.UserByName(ctx, name)
	if err != nil {
		return User{}, denied(err)
	}
	return userSnapshot(ctx, s.q, row)
}

// ListUsers returns account snapshots in name order.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.q.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	users := make([]User, 0, len(rows))
	for _, row := range rows {
		u, snapshotErr := userSnapshot(ctx, s.q, row)
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		users = append(users, u)
	}
	return users, nil
}

// Invite replaces the user's previous invitation. Only its hash is stored.
func (s *Store) Invite(ctx context.Context, userID, secret string, expires time.Time) error {
	hash := sha256.Sum256([]byte(secret))
	n, err := s.q.PutInvitation(ctx, queries.PutInvitationParams{SecretHash: hash[:], Expires: expires.UnixMilli(), ID: userID})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrDenied
	}
	return nil
}

// Invitation validates an invitation without consuming it.
func (s *Store) Invitation(ctx context.Context, hash []byte, now time.Time) (User, error) {
	row, err := s.q.Invitation(ctx, queries.InvitationParams{SecretHash: hash, Expires: now.UnixMilli()})
	if err != nil {
		return User{}, denied(err)
	}
	return userSnapshot(ctx, s.q, row)
}

func checkUser(ctx context.Context, q *queries.Queries, user User) error {
	row, err := q.UserByID(ctx, user.ID)
	if err != nil {
		return denied(err)
	}
	if row.Disabled != 0 || row.Generation != user.Generation {
		return ErrDenied
	}
	return nil
}

// Register consumes the invitation and adds a credential in one transaction.
// Failed verification belongs to the caller and must not call Register.
func (s *Store) Register(ctx context.Context, user User, invitationHash []byte, credential Credential, now time.Time) error {
	return s.transact(ctx, func(q *queries.Queries) error {
		if err := checkUser(ctx, q, user); err != nil {
			return err
		}
		if _, err := q.ConsumeInvitation(ctx, queries.ConsumeInvitationParams{SecretHash: invitationHash, Expires: now.UnixMilli(), UserID: user.ID, Generation: user.Generation}); err != nil {
			return denied(err)
		}
		return q.InsertCredential(ctx, queries.InsertCredentialParams{ID: credential.ID, UserID: user.ID, Data: credential.Data})
	})
}

// LoginInput contains a verified assertion and a new admission secret.
type LoginInput struct {
	User           User
	Credential     Credential
	Secret         string
	Expires        time.Time
	Kind, ClientID string
}

// CreateLogin updates the credential and creates a grant in one transaction.
// A stale credential version rejects concurrent assertions without counter loss.
func (s *Store) CreateLogin(ctx context.Context, input LoginInput) (Login, error) {
	if input.Kind == "" {
		input.Kind = "terminal"
	}
	if (input.Kind != "terminal" && input.Kind != "native") || (input.Kind == "native" && input.ClientID == "") {
		return Login{}, ErrDenied
	}
	login := Login{ID: rand.Text(), UserID: input.User.ID, Kind: input.Kind, ClientID: input.ClientID, Expires: input.Expires}
	hash := sha256.Sum256([]byte(input.Secret))
	err := s.transact(ctx, func(q *queries.Queries) error {
		if checkErr := checkUser(ctx, q, input.User); checkErr != nil {
			return checkErr
		}
		n, updateErr := q.UpdateCredential(ctx, queries.UpdateCredentialParams{Data: input.Credential.Data, ID: input.Credential.ID, UserID: input.User.ID, Version: input.Credential.Version})
		if updateErr != nil {
			return updateErr
		}
		if n != 1 {
			return ErrDenied
		}
		return q.InsertLogin(ctx, queries.InsertLoginParams{ID: login.ID, UserID: login.UserID, CredentialID: input.Credential.ID, SecretHash: hash[:], Expires: input.Expires.UnixMilli(), Kind: input.Kind, ClientID: input.ClientID})
	})
	return login, err
}

// Admission checks expiry and current ownership of the credential and account.
func (s *Store) Admission(ctx context.Context, secret string, now time.Time) (Login, error) {
	hash := sha256.Sum256([]byte(secret))
	row, err := s.q.Login(ctx, queries.LoginParams{SecretHash: hash[:], Expires: now.UnixMilli()})
	if err != nil {
		return Login{}, denied(err)
	}
	return Login{ID: row.ID, UserID: row.UserID, Kind: row.Kind, ClientID: row.ClientID, Expires: time.UnixMilli(row.Expires)}, nil
}

// AdmissionByID rechecks a ticket's login without storing its bearer secret.
func (s *Store) AdmissionByID(ctx context.Context, id string, now time.Time) (Login, error) {
	row, err := s.q.LoginByID(ctx, queries.LoginByIDParams{ID: id, Expires: now.UnixMilli()})
	if err != nil {
		return Login{}, denied(err)
	}
	return Login{ID: row.ID, UserID: row.UserID, Kind: row.Kind, ClientID: row.ClientID, Expires: time.UnixMilli(row.Expires)}, nil
}

// Logout deletes one login. The caller also closes its relay sessions.
func (s *Store) Logout(ctx context.Context, loginID string) error {
	_, err := s.q.DeleteLogin(ctx, loginID)
	return denied(err)
}

// RemoveCredential deletes one key and returns only its affected login IDs.
func (s *Store) RemoveCredential(ctx context.Context, userID string, credentialID []byte) ([]string, error) {
	var logins []string
	err := s.transact(ctx, func(q *queries.Queries) error {
		var lookupErr error
		logins, lookupErr = q.CredentialLogins(ctx, queries.CredentialLoginsParams{CredentialID: credentialID, UserID: userID})
		if lookupErr != nil {
			return lookupErr
		}
		n, removeErr := q.DeleteCredential(ctx, queries.DeleteCredentialParams{ID: credentialID, UserID: userID})
		if removeErr != nil {
			return removeErr
		}
		if n != 1 {
			return ErrDenied
		}
		return nil
	})
	return logins, err
}

// ChangeUser invalidates logins, invitations, and in-flight ceremonies.
// Recovery also removes keys and enables enrollment. Deletion removes the account.
func (s *Store) ChangeUser(ctx context.Context, userID, action string) error {
	if action != "disable" && action != "recover" && action != "delete" {
		return errors.New("invalid account action")
	}
	return s.transact(ctx, func(q *queries.Queries) error {
		if _, err := q.UserByID(ctx, userID); err != nil {
			return denied(err)
		}
		if err := q.RevokeUserLogins(ctx, userID); err != nil {
			return err
		}
		if err := q.DeleteInvitations(ctx, userID); err != nil {
			return err
		}
		if action == "delete" {
			return q.DeleteUser(ctx, userID)
		}
		disabled := int64(1)
		if action == "recover" {
			disabled = 0
			if err := q.DeleteCredentials(ctx, userID); err != nil {
				return err
			}
		}
		return q.SetUserState(ctx, queries.SetUserStateParams{Disabled: disabled, ID: userID})
	})
}

func denied(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDenied
	}
	return err
}

// NativeLogoutIdentity authenticates logout even after admission expiry.
// This lookup cannot admit a new connection.
func (s *Store) NativeLogoutIdentity(ctx context.Context, secret string) (string, error) {
	hash := sha256.Sum256([]byte(secret))
	id, err := s.q.NativeLogoutIdentity(ctx, hash[:])
	return id, denied(err)
}

// Prune removes expired invitations. Login hashes and IDs remain for key
// revocation after admission expiry. Admission still enforces expiry.
func (s *Store) Prune(ctx context.Context, now time.Time) error {
	return s.q.ExpireInvitations(ctx, now.UnixMilli())
}

// PruneAtStartup removes expired login records before any relay exists.
// Calling this while relay sessions run would lose their revocation identity.
func (s *Store) PruneAtStartup(ctx context.Context, now time.Time) error {
	return s.q.ExpireLogins(ctx, now.UnixMilli())
}

// Backup publishes a consistent snapshot without live logins or invitations.
// Existing files are preserved. Interrupted work leaves only a private partial.
func (s *Store) Backup(ctx context.Context, path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("backup path must be absolute")
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".backup-*.partial")
	if err != nil {
		return err
	}
	partial := temp.Name()
	defer func() { _ = os.Remove(partial) }()
	if closeErr := temp.Close(); closeErr != nil {
		return closeErr
	}
	if _, err = s.db.ExecContext(ctx, "VACUUM INTO ?", partial); err != nil {
		return fmt.Errorf("copy database snapshot: %w", err)
	}
	if sanitizeErr := sanitizeSnapshot(ctx, partial); sanitizeErr != nil {
		return sanitizeErr
	}
	// Linking publishes only a completed snapshot and cannot replace an old file.
	if linkErr := os.Link(partial, path); linkErr != nil {
		return linkErr
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func sanitizeSnapshot(ctx context.Context, path string) error {
	snapshot, err := Open(ctx, path)
	if err != nil {
		return err
	}
	err = snapshot.transact(ctx, func(q *queries.Queries) error {
		if clearErr := q.ClearLogins(ctx); clearErr != nil {
			return clearErr
		}
		return q.ClearInvitations(ctx)
	})
	return errors.Join(err, snapshot.Close())
}
