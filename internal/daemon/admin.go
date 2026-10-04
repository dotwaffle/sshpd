package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// AdminRequest selects one local account operation.
type AdminRequest struct {
	Action string `json:"action"`
	Name   string `json:"name,omitempty"`
	KeyID  string `json:"key_id,omitempty"`
}

// UserSummary exposes account and key identifiers on the private socket only.
type UserSummary struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Disabled bool     `json:"disabled"`
	Keys     []string `json:"keys"`
}

// AdminResponse contains a local result. Invitation links are sensitive.
type AdminResponse struct {
	OK         bool          `json:"ok"`
	Error      string        `json:"error,omitempty"`
	Invitation string        `json:"invitation,omitempty"`
	Users      []UserSummary `json:"users,omitempty"`
	Backup     string        `json:"backup,omitempty"`
}

// AdminHandler returns the private-socket handler. Never mount it publicly.
func (a *App) AdminHandler() http.Handler { return http.HandlerFunc(a.admin) }

func (a *App) admin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost || r.URL.Path != "/" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input AdminRequest
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil {
		http.Error(w, "invalid administration request", http.StatusBadRequest)
		return
	}
	out, err := a.adminAction(r, input)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "administration failed")
		w.WriteHeader(http.StatusBadRequest)
		out = AdminResponse{Error: "administration failed"}
	}
	if encodeErr := json.NewEncoder(w).Encode(out); encodeErr != nil {
		a.logger.ErrorContext(r.Context(), "administration response failed")
	}
}

func (a *App) adminAction(r *http.Request, input AdminRequest) (AdminResponse, error) {
	ctx := r.Context()
	out := AdminResponse{OK: true}
	if input.Action == "backup" {
		if input.Name == "" || input.Name == "." || input.Name == ".." || len(input.Name) > 80 {
			return out, errors.New("invalid backup name")
		}
		for _, c := range input.Name {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
				return out, errors.New("invalid backup name")
			}
		}
		dir := filepath.Join(a.cfg.StateDir, "backups")
		if err := privateDir(dir); err != nil {
			return out, err
		}
		path := filepath.Join(dir, input.Name+".db")
		if err := a.store.Backup(ctx, path); err != nil {
			return out, err
		}
		out.Backup = path
		a.logger.InfoContext(ctx, "admission backup complete")
		return out, nil
	}
	if input.Action == "users" {
		users, err := a.store.ListUsers(ctx)
		if err != nil {
			return out, err
		}
		for _, u := range users {
			summary := UserSummary{ID: u.ID, Name: u.Name, Disabled: u.Disabled, Keys: make([]string, 0, len(u.Credentials))}
			for _, k := range u.Credentials {
				summary.Keys = append(summary.Keys, base64.RawURLEncoding.EncodeToString(k.ID))
			}
			out.Users = append(out.Users, summary)
		}
		return out, nil
	}
	if input.Action != "user-add" && input.Action != "user-invite" && input.Action != "user-recover" && input.Action != "user-disable" && input.Action != "user-delete" && input.Action != "key-remove" {
		return out, errors.New("unknown administration action")
	}
	u, err := a.store.UserByName(ctx, input.Name)
	if input.Action == "user-add" {
		u, err = a.store.CreateUser(ctx, input.Name)
	}
	if err != nil {
		return out, err
	}
	switch input.Action {
	case "key-remove":
		keyID, decodeErr := base64.RawURLEncoding.DecodeString(input.KeyID)
		if decodeErr != nil {
			return out, decodeErr
		}
		ids, removeErr := a.store.RemoveCredential(ctx, u.ID, keyID)
		if removeErr != nil {
			return out, removeErr
		}
		for _, id := range ids {
			a.relay.RevokeLogin(id)
		}
	case "user-recover", "user-disable", "user-delete":
		action := input.Action[len("user-"):]
		if err := a.store.ChangeUser(ctx, u.ID, action); err != nil {
			return out, err
		}
		a.relay.RevokeUser(u.ID)
	case "user-add", "user-invite":
	}
	if input.Action == "user-add" || input.Action == "user-invite" || input.Action == "user-recover" {
		secret := rand.Text() + rand.Text()
		if err := a.store.Invite(ctx, u.ID, secret, time.Now().Add(time.Duration(a.cfg.InviteTTL))); err != nil {
			return out, err
		}
		out.Invitation = a.cfg.PublicOrigin + "/enroll#" + secret
	}
	a.logger.InfoContext(ctx, "account operation complete", slog.String("action", input.Action), slog.String("user_id", u.ID))
	return out, nil
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 || !owned(info) {
		return errors.New("state directory must be owned by the server UID with mode 0700")
	}
	return nil
}

type privateListener struct{ net.Listener }

// Accept rejects connections from other UIDs.
func (l privateListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if peerAllowed(conn) {
			return conn, nil
		}
		_ = conn.Close()
	}
}

// ListenAdmin opens an owner-only Unix socket with kernel peer-UID checks.
// Existing socket paths are preserved. Remove a stale socket after a crash.
func ListenAdmin(ctx context.Context, path string) (net.Listener, error) {
	if _, err := os.Lstat(path); err == nil {
		return nil, errors.New("administration socket already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0o600); err != nil {
		_ = l.Close()
		return nil, err
	}
	return privateListener{Listener: l}, nil
}
