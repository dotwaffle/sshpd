package daemon

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime/debug"
	"runtime/metrics"
	"slices"
	"sync"
	"time"

	"github.com/dotwaffle/sshpd/internal/auth"
	"github.com/dotwaffle/sshpd/internal/nativeapi"
	"github.com/dotwaffle/sshpd/internal/requestmeta"
	"github.com/dotwaffle/sshpd/internal/store"
	"github.com/dotwaffle/sshpd/relay"
)

//go:embed web/*
var web embed.FS

// App owns the authenticated server and its local administration handler.
type App struct {
	stop       context.CancelFunc
	workerDone chan struct{}
	mu         sync.Mutex
	cfg        Config
	logger     *slog.Logger
	store      *store.Store
	auth       *auth.Service
	registry   *relay.Registry
	relay      *relay.Server
}

// New migrates storage and configures authentication before any listener opens.
func New(ctx context.Context, cfg Config, logger *slog.Logger) (*App, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		return nil, errors.New("server requires a logger")
	}
	if err := privateDir(cfg.StateDir); err != nil {
		return nil, err
	}
	db, err := store.Open(ctx, filepath.Join(cfg.StateDir, "admission.db"))
	if err != nil {
		return nil, err
	}
	if err = db.PruneAtStartup(ctx, time.Now()); err != nil {
		_ = db.Close()
		return nil, err
	}
	serverCtx, cancel := context.WithCancel(ctx)
	app := &App{cfg: cfg, logger: logger, store: db, stop: cancel, workerDone: make(chan struct{})}
	app.registry, err = relay.NewRegistry(cfg.targets())
	if err == nil {
		app.auth, err = auth.New(auth.Config{Origin: cfg.PublicOrigin, RPID: cfg.RPID, AllowNoUV: cfg.AllowNoUV,
			LoginTTL: time.Duration(cfg.LoginTTL), CeremonyTTL: time.Duration(cfg.CeremonyTTL), Logger: logger,
			ApprovalTTL: time.Duration(cfg.ApprovalTTL), TicketTTL: time.Duration(cfg.TicketTTL), Resolver: app.registry}, db)
	}
	if err == nil {
		limit := debug.SetMemoryLimit(-1)
		app.relay, err = relay.New(serverCtx, relay.Config{Authorizer: app.auth, Resolver: app.registry, Logger: logger,
			Origins: append(slices.Clone(cfg.TerminalOrigins), cfg.PublicOrigin), Limits: cfg.Limits.relayLimits(),
			MemoryLimit: uint64(max(0, limit)), MemoryUsage: memoryUsage, StrictAudit: cfg.StrictAudit})
	}
	if err != nil {
		cancel()
		_ = db.Close()
		return nil, err
	}
	go app.maintenance(serverCtx)
	return app, nil
}

func memoryUsage() uint64 {
	samples := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(samples)
	total, released := samples[0].Value.Uint64(), samples[1].Value.Uint64()
	return total - min(total, released)
}

// Reload atomically replaces destinations and reconciles existing sessions.
// Other configuration changes require a restart.
func (a *App) Reload(ctx context.Context, next Config) error {
	if err := next.validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.cfg.reloadCompatible(next) {
		return errors.New("reload may change only destinations and drop_removed")
	}
	if err := a.registry.Replace(next.targets()); err != nil {
		return err
	}
	if err := a.relay.ReconcileDestinations(ctx, next.DropRemoved); err != nil {
		return err
	}
	a.cfg.Destinations = next.Destinations
	a.cfg.DropRemoved = next.DropRemoved
	a.logger.InfoContext(ctx, "destinations reloaded", slog.Int("destinations", len(next.Destinations)), slog.Bool("drop_removed", next.DropRemoved))
	return nil
}

// Close terminates relay streams and releases storage.
func (a *App) Close() error {
	a.stop()
	<-a.workerDone
	return errors.Join(a.relay.Close(), a.store.Close())
}

func (a *App) maintenance(ctx context.Context) {
	defer close(a.workerDone)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.prune(ctx)
		}
	}
}

func (a *App) prune(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := a.store.Prune(ctx, time.Now()); err != nil && ctx.Err() == nil {
		a.logger.WarnContext(ctx, "authentication cleanup failed")
	}
	if err := a.auth.Prune(ctx, time.Now()); err != nil && ctx.Err() == nil {
		a.logger.WarnContext(ctx, "native authentication cleanup failed")
	}
}

// ServeHTTP exposes relay discovery, passkey ceremonies, and static login pages.
// The administration handler is available only through the private socket.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	client := forwardedClient(r, a.cfg.trustedProxies)
	r = r.WithContext(requestmeta.WithClient(r.Context(), client))
	a.serveHTTP(w, r)
}

func (a *App) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	switch r.URL.Path {
	case "/v4/connect", "/v4/reconnect":
		a.relay.ServeHTTP(w, r)
	case "/endpoint", "/cookie":
		a.discovery(w, r)
	case "/native/login/start", "/native/login/poll", "/native/ticket":
		a.auth.NativeHTTP(w, r)
	case "/auth/native/info":
		a.auth.ApprovalInfo(w, r)
	case "/native/logout":
		id, err := a.auth.NativeLogout(w, r)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, nativeapi.ErrDenied) || errors.Is(err, store.ErrDenied) {
				status = http.StatusUnauthorized
			}
			http.Error(w, "logout failed", status)
			return
		}
		a.relay.RevokeLogin(id)
		a.logger.InfoContext(r.Context(), "login revoked", slog.String("login_id", id))
		w.WriteHeader(http.StatusNoContent)
	case "/auth/logout":
		id, err := a.auth.Logout(w, r)
		if err != nil {
			http.Error(w, "logout failed", http.StatusUnauthorized)
			return
		}
		a.relay.RevokeLogin(id)
		a.logger.InfoContext(r.Context(), "login revoked", slog.String("login_id", id))
		w.WriteHeader(http.StatusNoContent)
	case "/auth/register/begin", "/auth/register/finish", "/auth/login/begin", "/auth/login/finish", "/auth/native/begin", "/auth/native/finish":
		a.auth.ServeHTTP(w, r)
	case "/", "/login", "/enroll", "/approve":
		a.static(w, r, "index.html", "text/html; charset=utf-8")
	case "/assets/auth.js":
		a.static(w, r, "auth.js", "text/javascript; charset=utf-8")
	case "/assets/style.css":
		a.static(w, r, "style.css", "text/css; charset=utf-8")
	case "/assets/close.js":
		a.static(w, r, "close.js", "text/javascript; charset=utf-8")
	default:
		http.NotFound(w, r)
	}
}

func (a *App) static(w http.ResponseWriter, r *http.Request, name, typ string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := web.ReadFile("web/" + name)
	if err != nil {
		http.Error(w, "page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", typ)
	_, _ = w.Write(data)
}

func (a *App) trustedOrigin(origin string) bool {
	return origin == a.cfg.PublicOrigin || slices.Contains(a.cfg.TerminalOrigins, origin)
}

func (a *App) discovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if !a.trustedOrigin(origin) {
			http.Error(w, "origin denied", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Vary", "Origin")
	}
	u, _ := url.Parse(a.cfg.PublicOrigin)
	if r.URL.Path == "/endpoint" {
		a.endpoint(w, u.Host)
		return
	}
	q := r.URL.Query()
	if len(q["version"]) != 1 || q.Get("version") != "2" || len(q["method"]) != 1 {
		http.Error(w, "invalid cookie protocol", http.StatusBadRequest)
		return
	}
	method := q.Get("method")
	if method != "direct" && method != "close" {
		http.Error(w, "unsupported cookie method", http.StatusBadRequest)
		return
	}
	if method == "close" && (len(q["origin"]) != 1 || !a.trustedOrigin(q.Get("origin"))) {
		http.Error(w, "origin denied", http.StatusForbidden)
		return
	}
	if _, err := a.auth.Login(r.Context(), r); err != nil {
		path := "/login"
		if method == "close" {
			path += "?close=1"
		}
		http.Redirect(w, r, path, http.StatusFound)
		return
	}
	if method == "direct" {
		a.endpoint(w, u.Host)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html><html lang="en"><meta charset="utf-8"><title>Signed in</title><script src="/assets/close.js" defer></script><p>Signed in. You can close this window.</p></html>`)
}

func (a *App) endpoint(w http.ResponseWriter, host string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, ")]}'\n")
	// host comes from the validated public origin, never from a request header.
	if err := json.NewEncoder(w).Encode(struct {
		Endpoint string `json:"endpoint"`
	}{host}); err != nil {
		a.logger.Warn("relay discovery response failed")
	}
}
