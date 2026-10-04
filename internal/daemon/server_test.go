package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dotwaffle/sshpd/client"
	"github.com/dotwaffle/sshpd/internal/store"
	"github.com/dotwaffle/sshpd/relay"
)

type appHarness struct {
	app   *App
	http  *httptest.Server
	dials atomic.Int32
}

func testApp(t *testing.T) *appHarness {
	t.Helper()
	h := &appHarness{}
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var peers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, acceptErr := l.Accept()
			if acceptErr != nil {
				return
			}
			h.dials.Add(1)
			peers.Go(func() { defer conn.Close(); _, _ = io.Copy(conn, conn) })
		}
	}()
	t.Cleanup(func() { l.Close(); <-acceptDone; peers.Wait() })
	host, portText, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: filepath.Join(t.TempDir(), "state"), PublicOrigin: "https://relay.example", RPID: "relay.example",
		Destinations: []destination{{ID: "home", Aliases: []endpoint{{Host: "home"}}, Backend: endpoint{Host: host, Port: uint16(port)}}}}
	h.app, err = New(t.Context(), cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.app.Close() })
	h.http = httptest.NewServer(h.app)
	t.Cleanup(h.http.Close)
	return h
}

func seedBrowser(t *testing.T, a *App, u store.User, keyID string) (http.Header, store.Credential) {
	t.Helper()
	invite := rand.Text() + rand.Text()
	if err := a.store.Invite(t.Context(), u.ID, invite, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(invite))
	key := store.Credential{ID: []byte(keyID), Data: []byte(`{"fixture":true}`)}
	if err := a.store.Register(t.Context(), u, hash[:], key, time.Now()); err != nil {
		t.Fatal(err)
	}
	secret := rand.Text() + rand.Text()
	if _, err := a.store.CreateLogin(t.Context(), store.LoginInput{User: u, Credential: key, Secret: secret, Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.AddCookie(&http.Cookie{Name: "__Host-sshpd", Value: secret})
	r.AddCookie(&http.Cookie{Name: "__Host-sshpd-profile", Value: rand.Text()})
	return r.Header, key
}

func (h *appHarness) stream(t *testing.T, headers http.Header) *client.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	t.Cleanup(cancel)
	c, err := client.Open(ctx, client.Config{URL: h.http.URL, Destination: relay.Endpoint{Host: "home"}, AllowInsecure: true, Header: headers,
		Logger: slog.New(slog.DiscardHandler), MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, ResumeWindow: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func echoStream(t *testing.T, c *client.Conn, text string) {
	t.Helper()
	if _, err := c.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len(text))
	if _, err := io.ReadFull(c, data); err != nil || string(data) != text {
		t.Fatalf("echo %q: %v", data, err)
	}
}

func adminFixture(t *testing.T, a *App, input AdminRequest) AdminResponse {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.AdminHandler().ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", bytes.NewReader(data)))
	if w.Code != http.StatusOK {
		t.Fatalf("admin: %d %s", w.Code, w.Body.String())
	}
	var out AdminResponse
	if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAuthenticatedRelayAndScopedKeyRemoval(t *testing.T) {
	h := testApp(t)
	u, err := h.app.store.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	firstHeaders, firstKey := seedBrowser(t, h.app, u, "first-key")
	secondHeaders, _ := seedBrowser(t, h.app, u, "second-key")
	first, second := h.stream(t, firstHeaders), h.stream(t, secondHeaders)
	echoStream(t, first, "first")
	echoStream(t, second, "second")
	adminFixture(t, h.app, AdminRequest{Action: "key-remove", Name: "alice", KeyID: base64.RawURLEncoding.EncodeToString(firstKey.ID)})
	if _, err = first.Read(make([]byte, 1)); !errors.Is(err, client.ErrGone) {
		t.Fatalf("removed key stream: %v", err)
	}
	echoStream(t, second, "still connected")
	if h.dials.Load() != 2 || h.app.relay.Stats().Attached != 1 {
		t.Fatal("revocation changed unrelated login or created a new backend")
	}
}

func TestUserDisableClosesAttachedAndDetachedStreams(t *testing.T) {
	h := testApp(t)
	u, err := h.app.store.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	headers, _ := seedBrowser(t, h.app, u, "key")
	first, second := h.stream(t, headers), h.stream(t, headers)
	echoStream(t, first, "attached")
	echoStream(t, second, "detached")
	second.Close()
	deadline := time.Now().Add(time.Second)
	for h.app.relay.Stats().Detached != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if h.app.relay.Stats().Detached != 1 {
		t.Fatal("stream did not detach")
	}
	adminFixture(t, h.app, AdminRequest{Action: "user-disable", Name: "alice"})
	if _, err = first.Read(make([]byte, 1)); !errors.Is(err, client.ErrGone) {
		t.Fatalf("disabled user stream: %v", err)
	}
	if stats := h.app.relay.Stats(); stats.Attached != 0 || stats.Detached != 0 {
		t.Fatal("account disable retained stream")
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	r.Header = headers
	if _, err = h.app.auth.Admit(t.Context(), r, relay.Endpoint{Host: "home"}); err == nil {
		t.Fatal("disabled user retained admission")
	}
}

func TestReloadDrainAndInvalidConfigPreservation(t *testing.T) {
	h := testApp(t)
	u, err := h.app.store.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	headers, _ := seedBrowser(t, h.app, u, "key")
	c := h.stream(t, headers)
	echoStream(t, c, "before")
	next := h.app.cfg
	next.Destinations = []destination{{ID: "invalid", Aliases: []endpoint{{Host: "*"}}, Backend: endpoint{Host: "127.0.0.1"}}}
	if err = h.app.Reload(t.Context(), next); err == nil {
		t.Fatal("invalid destination reload accepted")
	}
	if _, err = h.app.registry.Resolve(t.Context(), relay.Endpoint{Host: "home"}); err != nil {
		t.Fatal("invalid reload changed registry")
	}
	next = h.app.cfg
	next.AllowNoUV = true
	if err = h.app.Reload(t.Context(), next); err == nil {
		t.Fatal("reload changed authentication policy")
	}
	next = h.app.cfg
	next.Destinations = nil
	if err = h.app.Reload(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	echoStream(t, c, "after drain")
	if _, err = h.app.registry.Resolve(t.Context(), relay.Endpoint{Host: "home"}); !errors.Is(err, relay.ErrDestination) {
		t.Fatal("removed target remained configured")
	}
	next.DropRemoved = true
	if err = h.app.Reload(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Read(make([]byte, 1)); !errors.Is(err, client.ErrGone) {
		t.Fatalf("immediate drop: %v", err)
	}
}

func TestCookieDiscoveryCORSAndPopup(t *testing.T) {
	h := testApp(t)
	u, err := h.app.store.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	headers, _ := seedBrowser(t, h.app, u, "key")
	for _, test := range []struct {
		name, path, origin string
		authenticated      bool
		status             int
	}{
		{"endpoint", "/endpoint", "chrome-untrusted://terminal", false, http.StatusOK},
		{"direct", "/cookie?version=2&method=direct", "chrome-untrusted://terminal", true, http.StatusOK},
		{"login redirect", "/cookie?version=2&method=direct", "chrome-untrusted://terminal", false, http.StatusFound},
		{"popup login", "/cookie?version=2&method=close&origin=chrome-untrusted%3A%2F%2Fterminal", "", false, http.StatusFound},
		{"popup close", "/cookie?version=2&method=close&origin=chrome-untrusted%3A%2F%2Fterminal", "", true, http.StatusOK},
		{"unknown request origin", "/endpoint", "https://attacker.example", false, http.StatusForbidden},
		{"unknown popup origin", "/cookie?version=2&method=close&origin=https%3A%2F%2Fattacker.example", "", true, http.StatusForbidden},
		{"legacy protocol", "/cookie?version=1&method=direct", "", true, http.StatusBadRequest},
		{"duplicate method", "/cookie?version=2&method=direct&method=close", "", true, http.StatusBadRequest},
		{"private admin route", "/admin", "", true, http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, test.path, http.NoBody)
			if test.authenticated {
				r.Header = headers.Clone()
			}
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			w := httptest.NewRecorder()
			h.app.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if test.origin == "chrome-untrusted://terminal" && (w.Header().Get("Access-Control-Allow-Origin") != test.origin || w.Header().Get("Access-Control-Allow-Credentials") != "true") {
				t.Fatal("missing credential CORS")
			}
			if test.origin == "https://attacker.example" && w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("untrusted CORS allowed")
			}
			if test.name == "endpoint" || test.name == "direct" {
				body := w.Body.String()
				if len(body) < 5 || body[:5] != ")]}'\n" {
					t.Fatal("missing XSSI prefix")
				}
				var payload struct {
					Endpoint string `json:"endpoint"`
				}
				if err := json.Unmarshal([]byte(body[5:]), &payload); err != nil || payload.Endpoint != "relay.example" {
					t.Fatal("invalid endpoint response")
				}
			}
		})
	}
}

func TestPrivateAdminSocketOwnershipAndLifecycle(t *testing.T) {
	h := testApp(t)
	l, err := ListenAdmin(t.Context(), h.app.cfg.AdminSocket())
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: h.app.AdminHandler(), ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() { s.Close(); <-done })
	info, err := os.Stat(h.app.cfg.AdminSocket())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("administration socket is not private")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", h.app.cfg.AdminSocket())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://unix/", bytes.NewBufferString(`{"action":"users"}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: transport}).Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("owner UID rejected")
	}
	if duplicate, listenErr := ListenAdmin(t.Context(), h.app.cfg.AdminSocket()); listenErr == nil {
		duplicate.Close()
		t.Fatal("existing socket replaced")
	}
	if peerAllowed(nil) {
		t.Fatal("non-Unix peer accepted")
	}
}

func TestConfigIsStrictAndStatePermissionsArePreserved(t *testing.T) {
	for _, data := range []string{
		`{"state_dir":"/tmp/x","public_origin":"https://relay.example","rp_id":"relay.example","typo":1}`,
		`{"state_dir":"/tmp/x","public_origin":"https://relay.example","rp_id":"relay.example"} {}`,
		`{"state_dir":"relative","public_origin":"https://relay.example","rp_id":"relay.example"}`,
		`{"state_dir":"/tmp/x","public_origin":"http://relay.example","rp_id":"relay.example"}`,
		`{"state_dir":"/tmp/x","public_origin":"https://relay.example","rp_id":"attacker.example"}`,
	} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("accepted invalid config: %s", data)
		}
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(dir); err == nil {
		t.Fatal("nonprivate state directory accepted")
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatal("server changed existing directory permissions")
	}
}

func TestAdminEnrollmentReplacementAndRecovery(t *testing.T) {
	h := testApp(t)
	created := adminFixture(t, h.app, AdminRequest{Action: "user-add", Name: "alice"})
	firstURL, err := url.Parse(created.Invitation)
	if err != nil || firstURL.Fragment == "" {
		t.Fatal("missing enrollment link")
	}
	second := adminFixture(t, h.app, AdminRequest{Action: "user-invite", Name: "alice"})
	secondURL, err := url.Parse(second.Invitation)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(firstURL.Fragment))
	if _, err = h.app.store.Invitation(t.Context(), hash[:], time.Now()); !errors.Is(err, store.ErrDenied) {
		t.Fatal("old enrollment link remained valid")
	}
	hash = sha256.Sum256([]byte(secondURL.Fragment))
	if _, err = h.app.store.Invitation(t.Context(), hash[:], time.Now()); err != nil {
		t.Fatal(err)
	}
	adminFixture(t, h.app, AdminRequest{Action: "user-disable", Name: "alice"})
	recovered := adminFixture(t, h.app, AdminRequest{Action: "user-recover", Name: "alice"})
	if recovered.Invitation == "" {
		t.Fatal("recovery did not issue enrollment")
	}
	users := adminFixture(t, h.app, AdminRequest{Action: "users"})
	if len(users.Users) != 1 || users.Users[0].Disabled || len(users.Users[0].Keys) != 0 {
		t.Fatal("recovery did not reset account")
	}
}
