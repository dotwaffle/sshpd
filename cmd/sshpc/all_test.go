package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func commandAgent(t *testing.T, handler http.Handler) string {
	t.Helper()
	// Keep the path short enough for macOS and BSD without a nested directory.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "s")
	if len(socket) > 103 {
		t.Fatalf("test socket path exceeds the portable 103-byte limit: %s", socket)
	}
	lc := net.ListenConfig{}
	l, err := lc.Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: handler, ReadHeaderTimeout: 0} // Test server accepts only a private Unix socket.
	done := make(chan struct{})
	go func() { _ = s.Serve(l); close(done) }()
	t.Cleanup(func() { _ = s.Close(); <-done })
	return socket
}

func TestAllCommandsIgnoreDefaultAndReportFailures(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	dir, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	writeConfig(t, filepath.Join(dir, "sshpc", "config.json"), "invalid JSON")
	for _, tc := range []struct {
		name, command, path, body string
		code                      int
		wantError                 string
	}{
		{"status", "status", "/status/all", `{"client_id":"test","servers":[]}`, 200, ""},
		{"logout", "logout", "/logout/all", `[]`, 200, ""},
		{"partial", "logout", "/logout/all", `[{"server":"https://one.example","logged_out":false},{"server":"https://two.example","logged_out":true}]`, 200, "https://one.example"},
		{"old_agent", "status", "/status/all", `not found`, 404, "restart"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socket := commandAgent(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.path {
					t.Errorf("path=%s, want %s", r.URL.Path, tc.path)
				}
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			}))
			var out writeBuffer
			var stderr bytes.Buffer
			err := run(t.Context(), []string{tc.command, "--agent-socket", socket}, io.NopCloser(strings.NewReader("")), &out, &stderr)
			if tc.wantError == "" && err != nil || tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatal("incorrect command result", err)
			}
			if stderr.Len() != 0 {
				t.Fatal("all-server command selected a default")
			}
			if tc.code == 200 && !strings.Contains(out.String(), tc.body) {
				t.Fatal("missing structured result")
			}
		})
	}
}

func TestProxyDefaultNoticeDoesNotWriteStdout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig(t, path, `{"server":"https://configured.example"}`)
	socket := commandAgent(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ticket" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		data, _ := io.ReadAll(r.Body)
		if !bytes.Contains(data, []byte(`"server":"https://configured.example"`)) {
			t.Error("ticket request did not use default server")
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	var out writeBuffer
	var stderr bytes.Buffer
	err := run(t.Context(), []string{"proxy", "--config", path, "--host", "home", "--agent-socket", socket}, io.NopCloser(strings.NewReader("")), &out, &stderr)
	if err == nil || out.Len() != 0 || !strings.Contains(stderr.String(), "Using server https://configured.example") {
		t.Fatal("proxy notice missing or contaminated stdout", err)
	}
}
