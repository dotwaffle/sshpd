package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/dotwaffle/sshpd/internal/daemon"
)

func TestAdminCommandUsesPrivateSocket(t *testing.T) {
	cfg := daemon.Config{StateDir: filepath.Join(t.TempDir(), "state"), PublicOrigin: "https://relay.example", RPID: "relay.example"}
	app, err := daemon.New(t.Context(), cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	l, err := daemon.ListenAdmin(t.Context(), cfg.AdminSocket())
	if err != nil {
		t.Fatal(err)
	}
	s := &http.Server{Handler: app.AdminHandler(), ReadHeaderTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() {
		s.Close()
		if serveErr := <-done; !errors.Is(serveErr, http.ErrServerClosed) {
			t.Errorf("admin server: %v", serveErr)
		}
	})
	var out bytes.Buffer
	if err = run(t.Context(), []string{"admin", "-socket", cfg.AdminSocket(), "user-add", "alice"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var added daemon.AdminResponse
	if err = json.Unmarshal(out.Bytes(), &added); err != nil || !added.OK || added.Invitation == "" {
		t.Fatal("CLI did not return enrollment link")
	}
	out.Reset()
	if err = run(t.Context(), []string{"admin", "-socket", cfg.AdminSocket(), "users"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var listed daemon.AdminResponse
	if err = json.Unmarshal(out.Bytes(), &listed); err != nil || len(listed.Users) != 1 || listed.Users[0].Name != "alice" {
		t.Fatal("CLI did not list created user")
	}
}

func TestCommandArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		{"unknown"}, {"admin", "users"}, {"admin", "-socket", "/unused", "key-remove", "alice"},
		{"admin", "-socket", "/unused", "users", "extra"}, {"serve", "extra"},
	} {
		if err := run(t.Context(), args, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted arguments %v", args)
		}
	}
}
