package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixtureSocket(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "private", "agent.sock")
}

func TestPrivateSocketRPCAndStableInstallation(t *testing.T) {
	socket := fixtureSocket(t)
	var previous string
	for iteration := range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		l, id, err := listen(ctx, socket)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if previous != "" && previous != id {
			t.Fatal("installation ID changed after restart")
		}
		previous = id
		for _, name := range []string{socket, filepath.Join(filepath.Dir(socket), "client-id"), filepath.Join(filepath.Dir(socket), "agent.lock")} {
			info, statErr := os.Lstat(name)
			if statErr != nil || info.Mode().Perm() != 0o600 || !owned(info) {
				t.Fatal("private file mode", statErr)
			}
		}
		if other, _, listenErr := listen(ctx, socket); listenErr == nil {
			other.Close()
			t.Fatal("second agent replaced live socket")
		}
		s, err := New(Config{ClientID: id, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- serve(ctx, l, s) }()
		var status Status
		if _, err = Call(ctx, socket, "/status", Request{Server: "https://relay.example"}, &status); err != nil || status.ClientID != id || status.LoggedIn {
			t.Fatal("private RPC failed", err)
		}
		data, err := os.ReadFile(filepath.Join(filepath.Dir(socket), "client-id"))
		if err != nil || string(data) != id {
			t.Fatal("installation changed", iteration, err)
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("agent did not stop")
		}
		if _, err := Call(t.Context(), socket, "/status", Request{Server: "https://relay.example"}, &status); !errors.Is(err, ErrUnavailable) {
			t.Fatal("dead agent usable", err)
		}
	}
}

func TestStaleSocketRecoveryAndUnsafePaths(t *testing.T) {
	for _, kind := range []string{"stale", "file", "symlink", "wide-directory", "wide-socket", "symlink-id"} {
		t.Run(kind, func(t *testing.T) {
			socket := fixtureSocket(t)
			if err := PrivateDir(socket); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "file":
				_ = os.WriteFile(socket, []byte("keep"), 0o600)
			case "symlink":
				_ = os.Symlink("missing", socket)
			case "wide-directory":
				_ = os.Chmod(filepath.Dir(socket), 0o755)
			case "symlink-id":
				_ = os.Symlink("missing", filepath.Join(filepath.Dir(socket), "client-id"))
			default:
				l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				l.SetUnlinkOnClose(false)
				mode := os.FileMode(0o600)
				if kind == "wide-socket" {
					mode = 0o666
				}
				_ = os.Chmod(socket, mode)
				_ = l.Close()
			}
			l, _, err := listen(t.Context(), socket)
			if kind == "stale" {
				if err != nil {
					t.Fatal(err)
				}
				_ = l.Close()
			} else {
				if err == nil {
					l.Close()
					t.Fatal("unsafe path accepted")
				}
				if kind == "file" {
					data, _ := os.ReadFile(socket)
					if string(data) != "keep" {
						t.Fatal("existing file replaced")
					}
				}
			}
		})
	}
}
