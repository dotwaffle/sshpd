package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dotwaffle/sshpd/internal/nativeapi"
)

// ErrUnavailable means no usable private agent is listening.
var ErrUnavailable = errors.New("private agent unavailable; run sshpc login")

// DefaultSocket returns a socket distinct from SSH_AUTH_SOCK.
func DefaultSocket() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "sshpd", "agent.sock"), nil
}

// PrivateDir validates the owner-only socket directory without changing ~/.ssh.
func PrivateDir(socket string) error {
	if !filepath.IsAbs(socket) {
		return errors.New("agent socket requires an absolute path")
	}
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || !owned(info) || info.Mode().Perm() != 0o700 {
		return errors.New("agent directory must be owned by this user with mode 0o700")
	}
	return nil
}

func privateFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !owned(info) || info.Mode().Perm() != 0o600 {
		_ = f.Close()
		return nil, errors.New("invalid private agent file")
	}
	return f, nil
}

func installation(dir string) (string, error) {
	f, err := privateFile(filepath.Join(dir, "client-id"))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 27))
	if err != nil {
		return "", err
	}
	if len(data) != 0 {
		if !nativeapi.ValidID(string(data), 26) {
			return "", errors.New("invalid installation identity")
		}
		return string(data), nil
	}
	id := rand.Text()
	if _, err := f.WriteString(id); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	return id, nil
}

type privateListener struct {
	net.Listener
	lock *os.File
	once sync.Once
}

// Accept rejects peers with a different UID.
func (l *privateListener) Accept() (net.Conn, error) {
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

// Close removes the listener and releases its singleton lock.
func (l *privateListener) Close() error {
	var err error
	l.once.Do(func() { err = l.Listener.Close(); _ = l.lock.Close() })
	return err
}

func listen(ctx context.Context, socket string) (*privateListener, string, error) {
	if err := PrivateDir(socket); err != nil {
		return nil, "", err
	}
	lock, err := privateFile(filepath.Join(filepath.Dir(socket), "agent.lock"))
	if err != nil {
		return nil, "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = lock.Close()
		}
	}()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, "", errors.New("agent already running")
	}
	info, err := os.Lstat(socket)
	if err == nil {
		if info.Mode()&os.ModeSocket == 0 || !owned(info) || info.Mode().Perm() != 0o600 {
			return nil, "", errors.New("invalid existing agent socket")
		}
		dialer := net.Dialer{Timeout: time.Second}
		conn, dialErr := dialer.DialContext(ctx, "unix", socket)
		if dialErr == nil {
			_ = conn.Close()
			return nil, "", errors.New("agent already running")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, "", ErrUnavailable
		}
		current, statErr := os.Lstat(socket)
		if statErr != nil || !os.SameFile(info, current) {
			return nil, "", ErrUnavailable
		}
		if removeErr := os.Remove(socket); removeErr != nil {
			return nil, "", removeErr
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	id, err := installation(filepath.Dir(socket))
	if err != nil {
		return nil, "", err
	}
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "unix", socket)
	if err != nil {
		return nil, "", err
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = l.Close()
		return nil, "", err
	}
	keep = true
	return &privateListener{Listener: l, lock: lock}, id, nil
}

// Run serves a memory-only agent until ctx ends. Bearers never reach a file.
func Run(ctx context.Context, socket string, logger *slog.Logger) error {
	l, id, err := listen(ctx, socket)
	if err != nil {
		return err
	}
	defer func() { _ = l.Close() }()
	s, err := New(Config{ClientID: id, Logger: logger})
	if err != nil {
		return err
	}
	return serve(ctx, l, s)
}

func serve(ctx context.Context, l net.Listener, s *Service) error {
	h := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }, ErrorLog: slog.NewLogLogger(s.cfg.Logger.Handler(), slog.LevelError)}
	done := make(chan error, 1)
	go func() { done <- h.Serve(l) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := h.Shutdown(shutdown); err != nil {
			_ = h.Close()
		}
		<-done
		return nil
	}
}

// Call authenticates the agent peer and exchanges a local message.
func Call(ctx context.Context, socket, path string, input Request, out any) (int, error) {
	info, err := os.Lstat(filepath.Dir(socket))
	if err != nil || !info.IsDir() || !owned(info) || info.Mode().Perm() != 0o700 {
		return 0, ErrUnavailable
	}
	info, err = os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || !owned(info) || info.Mode().Perm() != 0o600 {
		return 0, ErrUnavailable
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		conn, dialErr := d.DialContext(ctx, "unix", socket)
		if dialErr != nil {
			return nil, ErrUnavailable
		}
		if !peerAllowed(conn) {
			_ = conn.Close()
			return nil, ErrUnavailable
		}
		return conn, nil
	}}
	defer transport.CloseIdleConnections()
	status, err := nativeapi.Post(ctx, &http.Client{Transport: transport, Timeout: 20 * time.Second}, "http://unix", path, input, "", out)
	if errors.Is(err, nativeapi.ErrDenied) {
		return status, ErrLogin
	}
	if status == 0 {
		return status, ErrUnavailable
	}
	return status, err
}
