package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KimMachineGun/automemlimit/memlimit"

	"github.com/dotwaffle/sshpd/internal/command"
	"github.com/dotwaffle/sshpd/internal/daemon"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	var cli serverCLI
	selected, err := command.Parse(&cli, "sshpd", args, out, errOut)
	if err != nil || selected == "" {
		return err
	}
	switch selected {
	case "serve":
		return serve(ctx, cli.Serve.Config, errOut)
	default:
		input, err := cli.Admin.request(selected)
		if err != nil {
			return err
		}
		return admin(ctx, cli.Admin.Socket, input, out)
	}
}

func serve(ctx context.Context, path string, errOut io.Writer) error {
	cfg, err := daemon.Load(path)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(errOut, nil))
	if _, err = memlimit.Set(memlimit.WithLogger(logger)); err != nil && !errors.Is(err, memlimit.ErrNoLimit) {
		logger.WarnContext(ctx, "automatic memory limit unavailable", slog.String("error", err.Error()))
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := daemon.New(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() { _ = app.CloseContext(ctx) }()
	public, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer func() { _ = public.Close() }()
	private, err := daemon.ListenAdmin(ctx, cfg.AdminSocket())
	if err != nil {
		return err
	}
	defer func() { _ = private.Close() }()
	httpServer := httpService(app, logger)
	adminServer := httpService(app.AdminHandler(), logger)
	failed := make(chan error, 2)
	go func() { failed <- httpServer.Serve(public) }()
	go func() { failed <- adminServer.Serve(private) }()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	logger.InfoContext(ctx, "server ready", slog.String("listen", public.Addr().String()), slog.String("admin_socket", cfg.AdminSocket()))
	err = wait(ctx, app, path, hup, failed, logger)
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return errors.Join(err, httpServer.Shutdown(shutdownCtx), adminServer.Shutdown(shutdownCtx))
}

func httpService(handler http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError)}
}

func wait(ctx context.Context, app *daemon.App, path string, hup <-chan os.Signal, failed <-chan error, logger *slog.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failed:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-hup:
			reload(ctx, app, path, logger)
		}
	}
}

func reload(ctx context.Context, app *daemon.App, path string, logger *slog.Logger) {
	next, err := daemon.Load(path)
	if err == nil {
		reloadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		err = app.Reload(reloadCtx, next)
	}
	if err != nil {
		logger.ErrorContext(ctx, "destination reload failed", slog.String("error", err.Error()))
	}
}

func admin(ctx context.Context, socket string, input daemon.AdminRequest, out io.Writer) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/", bytes.NewReader(data))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(r)
	if err != nil {
		return fmt.Errorf("connect to administration socket: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return errors.New("administration failed")
	}
	_, err = io.Copy(out, io.LimitReader(response.Body, 1<<20))
	return err
}
