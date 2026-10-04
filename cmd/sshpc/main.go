package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/dotwaffle/sshpd/client"
	"github.com/dotwaffle/sshpd/internal/agent"
	"github.com/dotwaffle/sshpd/internal/nativeapi"
	"github.com/dotwaffle/sshpd/relay"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, input io.ReadCloser, out io.WriteCloser, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "help" {
		_, err := fmt.Fprintln(out, "Usage: sshpc login --server HTTPS_ORIGIN [--agent-socket PATH]\n       sshpc status|logout --server HTTPS_ORIGIN [--agent-socket PATH]\n       sshpc proxy --server HTTPS_ORIGIN --host HOST --port PORT [--agent-socket PATH]\n       sshpc agent [--agent-socket PATH]")
		return err
	}
	command := args[0]
	if command != "login" && command != "status" && command != "logout" && command != "proxy" && command != "agent" {
		return errors.New("unknown command, use sshpc help")
	}
	defaultSocket, err := agent.DefaultSocket()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	socket := flags.String("agent-socket", defaultSocket, "private native credential-agent socket")
	server := flags.String("server", "", "public HTTPS relay origin")
	host := flags.String("host", "", "SSH destination host")
	port := flags.Uint("port", 22, "SSH destination port")
	resumeWindow := flags.Duration("resume-window", 15*time.Minute, "maximum retry time after transport loss")
	if parseErr := flags.Parse(args[1:]); parseErr != nil {
		return parseErr
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	logger := slog.New(slog.NewJSONHandler(errOut, nil))
	if command == "agent" {
		return agent.Run(ctx, *socket, logger)
	}
	origin, err := nativeapi.Origin(*server, false)
	if err != nil {
		return errors.New("--server requires an HTTPS origin")
	}
	request := agent.Request{Server: origin}
	switch command {
	case "login":
		if err := ensureAgent(ctx, *socket, request); err != nil {
			return err
		}
		return login(ctx, *socket, request, out)
	case "status":
		var status agent.Status
		if _, err := agent.Call(ctx, *socket, "/status", request, &status); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(status)
	case "logout":
		_, err := agent.Call(ctx, *socket, "/logout", request, nil)
		return err
	case "proxy":
		if *resumeWindow <= 0 {
			return errors.New("resume window must be positive")
		}
		if *port == 0 || *port > 65535 {
			return errors.New("invalid SSH port")
		}
		target, err := (relay.Endpoint{Host: *host, Port: uint16(*port)}).Normalize()
		if err != nil {
			return errors.New("invalid SSH destination")
		}
		request.Target = nativeapi.Target{Host: target.Host, Port: target.Port}
		var ticket nativeapi.Ticket
		if _, err = agent.Call(ctx, *socket, "/ticket", request, &ticket); err != nil {
			return err
		}
		conn, err := client.Open(ctx, client.Config{URL: origin, Destination: target, Header: http.Header{"Authorization": []string{"Bearer " + ticket.Secret}}, Logger: logger, ResumeWindow: *resumeWindow})
		if err != nil {
			return err
		}
		return stream(ctx, conn, input, out)
	}
	return errors.New("unknown command")
}

func ensureAgent(ctx context.Context, socket string, request agent.Request) error {
	_, err := agent.Call(ctx, socket, "/status", request, &agent.Status{})
	if err == nil {
		return nil
	}
	if !errors.Is(err, agent.ErrUnavailable) {
		return err
	}
	if dirErr := agent.PrivateDir(socket); dirErr != nil {
		return dirErr
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = devNull.Close() }()
	// The executable is this running program. Arguments never pass through a shell.
	cmd := exec.Command(executable, "agent", "--agent-socket", socket) //nolint:gosec,noctx // Relaunch this executable, detached from the login command's lifetime.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devNull, devNull, devNull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return errors.New("cannot start private agent")
	}
	if err := cmd.Process.Release(); err != nil {
		return err
	}
	startup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if _, err := agent.Call(startup, socket, "/status", request, &agent.Status{}); err == nil {
			return nil
		}
		if err := pause(startup, 50*time.Millisecond); err != nil {
			return errors.New("private agent did not start; run sshpc agent to inspect the failure")
		}
	}
}

func login(ctx context.Context, socket string, request agent.Request, out io.Writer) error {
	var approval nativeapi.Approval
	if _, err := agent.Call(ctx, socket, "/login/start", request, &approval); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Open %s\nApprove code %s for client %s. Expires %s.\n", approval.URL, approval.Code, approval.ClientID, approval.Expires.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, approval.Expires)
	defer cancel()
	request.Code = approval.Code
	for {
		status, err := agent.Call(ctx, socket, "/login/poll", request, &agent.Status{})
		if err != nil {
			return err
		}
		if status == http.StatusOK {
			_, err := fmt.Fprintln(out, "Logged in. Admission credentials remain in the private agent.")
			return err
		}
		if err := pause(ctx, time.Second); err != nil {
			return errors.New("login canceled or approval expired")
		}
	}
}

func pause(ctx context.Context, delay time.Duration) error {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func stream(ctx context.Context, conn *client.Conn, input io.ReadCloser, output io.WriteCloser) error {
	defer func() { _ = conn.Close() }()
	inDone, outDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := io.Copy(conn, input); inDone <- err }()
	go func() { _, err := io.Copy(output, conn); outDone <- err }()
	inFinished, outFinished := false, false
	defer func() {
		_ = input.Close()
		_ = output.Close()
		_ = conn.Close()
		if !inFinished {
			<-inDone
		}
		if !outFinished {
			<-outDone
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-outDone:
		outFinished = true
		return err
	case err := <-inDone:
		inFinished = true
		if err != nil {
			return err
		}
		flushCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := conn.Flush(flushCtx); err != nil {
			return err
		}
		select {
		case err := <-outDone:
			outFinished = true
			return err
		case <-flushCtx.Done():
			return flushCtx.Err()
		}
	}
}
