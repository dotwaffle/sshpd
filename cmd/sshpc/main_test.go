package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/dotwaffle/sshpd/client"
	"github.com/dotwaffle/sshpd/internal/agent"
	"github.com/dotwaffle/sshpd/protocol"
	"github.com/dotwaffle/sshpd/relay"
)

type writeBuffer struct{ bytes.Buffer }

func (*writeBuffer) Close() error { return nil }

func TestCommandsValidateArgumentsWithoutStartingAgent(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "absent", "agent.sock")
	for _, args := range [][]string{
		{"proxy", "--server", "https://relay.example", "--host", "home", "--agent-socket", socket},
		{"proxy", "--server", "http://relay.example", "--host", "home", "--agent-socket", socket},
		{"proxy", "--server", "https://relay.example", "--host", "home", "--port", "65536", "--agent-socket", socket},
		{"logout", "--server", "https://relay.example", "--agent-socket", socket},
		{"status", "--server", "https://relay.example", "--agent-socket", socket},
	} {
		t.Run(args[0]+args[2], func(t *testing.T) {
			var output writeBuffer
			var stderr bytes.Buffer
			err := run(t.Context(), args, io.NopCloser(bytes.NewReader(nil)), &output, &stderr)
			if err == nil || output.Len() != 0 {
				t.Fatal("invalid/unavailable command wrote data or succeeded", err)
			}
			if _, err := os.Lstat(filepath.Dir(socket)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("command started agent or created directory")
			}
		})
	}
}

func TestStatusUsesPrivateAgentAndHelpListsCommands(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	socket := filepath.Join(t.TempDir(), "private", "agent.sock")
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx, socket, slog.New(slog.DiscardHandler)) }()
	t.Cleanup(func() { cancel(); <-done })
	startup, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	for {
		if _, err := agent.Call(startup, socket, "/status", agent.Request{Server: "https://relay.example"}, &agent.Status{}); err == nil {
			break
		}
		if err := pause(startup, time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	var output writeBuffer
	if err := run(ctx, []string{"status", "--server", "https://relay.example", "--agent-socket", socket}, io.NopCloser(bytes.NewReader(nil)), &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"logged_in":false`)) {
		t.Fatal("incorrect status")
	}
	output.Reset()
	if err := run(ctx, []string{"help"}, io.NopCloser(bytes.NewReader(nil)), &output, io.Discard); err != nil || !bytes.Contains(output.Bytes(), []byte("sshpc proxy")) {
		t.Fatal("missing help", err)
	}
}

func TestProxyStreamWaitsForACKAndCancelsBlockedInput(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	gotData, sendACK := make(chan struct{}), make(chan struct{})
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"ssh"}})
		if err != nil {
			t.Error(err)
			return
		}
		defer ws.CloseNow()
		write := func(packet protocol.Packet) error {
			data, encodeErr := protocol.Encode(packet)
			if encodeErr != nil {
				return encodeErr
			}
			return ws.Write(ctx, websocket.MessageBinary, data)
		}
		if writeErr := write(protocol.Packet{Tag: protocol.ConnectSuccess, Bytes: []byte("fixture-sid")}); writeErr != nil {
			t.Error(writeErr)
			return
		}
		_, data, err := ws.Read(ctx)
		if err != nil {
			t.Error(err)
			return
		}
		packet, err := protocol.Decode(data)
		if err != nil || packet.Tag != protocol.Data || string(packet.Bytes) != "disconnect" {
			t.Error("incorrect proxy payload")
			return
		}
		close(gotData)
		select {
		case <-sendACK:
		case <-ctx.Done():
			return
		}
		if err := write(protocol.Packet{Tag: protocol.ACK, Position: uint64(len(packet.Bytes))}); err != nil {
			t.Error(err)
			return
		}
		if err := write(protocol.Packet{Tag: protocol.Data, Bytes: []byte("final output")}); err != nil {
			t.Error(err)
			return
		}
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				return
			}
		}
	}))
	t.Cleanup(h.Close)
	conn, err := client.Open(ctx, client.Config{URL: h.URL, Destination: relay.Endpoint{Host: "home"}, AllowInsecure: true, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	input, writer := io.Pipe()
	output, outputWriter := io.Pipe()
	t.Cleanup(func() { writer.Close(); output.Close() })
	done := make(chan error, 1)
	go func() { done <- stream(ctx, conn, input, outputWriter) }()
	if _, err := writer.Write([]byte("disconnect")); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	select {
	case <-gotData:
	case <-ctx.Done():
		t.Fatal("no input received")
	}
	select {
	case <-done:
		t.Fatal("stdin EOF discarded unacknowledged bytes")
	default:
	}
	close(sendACK)
	data := make([]byte, len("final output"))
	if _, err := io.ReadFull(output, data); err != nil || string(data) != "final output" {
		t.Fatal("output missing", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy goroutines did not stop")
	}
}
