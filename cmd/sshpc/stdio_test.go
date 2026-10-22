package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/sys/unix"

	"github.com/dotwaffle/sshpd/client"
	"github.com/dotwaffle/sshpd/protocol"
	"github.com/dotwaffle/sshpd/relay"
)

func inheritedPipe(t *testing.T, readEnd bool) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	source, peer := r, w
	if !readEnd {
		source, peer = w, r
	}
	// Fd puts the descriptor in blocking mode, as inherited SSH pipes are.
	fd, err := unix.Dup(int(source.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = source.Close()
	f := os.NewFile(uintptr(fd), "inherited-pipe")
	t.Cleanup(func() { _ = peer.Close(); _ = f.Close() })
	return f, peer
}

func TestProxyClosesInheritedPipes(t *testing.T) {
	for _, blocked := range []string{"stdin", "stdout"} {
		t.Run(blocked, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			received := make(chan struct{})
			h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"ssh"}})
				if err != nil {
					t.Error(err)
					return
				}
				defer ws.CloseNow()
				data, _ := protocol.Encode(protocol.Packet{Tag: protocol.ConnectSuccess, Bytes: []byte("fixture")})
				if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
					return
				}
				if blocked == "stdin" {
					if _, _, err := ws.Read(ctx); err == nil {
						close(received)
					}
					<-ctx.Done()
					return
				}
				// More than an OS pipe can buffer, so stdout must block without a reader.
				for range 64 {
					data, _ := protocol.Encode(protocol.Packet{Tag: protocol.Data, Bytes: make([]byte, 16384)})
					if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
						return
					}
				}
				for {
					_, data, err := ws.Read(ctx)
					if err != nil {
						return
					}
					packet, err := protocol.Decode(data)
					if err == nil && packet.Tag == protocol.ACK && packet.Position >= 256<<10 {
						close(received)
						break
					}
				}
				<-ctx.Done()
			}))
			t.Cleanup(h.Close)
			conn, err := client.Open(ctx, client.Config{URL: h.URL, Destination: relay.Endpoint{Host: "home"}, AllowInsecure: true, Logger: slog.New(slog.DiscardHandler)})
			if err != nil {
				t.Fatal(err)
			}
			in, writer := inheritedPipe(t, true)
			out, reader := inheritedPipe(t, false)
			done := make(chan error, 1)
			go func() { done <- stream(ctx, conn, in, out) }()
			if blocked == "stdin" {
				if _, err := writer.WriteString("ready"); err != nil {
					t.Fatal(err)
				}
				select {
				case <-received:
				case <-ctx.Done():
					t.Fatal("stdin did not reach relay")
				}
			} else {
				if _, err := io.ReadFull(reader, make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
				select {
				case <-received:
				case <-ctx.Done():
					t.Fatal("relay did not fill stdout")
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				// Release the real OS pipes before reporting the regression.
				_ = writer.Close()
				_ = reader.Close()
				<-done
				t.Fatal("proxy cleanup blocked on inherited " + blocked)
			}
		})
	}
}
