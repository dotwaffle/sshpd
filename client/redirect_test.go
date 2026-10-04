package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/dotwaffle/sshpd/protocol"
)

func TestNativeRedirectCannotForwardAdmissionOrResume(t *testing.T) {
	for _, phase := range []string{"admission", "resume"} {
		t.Run(phase, func(t *testing.T) {
			var forwarded, admissions, resumes atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded.Add(1); w.WriteHeader(http.StatusBadRequest) }))
			t.Cleanup(target.Close)
			cfg := nativeServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v4/connect" {
					admissions.Add(1)
				} else {
					resumes.Add(1)
				}
				if phase == "admission" || r.URL.Path == "/v4/reconnect" {
					http.Redirect(w, r, target.URL+"/v4/connect", http.StatusTemporaryRedirect)
					return
				}
				ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"ssh"}})
				if err != nil {
					t.Error(err)
					return
				}
				defer ws.CloseNow()
				if err := peerWrite(r.Context(), ws, protocol.Packet{Tag: protocol.ConnectSuccess, Bytes: []byte("redirect-fixture-sid")}); err != nil {
					t.Error(err)
				}
			})
			cfg.ResumeWindow = 20 * time.Millisecond
			conn, err := Open(t.Context(), cfg)
			if phase == "admission" {
				if !errors.Is(err, ErrTransport) || conn != nil {
					t.Fatal("redirected admission succeeded", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrTransport) {
					t.Fatal("redirected resume did not end", err)
				}
				if resumes.Load() == 0 {
					t.Fatal("resume redirect was not exercised")
				}
			}
			if forwarded.Load() != 0 || admissions.Load() != 1 {
				t.Fatal("redirect forwarded credentials or made a fresh admission", forwarded.Load(), admissions.Load())
			}
		})
	}
}
