package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dotwaffle/sshpd/internal/requestmeta"
	"github.com/dotwaffle/sshpd/protocol"
)

func TestAuditTransportAndResumeClientAddresses(t *testing.T) {
	h := newHarness(t, nil)
	ws, sid, _ := h.connect(t, http.Header{"X-Forwarded-For": {"203.0.113.99"}})
	started := h.waitEvent(t, "session.start")
	if started.ClientIP != "127.0.0.1" || started.PeerIP != "127.0.0.1" {
		t.Fatalf("standalone relay trusted forwarding header: %+v", started)
	}
	ws.CloseNow()
	h.waitEvent(t, "session.detach")
	h.http.Close()
	h.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := requestmeta.WithClient(r.Context(), requestmeta.Client{IP: "203.0.113.8", Peer: "127.0.0.1"})
		h.s.ServeHTTP(w, r.WithContext(ctx))
	}))
	resumedWS, hello := h.resume(t, sid, 0)
	if hello.Tag != protocol.ReconnectSuccess || h.dials.Load() != 1 {
		t.Fatal("IP change prevented same-backend resume")
	}
	resumed := h.waitEvent(t, "session.resume")
	if resumed.ClientIP != "203.0.113.8" || resumed.PeerIP != "127.0.0.1" {
		t.Fatalf("missing validated resume addresses: %+v", resumed)
	}
	resumedWS.CloseNow()
	detached := h.waitEvent(t, "session.detach")
	if detached.ClientIP != resumed.ClientIP || detached.PeerIP != resumed.PeerIP {
		t.Fatal("detach lost attachment address metadata")
	}
}
