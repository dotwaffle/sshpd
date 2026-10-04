package daemon

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestKeyRevocationAfterBrowserAdmissionExpiry(t *testing.T) {
	h := testApp(t)
	u, err := h.app.store.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	firstHeaders, firstKey := seedBrowser(t, h.app, u, "first-key")
	secondHeaders, _ := seedBrowser(t, h.app, u, "second-key")
	first := h.stream(t, firstHeaders)
	second := h.stream(t, secondHeaders)
	echoStream(t, first, "first login")
	echoStream(t, second, "second login")
	if err = h.app.store.Prune(t.Context(), time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	adminFixture(t, h.app, AdminRequest{Action: "key-remove", Name: "alice", KeyID: base64.RawURLEncoding.EncodeToString(firstKey.ID)})
	if stats := h.app.relay.Stats(); stats.Attached != 1 {
		t.Fatal("expired login lost its revocation scope", stats.Attached)
	}
	echoStream(t, second, "other key remains active")
}
