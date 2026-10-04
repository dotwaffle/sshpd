package nativeapi

import (
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPostBoundsResponsesAndSanitizesFailures(t *testing.T) {
	secret := rand.Text() + rand.Text()
	for _, test := range []struct {
		name, body string
		status     int
		want       error
	}{
		{name: "denied", status: http.StatusUnauthorized, body: secret, want: ErrDenied},
		{name: "capacity", status: http.StatusTooManyRequests, body: secret, want: ErrTransport},
		{name: "extra-json", status: http.StatusOK, body: `{} {}`, want: ErrTransport},
		{name: "oversize", status: http.StatusOK, body: `{"secret":"` + strings.Repeat("A", 65<<10) + `"}`, want: ErrTransport},
		{name: "ok", status: http.StatusOK, body: `{"secret":"fixture"}`, want: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+secret {
					t.Error("authorization missing")
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			t.Cleanup(h.Close)
			_, err := Post(t.Context(), h.Client(), h.URL, "/fixture", struct{}{}, secret, &Ticket{})
			if !errors.Is(err, test.want) {
				t.Fatal(err)
			}
			if err != nil && (strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), h.URL)) {
				t.Fatal("error leaked response or URL")
			}
		})
	}
}

func TestOriginRequiresExactHTTPSOrigin(t *testing.T) {
	for _, value := range []string{"https://example.com/", "https://example.com?", "https://example.com?token=value", "https://example.com#value", "https://user:secret@example.com", "http://example.com", "file:///etc/passwd", "https://"} {
		if _, err := Origin(value, false); err == nil {
			t.Fatal("invalid origin accepted", value)
		}
	}
	if origin, err := Origin("https://example.com:8443", false); err != nil || origin != "https://example.com:8443" {
		t.Fatal(err)
	}
}
