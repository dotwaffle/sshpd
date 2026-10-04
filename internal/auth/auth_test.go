package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/dotwaffle/sshpd/internal/store"
	"github.com/dotwaffle/sshpd/relay"
)

type fixtureKey struct {
	key *ecdsa.PrivateKey
	id  []byte
}

func newFixtureKey(t *testing.T, id string) fixtureKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fixtureKey{key: key, id: []byte(id)}
}

func testAuth(t *testing.T, noUV bool) (*Service, *store.Store) {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "admission.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(Config{Origin: "https://relay.example", RPID: "relay.example", AllowNoUV: noUV, LoginTTL: time.Hour, CeremonyTTL: time.Minute, Logger: slog.New(slog.DiscardHandler)}, db)
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

type options struct {
	Ceremony  string `json:"ceremony"`
	PublicKey struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
		UserVerification       string `json:"userVerification"`
		AuthenticatorSelection struct {
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
	} `json:"publicKey"`
}

func authRequest(t *testing.T, s *Service, path string, body any, id string) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, bytes.NewReader(data))
	r.Header.Set("Origin", s.cfg.Origin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Ceremony-ID", id)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func beginFixture(t *testing.T, s *Service, name, invitation string) options {
	t.Helper()
	path := "/auth/login/begin"
	if invitation != "" {
		path = "/auth/register/begin"
	}
	w := authRequest(t, s, path, beginInput{Name: name, Invitation: invitation}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("begin: %d %s", w.Code, w.Body.String())
	}
	var out options
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func fixtureClientData(t *testing.T, kind, challenge, origin string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func fixtureAuthData(rp string, flags byte, counter uint32) []byte {
	hash := sha256.Sum256([]byte(rp))
	data := append([]byte(nil), hash[:]...)
	data = append(data, flags)
	return binary.BigEndian.AppendUint32(data, counter)
}

func (k fixtureKey) registration(t *testing.T, o options, origin, rp string, flags byte) map[string]any {
	t.Helper()
	data := fixtureAuthData(rp, flags, 0)
	data = append(data, make([]byte, 16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(k.id)))
	data = append(data, k.id...)
	// Test-only CBOR encodes one ES256 key and a none-attestation object.
	data = append(data, 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20)
	public, err := k.key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, public[1:33]...)
	data = append(data, 0x22, 0x58, 0x20)
	data = append(data, public[33:]...)
	attestation := []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e', 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a', 0x58, byte(len(data))}
	attestation = append(attestation, data...)
	return map[string]any{"id": b64(k.id), "rawId": b64(k.id), "type": "public-key", "authenticatorAttachment": "cross-platform",
		"response": map[string]any{"clientDataJSON": b64(fixtureClientData(t, "webauthn.create", o.PublicKey.Challenge, origin)), "attestationObject": b64(attestation), "transports": []string{"usb"}}, "clientExtensionResults": map[string]any{}}
}

func (k fixtureKey) assertion(t *testing.T, o options, origin, rp string, flags byte, userID string) map[string]any {
	t.Helper()
	clientData := fixtureClientData(t, "webauthn.get", o.PublicKey.Challenge, origin)
	authData := fixtureAuthData(rp, flags, 1)
	clientHash := sha256.Sum256(clientData)
	message := append(append([]byte(nil), authData...), clientHash[:]...)
	messageHash := sha256.Sum256(message)
	signature, err := ecdsa.SignASN1(rand.Reader, k.key, messageHash[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"id": b64(k.id), "rawId": b64(k.id), "type": "public-key", "authenticatorAttachment": "cross-platform",
		"response": map[string]any{"clientDataJSON": b64(clientData), "authenticatorData": b64(authData), "signature": b64(signature), "userHandle": b64([]byte(userID))}, "clientExtensionResults": map[string]any{}}
}

func fixtureEnrollment(t *testing.T, s *Service, db *store.Store, u store.User, k fixtureKey, flags byte) {
	t.Helper()
	secret := rand.Text() + rand.Text()
	if err := db.Invite(t.Context(), u.ID, secret, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	o := beginFixture(t, s, "", secret)
	w := authRequest(t, s, "/auth/register/finish", k.registration(t, o, s.cfg.Origin, s.cfg.RPID, flags), o.Ceremony)
	if w.Code != http.StatusOK {
		t.Fatalf("registration: %d %s", w.Code, w.Body.String())
	}
}

func TestPasskeyEnrollmentLoginAndBrowserAdmission(t *testing.T) {
	for _, flags := range []byte{0x45, 0x5d} {
		t.Run(base64.RawURLEncoding.EncodeToString([]byte{flags}), func(t *testing.T) {
			s, db := testAuth(t, false)
			u, err := db.CreateUser(t.Context(), "alice")
			if err != nil {
				t.Fatal(err)
			}
			k := newFixtureKey(t, "fixture-key")
			fixtureEnrollment(t, s, db, u, k, flags)
			o := beginFixture(t, s, "alice", "")
			if o.PublicKey.UserVerification != "required" {
				t.Fatal("login did not require UV")
			}
			w := authRequest(t, s, "/auth/login/finish", k.assertion(t, o, s.cfg.Origin, s.cfg.RPID, flags&^0x40, u.ID), o.Ceremony)
			if w.Code != http.StatusOK {
				t.Fatalf("login: %d %s", w.Code, w.Body.String())
			}
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home", http.NoBody)
			response := w.Result()
			defer response.Body.Close()
			for _, cookie := range response.Cookies() {
				if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode || cookie.Path != "/" || cookie.Domain != "" {
					t.Fatal("invalid browser cookie security")
				}
				r.AddCookie(cookie)
			}
			grant, err := s.Admit(t.Context(), r, relay.Endpoint{Host: "home"})
			if err != nil || grant.UserID != u.ID || grant.ClientKind != "terminal" || grant.ClientID == "" {
				t.Fatalf("browser grant: %+v %v", grant, err)
			}
			if w = authRequest(t, s, "/auth/login/finish", k.assertion(t, o, s.cfg.Origin, s.cfg.RPID, flags&^0x40, u.ID), o.Ceremony); w.Code != http.StatusUnauthorized {
				t.Fatal("ceremony replay succeeded")
			}
		})
	}
}

func TestRegistrationRejectsInvalidProofWithoutConsumingInvitation(t *testing.T) {
	for _, test := range []struct {
		name, origin, rp string
		flags            byte
		wrongChallenge   bool
	}{
		{"missing UV", "https://relay.example", "relay.example", 0x41, false},
		{"missing presence", "https://relay.example", "relay.example", 0x44, false},
		{"wrong origin", "https://attacker.example", "relay.example", 0x45, false},
		{"wrong RP", "https://relay.example", "attacker.example", 0x45, false},
		{"wrong challenge", "https://relay.example", "relay.example", 0x45, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, db := testAuth(t, false)
			u, err := db.CreateUser(t.Context(), "alice")
			if err != nil {
				t.Fatal(err)
			}
			secret := rand.Text() + rand.Text()
			if err = db.Invite(t.Context(), u.ID, secret, time.Now().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			k := newFixtureKey(t, "fixture-key")
			o := beginFixture(t, s, "", secret)
			if o.PublicKey.AuthenticatorSelection.UserVerification != "required" {
				t.Fatal("registration did not require UV")
			}
			id := o.Ceremony
			if test.wrongChallenge {
				o.PublicKey.Challenge = b64([]byte("wrong"))
			}
			if w := authRequest(t, s, "/auth/register/finish", k.registration(t, o, test.origin, test.rp, test.flags), id); w.Code != http.StatusUnauthorized {
				t.Fatal("invalid registration accepted")
			}
			hash := sha256.Sum256([]byte(secret))
			if _, err = db.Invitation(t.Context(), hash[:], time.Now()); err != nil {
				t.Fatal("failed proof consumed invitation")
			}
		})
	}
}

func TestLoginRejectsInvalidProof(t *testing.T) {
	for _, test := range []struct {
		name, origin, rp string
		flags            byte
		tamper           bool
	}{
		{"missing UV", "https://relay.example", "relay.example", 0x01, false},
		{"missing presence", "https://relay.example", "relay.example", 0x04, false},
		{"wrong origin", "https://attacker.example", "relay.example", 0x05, false},
		{"wrong RP", "https://relay.example", "attacker.example", 0x05, false},
		{"wrong signature", "https://relay.example", "relay.example", 0x05, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, db := testAuth(t, false)
			u, err := db.CreateUser(t.Context(), "alice")
			if err != nil {
				t.Fatal(err)
			}
			k := newFixtureKey(t, "fixture-key")
			fixtureEnrollment(t, s, db, u, k, 0x45)
			o := beginFixture(t, s, "alice", "")
			body := k.assertion(t, o, test.origin, test.rp, test.flags, u.ID)
			if test.tamper {
				response, ok := body["response"].(map[string]any)
				if !ok {
					t.Fatal("invalid fixture response")
				}
				response["signature"] = b64([]byte("bad signature"))
			}
			if w := authRequest(t, s, "/auth/login/finish", body, o.Ceremony); w.Code != http.StatusUnauthorized || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("invalid login accepted")
			}
		})
	}
}

func TestCompatibilityModeStillRequiresPresence(t *testing.T) {
	s, db := testAuth(t, true)
	u, err := db.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	k := newFixtureKey(t, "fixture-key")
	fixtureEnrollment(t, s, db, u, k, 0x41)
	o := beginFixture(t, s, "alice", "")
	if w := authRequest(t, s, "/auth/login/finish", k.assertion(t, o, s.cfg.Origin, s.cfg.RPID, 0x01, u.ID), o.Ceremony); w.Code != http.StatusOK {
		t.Fatal("operator compatibility mode rejected no-UV key")
	}
	o = beginFixture(t, s, "alice", "")
	if w := authRequest(t, s, "/auth/login/finish", k.assertion(t, o, s.cfg.Origin, s.cfg.RPID, 0, u.ID), o.Ceremony); w.Code != http.StatusUnauthorized {
		t.Fatal("compatibility mode waived presence")
	}
}

func TestSameOriginAndCeremonyExpiry(t *testing.T) {
	s, _ := testAuth(t, false)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/login/begin", bytes.NewBufferString(`{"name":"alice"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://attacker.example")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("cross-origin ceremony accepted")
	}
	id, err := s.remember(ceremony{user: user{User: store.User{ID: "alice"}}, expires: time.Now().Add(-time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.take(id, false); err == nil {
		t.Fatal("expired ceremony accepted")
	}
}

func TestAddingPasskeyPreservesLoginAndRecoveryFencesLateAssertion(t *testing.T) {
	s, db := testAuth(t, false)
	u, err := db.CreateUser(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	first := newFixtureKey(t, "first-key")
	fixtureEnrollment(t, s, db, u, first, 0x45)
	o := beginFixture(t, s, "alice", "")
	w := authRequest(t, s, "/auth/login/finish", first.assertion(t, o, s.cfg.Origin, s.cfg.RPID, 0x05, u.ID), o.Ceremony)
	if w.Code != http.StatusOK {
		t.Fatal("first login failed")
	}
	response := w.Result()
	defer response.Body.Close()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)
	for _, cookie := range response.Cookies() {
		r.AddCookie(cookie)
	}
	second := newFixtureKey(t, "second-key")
	fixtureEnrollment(t, s, db, u, second, 0x5d)
	if _, err = s.Login(t.Context(), r); err != nil {
		t.Fatal("adding a key revoked an existing login")
	}
	o = beginFixture(t, s, "alice", "")
	if err = db.ChangeUser(t.Context(), u.ID, "recover"); err != nil {
		t.Fatal(err)
	}
	w = authRequest(t, s, "/auth/login/finish", first.assertion(t, o, s.cfg.Origin, s.cfg.RPID, 0x05, u.ID), o.Ceremony)
	if w.Code != http.StatusUnauthorized || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("late assertion survived operator recovery")
	}
}
