// Package nativeapi defines bounded native approval and ticket messages.
package nativeapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"time"
)

// ErrDenied indicates an expired, consumed, or invalid native capability.
var ErrDenied = errors.New("native admission unavailable")

// Target selects an exact configured SSH destination.
type Target struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

// Start binds browser approval to an installation and a private polling proof.
type Start struct {
	ClientID string `json:"client_id"`
	PollHash string `json:"poll_hash"`
}

// Approval contains information that the user must compare before approval.
type Approval struct {
	Code     string    `json:"code"`
	URL      string    `json:"url"`
	ClientID string    `json:"client_id"`
	Expires  time.Time `json:"expires"`
}

// Poll proves ownership of the client that initiated an approval.
type Poll struct {
	Code  string `json:"code"`
	Proof string `json:"proof"`
}

// Grant is delivered once to the agent and never returned by its local API.
type Grant struct {
	Secret   string    `json:"secret"`
	ClientID string    `json:"client_id"`
	Expires  time.Time `json:"expires"`
}

// Ticket permits one fresh admission for one canonical destination.
type Ticket struct {
	Secret  string    `json:"secret"`
	Expires time.Time `json:"expires"`
}

// Hash returns the SHA-256 polling commitment without retaining the proof.
func Hash(proof string) string {
	sum := sha256.Sum256([]byte(proof))
	return hex.EncodeToString(sum[:])
}

// ValidID accepts opaque base32 identifiers without control characters.
func ValidID(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if (c < 'A' || c > 'Z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// Origin validates a public HTTPS origin. Insecure origins are for local tests.
func Origin(value string, insecure bool) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Scheme != "https" && (!insecure || u.Scheme != "http")) {
		return "", errors.New("server must be an exact HTTPS origin")
	}
	return u.String(), nil
}
