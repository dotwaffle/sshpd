// Package daemon integrates relay admission, storage, and local administration.
package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/dotwaffle/sshpd/relay"
)

// Duration is a JSON duration string such as "15m".
type Duration time.Duration

// UnmarshalJSON parses a duration string.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	value, err := time.ParseDuration(text)
	if err != nil {
		return err
	}
	*d = Duration(value)
	return nil
}

// MarshalJSON writes a duration string.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

type endpoint struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

type destination struct {
	ID      string     `json:"id"`
	Aliases []endpoint `json:"aliases"`
	Backend endpoint   `json:"backend"`
}

type limits struct {
	Sessions        int      `json:"sessions"`
	SessionsPerUser int      `json:"sessions_per_user"`
	ReplayBytes     int      `json:"replay_bytes"`
	ReplayBudget    int      `json:"replay_budget"`
	Retention       Duration `json:"retention"`
	EvictionAge     Duration `json:"eviction_age"`
	ReplacementAge  Duration `json:"replacement_age"`
	OldestFirst     bool     `json:"oldest_first"`
	PressureHigh    float64  `json:"pressure_high"`
	PressureLow     float64  `json:"pressure_low"`
}

func (l limits) relayLimits() relay.Limits {
	return relay.Limits{Sessions: l.Sessions, SessionsPerUser: l.SessionsPerUser, ReplayBytes: l.ReplayBytes, ReplayBudget: l.ReplayBudget,
		Retention: time.Duration(l.Retention), EvictionAge: time.Duration(l.EvictionAge), ReplacementAge: time.Duration(l.ReplacementAge),
		OldestFirst: l.OldestFirst, PressureHigh: l.PressureHigh, PressureLow: l.PressureLow}
}

// Config is the strict JSON configuration for one standalone server.
// SIGHUP permits changes only to destinations and their immediate-close policy.
type Config struct {
	Listen          string        `json:"listen"`
	StateDir        string        `json:"state_dir"`
	PublicOrigin    string        `json:"public_origin"`
	RPID            string        `json:"rp_id"`
	TerminalOrigins []string      `json:"terminal_origins"`
	AllowNoUV       bool          `json:"allow_no_uv"`
	LoginTTL        Duration      `json:"login_ttl"`
	InviteTTL       Duration      `json:"invite_ttl"`
	CeremonyTTL     Duration      `json:"ceremony_ttl"`
	ApprovalTTL     Duration      `json:"approval_ttl"`
	TicketTTL       Duration      `json:"ticket_ttl"`
	Destinations    []destination `json:"destinations"`
	DropRemoved     bool          `json:"drop_removed"`
	Limits          limits        `json:"limits"`
	StrictAudit     bool          `json:"strict_audit"`
	TrustedProxies  []string      `json:"trusted_proxies"`
	trustedProxies  []netip.Prefix
}

// Load rejects unknown fields, extra JSON values, and invalid policy values.
func Load(path string) (Config, error) {
	//nolint:gosec // The operator supplies the configuration path on the command line.
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer func() { _ = f.Close() }()
	var cfg Config
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err = d.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("config must contain one JSON object")
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if len(c.TrustedProxies) > 64 {
		return errors.New("trusted_proxies permits at most 64 CIDRs")
	}
	c.trustedProxies = nil
	for _, text := range c.TrustedProxies {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix.Addr().Is4In6() {
			return errors.New("trusted_proxies must contain IPv4 or IPv6 CIDRs")
		}
		c.trustedProxies = append(c.trustedProxies, prefix.Masked())
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	if !filepath.IsAbs(c.StateDir) {
		return errors.New("state_dir must be absolute")
	}
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("public_origin must be an exact HTTPS origin")
	}
	if c.RPID == "" || strings.ContainsAny(c.RPID, "/:* ") || (u.Hostname() != c.RPID && !strings.HasSuffix(u.Hostname(), "."+c.RPID)) {
		return errors.New("rp_id must match the public origin or its parent domain")
	}
	if c.LoginTTL == 0 {
		c.LoginTTL = Duration(12 * time.Hour)
	}
	if c.InviteTTL == 0 {
		c.InviteTTL = Duration(15 * time.Minute)
	}
	if c.CeremonyTTL == 0 {
		c.CeremonyTTL = Duration(5 * time.Minute)
	}
	if c.ApprovalTTL == 0 {
		c.ApprovalTTL = Duration(5 * time.Minute)
	}
	if c.TicketTTL == 0 {
		c.TicketTTL = Duration(30 * time.Second)
	}
	if c.LoginTTL <= 0 || c.InviteTTL <= 0 || c.CeremonyTTL <= 0 || c.ApprovalTTL <= 0 || c.TicketTTL <= 0 {
		return errors.New("authentication lifetimes must be positive")
	}
	if c.TerminalOrigins == nil {
		c.TerminalOrigins = []string{"chrome-untrusted://terminal"}
	}
	for _, origin := range c.TerminalOrigins {
		v, parseErr := url.Parse(origin)
		if parseErr != nil || v.Scheme == "" || v.Host == "" || v.User != nil || v.Path != "" || v.RawQuery != "" || v.Fragment != "" || strings.ContainsAny(origin, "*?") {
			return errors.New("terminal_origins must contain exact origins")
		}
	}
	_, err = relay.NewRegistry(c.targets())
	return err
}

func (c *Config) targets() []relay.Destination {
	out := make([]relay.Destination, 0, len(c.Destinations))
	for _, d := range c.Destinations {
		target := relay.Destination{ID: d.ID, Backend: relay.Endpoint{Host: d.Backend.Host, Port: d.Backend.Port}}
		for _, alias := range d.Aliases {
			target.Aliases = append(target.Aliases, relay.Endpoint{Host: alias.Host, Port: alias.Port})
		}
		out = append(out, target)
	}
	return out
}

func (c *Config) reloadCompatible(next Config) bool {
	current := *c
	current.Destinations, next.Destinations = nil, nil
	current.DropRemoved, next.DropRemoved = false, false
	return reflect.DeepEqual(current, next)
}

// AdminSocket is the private server administration socket path.
func (c *Config) AdminSocket() string { return filepath.Join(c.StateDir, "admin.sock") }
