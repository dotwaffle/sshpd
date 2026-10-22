package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredServerPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, user, system, want string
	}{
		{"user", `{"server":"https://user.example"}`, `{"server":"https://system.example"}`, "https://user.example"},
		{"system", `{}`, `{"server":"https://system.example"}`, "https://system.example"},
		{"missing_user", "", `{"server":"https://system.example"}`, "https://system.example"},
		{"no_files", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			paths := []string{filepath.Join(dir, "user.json"), filepath.Join(dir, "system.json")}
			for i, data := range []string{tc.user, tc.system} {
				if data != "" {
					writeConfig(t, paths[i], data)
				}
			}
			got, _, err := configuredServer(paths, false)
			if err != nil || got != tc.want {
				t.Fatalf("server=%q, error=%v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestClientConfigRejectsInvalidInput(t *testing.T) {
	for _, data := range []string{
		`{"server":"http://relay.example"}`, `{"server":"https://user:password@relay.example"}`,
		`{"server":"https://relay.example/path"}`, `{"unknown":true}`, `{`, `null`, `[]`, `{ } { }`,
		strings.Repeat(" ", 64<<10) + `{}`,
	} {
		t.Run(strings.TrimSpace(data), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			writeConfig(t, path, data)
			if _, _, err := configuredServer([]string{path}, true); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	if _, _, err := configuredServer([]string{filepath.Join(t.TempDir(), "missing")}, true); err == nil {
		t.Fatal("explicit missing configuration accepted")
	}
}

func TestServerSelectionNoticeAndOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeConfig(t, path, `{"server":"https://configured.example"}`)
	var stderr bytes.Buffer
	if origin, err := serverOrigin("", false, path, &stderr); err != nil || origin != "https://configured.example" {
		t.Fatal("configured server not selected", err)
	}
	if !strings.Contains(stderr.String(), "https://configured.example") || !strings.Contains(stderr.String(), path) {
		t.Fatal("configured server notice missing")
	}
	writeConfig(t, path, "invalid JSON")
	stderr.Reset()
	if origin, err := serverOrigin("https://explicit.example", true, path, &stderr); err != nil || origin != "https://explicit.example" || stderr.Len() != 0 {
		t.Fatal("explicit server did not override configuration", err)
	}
	if _, err := serverOrigin("", true, path, &stderr); err == nil {
		t.Fatal("explicit empty server used a default")
	}
}
