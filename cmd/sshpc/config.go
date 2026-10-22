package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/dotwaffle/sshpd/internal/nativeapi"
)

type clientConfig struct {
	Server string `json:"server"`
}

func serverOrigin(server string, explicit bool, configPath string, errOut io.Writer) (string, error) {
	if explicit {
		origin, err := nativeapi.Origin(server, false)
		if err != nil {
			return "", errors.New("--server requires an HTTPS origin")
		}
		return origin, nil
	}
	paths := []string{configPath}
	if configPath == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("find user configuration: %w", err)
		}
		paths = []string{filepath.Join(dir, "sshpc", "config.json"), "/etc/sshpc.json"}
	}
	origin, source, err := configuredServer(paths, configPath != "")
	if err != nil {
		return "", err
	}
	if origin == "" {
		return "", errors.New("--server or a configured HTTPS server is required")
	}
	if _, err := fmt.Fprintf(errOut, "Using server %s from %s\n", origin, source); err != nil {
		return "", err
	}
	return origin, nil
}

// Paths are ordered from highest to lowest priority. Missing default files are optional.
func configuredServer(paths []string, required bool) (string, string, error) {
	for _, path := range paths {
		cfg, err := readClientConfig(path)
		if errors.Is(err, os.ErrNotExist) && !required {
			continue
		}
		if err != nil {
			return "", "", fmt.Errorf("read client configuration %s: %w", path, err)
		}
		if cfg.Server == "" {
			continue
		}
		origin, err := nativeapi.Origin(cfg.Server, false)
		if err != nil {
			return "", "", fmt.Errorf("client configuration %s requires an HTTPS server origin", path)
		}
		return origin, path, nil
	}
	return "", "", nil
}

func readClientConfig(path string) (clientConfig, error) {
	var cfg clientConfig
	f, err := os.Open(path) //nolint:gosec // The user selects a local configuration file.
	if err != nil {
		return cfg, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return cfg, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return cfg, errors.New("configuration must be a regular file of at most 64 KiB")
	}
	d := json.NewDecoder(io.LimitReader(f, (64<<10)+1))
	d.DisallowUnknownFields()
	var decoded *clientConfig
	if err := d.Decode(&decoded); err != nil || decoded == nil {
		return cfg, errors.New("invalid client configuration JSON")
	}
	cfg = *decoded
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return cfg, errors.New("client configuration must contain one JSON object")
	}
	return cfg, nil
}
