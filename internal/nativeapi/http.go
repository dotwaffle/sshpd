package nativeapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// ErrTransport omits response bodies, URLs, and credential material.
var ErrTransport = errors.New("native service unavailable")

// Post exchanges a bounded JSON message without following redirects.
// Accepted indicates a pending approval. NoContent indicates logout success.
func Post(ctx context.Context, client *http.Client, origin, path string, input any, secret string, out any) (int, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return 0, ErrTransport
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(data))
	if err != nil {
		return 0, ErrTransport
	}
	r.Header.Set("Content-Type", "application/json")
	if secret != "" {
		r.Header.Set("Authorization", "Bearer "+secret)
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copyClient.Do(r)
	if err != nil {
		return 0, ErrTransport
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return response.StatusCode, ErrDenied
	}
	if response.StatusCode == http.StatusAccepted || response.StatusCode == http.StatusNoContent {
		return response.StatusCode, nil
	}
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, ErrTransport
	}
	if out != nil {
		d := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
		if err := d.Decode(out); err != nil {
			return response.StatusCode, ErrTransport
		}
		var extra any
		if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
			return response.StatusCode, ErrTransport
		}
	}
	return response.StatusCode, nil
}
