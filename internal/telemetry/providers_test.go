package telemetry

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dotwaffle/sshpd/internal/observe"
)

func TestSamplingConfig(t *testing.T) {
	for _, ratio := range []float64{-1, math.NaN(), math.Inf(1), 1.1, 0, .1, 1} {
		err := (Config{SampleRatio: &ratio}).Validate()
		valid := !math.IsNaN(ratio) && ratio >= 0 && ratio <= 1
		if (err == nil) != valid {
			t.Fatalf("ratio %v: %v", ratio, err)
		}
	}
	if err := (Config{}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOTLPExportAndRedactedFailure(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var mu sync.Mutex
			requests := make(map[string]int)
			collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil || len(body) == 0 || r.Header.Get("Authorization") != "fixture-header-secret" {
					t.Error("invalid OTLP request")
				}
				mu.Lock()
				requests[r.URL.Path]++
				mu.Unlock()
				w.Header().Set("Content-Type", "application/x-protobuf")
				w.WriteHeader(status)
				if status != http.StatusOK {
					_, _ = io.WriteString(w, "fixture-response-secret")
				}
			}))
			defer collector.Close()
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", collector.URL+"/fixture-endpoint-secret/traces")
			t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", collector.URL+"/fixture-endpoint-secret/metrics")
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "Authorization=fixture-header-secret")
			t.Setenv("OTEL_EXPORTER_OTLP_METRICS_HEADERS", "Authorization=fixture-header-secret")
			t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "60000")
			var output bytes.Buffer
			ratio := 1.0
			providers, err := New(t.Context(), Config{Enabled: true, SampleRatio: &ratio}, slog.New(slog.NewJSONHandler(&output, nil)))
			if err != nil {
				t.Fatal(err)
			}
			r, err := observe.NewRecorder("test", providers.Traces, providers.Metrics)
			if err != nil {
				t.Fatal(err)
			}
			ctx, op := r.Start(t.Context(), "auth.login.finish")
			op.End(ctx, "ok")
			canceled, cancel := context.WithCancel(t.Context())
			cancel()
			started := time.Now()
			err = providers.Close(canceled)
			if time.Since(started) > 6*time.Second {
				t.Fatal("shutdown exceeded export deadline")
			}
			if status == http.StatusOK && err != nil {
				t.Fatal(err)
			}
			if status != http.StatusOK && !strings.Contains(output.String(), "telemetry export failed") {
				t.Fatal("collector failure was not reported")
			}
			mu.Lock()
			defer mu.Unlock()
			if requests["/fixture-endpoint-secret/traces"] == 0 || requests["/fixture-endpoint-secret/metrics"] == 0 {
				t.Fatalf("missing exports: %v", requests)
			}
			for _, secret := range []string{"fixture-endpoint-secret", "fixture-header-secret", "fixture-response-secret"} {
				if strings.Contains(output.String(), secret) || (err != nil && strings.Contains(err.Error(), secret)) {
					t.Fatalf("export leaked %q", secret)
				}
			}
		})
	}
}
