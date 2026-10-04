package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/dotwaffle/sshpd/internal/store/queries"
)

func TestSQLiteWaitsBusyRetriesAndTransactionSpans(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()); _ = mp.Shutdown(t.Context()) })
	path := filepath.Join(t.TempDir(), "admission.db")
	s, err := Open(t.Context(), path, WithTelemetry(tp, mp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err = s.CreateUser(t.Context(), "fixture"); err != nil {
		t.Fatal(err)
	}
	// Exhaust the one-connection pool and cancel a waiting request.
	conn, err := s.db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	_, err = s.ListUsers(ctx)
	cancel()
	_ = conn.Close()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("pool contention did not honor the deadline")
	}
	other, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	// Keep production's timeout unchanged. Make the fixture return BUSY fast.
	if _, err = s.db.ExecContext(t.Context(), "PRAGMA busy_timeout=1"); err != nil {
		t.Fatal(err)
	}
	lock, err := other.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	work := func(*queries.Queries) error { return nil }
	if err = s.transact(t.Context(), work); err == nil {
		t.Fatal("writer lock did not exhaust bounded retries")
	}
	if err = lock.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = s.transact(t.Context(), work); err != nil {
		t.Fatal(err)
	}
	var data metricdata.ResourceMetrics
	if err = reader.Collect(t.Context(), &data); err != nil {
		t.Fatal(err)
	}
	values := make(map[string]float64)
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			switch aggregate := metric.Data.(type) {
			case metricdata.Sum[int64]:
				for _, point := range aggregate.DataPoints {
					values[metric.Name] += float64(point.Value)
				}
			case metricdata.Sum[float64]:
				for _, point := range aggregate.DataPoints {
					values[metric.Name] += point.Value
				}
			case metricdata.Gauge[int64]:
				for _, point := range aggregate.DataPoints {
					values[metric.Name] += float64(point.Value)
				}
			}
		}
	}
	if values["sshpd.sqlite.busy"] != 3 || values["sshpd.sqlite.pool.waits"] < 1 || values["sshpd.sqlite.pool.wait.duration"] <= 0 || values["sshpd.sqlite.wal.size"] <= 0 {
		t.Fatalf("missing SQLite observations: %v", values)
	}
	ended := spans.Ended()
	if len(ended) != 7 {
		t.Fatalf("unexpected transaction spans: %d", len(ended))
	}
	transaction := ended[len(ended)-1]
	if transaction.Name() != "sqlite.transaction" {
		t.Fatal("transaction did not end after its phases")
	}
	for _, phase := range ended[len(ended)-3 : len(ended)-1] {
		if !phase.Parent().Equal(transaction.SpanContext()) {
			t.Fatal("begin and commit must be siblings within the transaction")
		}
	}
}
