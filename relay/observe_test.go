package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/dotwaffle/sshpd/protocol"
)

func TestOperationSpansEndBeforeStreamAndLinkResume(t *testing.T) {
	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()); _ = mp.Shutdown(t.Context()) })
	h := newHarness(t, func(c *Config) { c.TracerProvider, c.MeterProvider = tp, mp })
	ws, sid, _ := h.connect(t, http.Header{"Cookie": {"fixture-cookie-secret"}, "Traceparent": {"00-11111111111111111111111111111111-2222222222222222-01"}})
	h.waitEvent(t, "session.start")
	var initial trace.SpanContext
	for _, span := range spans.Ended() {
		if span.Name() == "relay.connect" {
			initial = span.SpanContext()
		}
	}
	if !initial.IsValid() || initial.TraceID().String() == "11111111111111111111111111111111" {
		t.Fatal("connect span is still open or accepted untrusted propagation")
	}
	if h.s.Stats().Attached != 1 {
		t.Fatal("connect span ended only after stream closure")
	}
	_ = ws.CloseNow()
	h.waitEvent(t, "session.detach")
	_, hello := h.resume(t, sid, 0)
	if hello.Tag != protocol.ReconnectSuccess || h.dials.Load() != 1 {
		t.Fatal("resume replaced backend")
	}
	h.waitEvent(t, "session.resume")
	await(t, func() bool {
		for _, span := range spans.Ended() {
			if span.Name() == "relay.reconnect" {
				return true
			}
		}
		return false
	})
	linked, admission, dial := false, false, false
	for _, span := range spans.Ended() {
		switch span.Name() {
		case "relay.reconnect":
			if span.SpanContext().TraceID() == initial.TraceID() {
				t.Fatal("resume reused the initial trace")
			}
			for _, link := range span.Links() {
				linked = linked || link.SpanContext.Equal(initial)
			}
		case "relay.admission":
			admission = span.Parent().Equal(initial)
		case "relay.backend.dial":
			dial = span.Parent().Equal(initial)
		}
		for _, attr := range span.Attributes() {
			switch attr.Key {
			case "operation", "outcome", "event.kind", "event.reason":
			default:
				t.Fatalf("unexpected trace attribute %s", attr.Key)
			}
			if attr.Value.AsString() == sid || attr.Value.AsString() == "fixture-cookie-secret" {
				t.Fatal("trace contains an admission secret")
			}
		}
	}
	if !linked || !admission || !dial {
		t.Fatal("missing resume link or short admission/dial span")
	}
	var data metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &data); err != nil {
		t.Fatal(err)
	}
	attached := false
	for _, scope := range data.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != "sshpd.relay.sessions" {
				continue
			}
			gauge, ok := metric.Data.(metricdata.Gauge[int64])
			if !ok {
				t.Fatal("invalid session gauge")
			}
			for _, point := range gauge.DataPoints {
				state, _ := point.Attributes.Value(attribute.Key("state"))
				if point.Attributes.Len() != 1 {
					t.Fatal("session metrics contain identity labels")
				}
				attached = attached || state.AsString() == "attached" && point.Value == 1
			}
		}
	}
	if !attached {
		t.Fatal("missing attached gauge")
	}
}

func TestUnsampledAuditFailurePolicy(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "best_effort", true: "strict"}[strict], func(t *testing.T) {
			spans := tracetest.NewSpanRecorder()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.NeverSample()), sdktrace.WithSpanProcessor(spans))
			t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })
			h := newHarness(t, func(c *Config) {
				c.TracerProvider, c.StrictAudit = tp, strict
				c.Audit = auditFunc(func(_ context.Context, _ AuditEvent) error { return errors.New("fixture audit failure") })
			})
			if strict {
				w := httptest.NewRecorder()
				h.s.connect(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v4/connect?host=home", http.NoBody))
				if w.Code != http.StatusServiceUnavailable || h.s.Stats().Attached+h.s.Stats().Detached != 0 {
					t.Fatal("strict audit did not reject admission")
				}
			} else {
				h.connect(t, nil)
				await(t, func() bool { return h.s.Stats().AuditLost > 0 })
				if h.s.Stats().Attached != 1 {
					t.Fatal("audit failure closed a best-effort stream")
				}
			}
			if h.s.Stats().AuditLost == 0 || len(spans.Ended()) != 0 {
				t.Fatal("sampling affected audit failure accounting")
			}
		})
	}
}
