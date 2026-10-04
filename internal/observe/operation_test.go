package observe

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/dotwaffle/sshpd/internal/requestmeta"
)

func TestMetricsSurviveSamplingAndRepeatedEnd(t *testing.T) {
	for _, sample := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsampled", true: "sampled"}[sample], func(t *testing.T) {
			reader := sdkmetric.NewManualReader()
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			spans := tracetest.NewSpanRecorder()
			sampler := sdktrace.NeverSample()
			if sample {
				sampler = sdktrace.AlwaysSample()
			}
			tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans), sdktrace.WithSampler(sampler))
			t.Cleanup(func() { _ = tp.Shutdown(t.Context()); _ = mp.Shutdown(t.Context()) })
			r, err := NewRecorder("test", tp, mp)
			if err != nil {
				t.Fatal(err)
			}
			ctx, operation := r.Start(t.Context(), "auth.login.finish")
			operation.End(ctx, "denied")
			operation.End(ctx, "ok")
			var data metricdata.ResourceMetrics
			if err = reader.Collect(t.Context(), &data); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, scope := range data.ScopeMetrics {
				for _, metric := range scope.Metrics {
					if metric.Name != "sshpd.operations" {
						continue
					}
					sum, ok := metric.Data.(metricdata.Sum[int64])
					if !ok || len(sum.DataPoints) != 1 || sum.DataPoints[0].Value != 1 {
						t.Fatalf("operation counted more than once: %#v", metric.Data)
					}
					attrs := sum.DataPoints[0].Attributes
					outcome, _ := attrs.Value(attribute.Key("outcome"))
					if attrs.Len() != 2 || outcome.AsString() != "denied" {
						t.Fatalf("unexpected metric labels: %v", attrs)
					}
					found = true
				}
			}
			if !found || len(spans.Ended()) != map[bool]int{false: 0, true: 1}[sample] {
				t.Fatal("sampling changed operation metrics")
			}
		})
	}
}

func TestLoggerCorrelatesValidatedMetadata(t *testing.T) {
	var output bytes.Buffer
	logger := Logger(slog.New(slog.NewJSONHandler(&output, nil)))
	if Logger(logger) != logger {
		t.Fatal("logger wrapped twice")
	}
	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })
	ctx, span := tp.Tracer("test").Start(t.Context(), "test")
	defer span.End()
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/?secret=do-not-log", http.NoBody)
	r.Header.Set("Cookie", "do-not-log")
	ctx = requestmeta.WithClient(r.Context(), requestmeta.Client{IP: "192.0.2.8", Peer: "192.0.2.1"})
	logger.With(slog.String("component", "test")).WithGroup("request").InfoContext(ctx, "complete", slog.String("client_ip", "192.0.2.8"))
	logged := output.String()
	for _, expected := range []string{"192.0.2.8", "192.0.2.1", trace.SpanContextFromContext(ctx).TraceID().String()} {
		if !strings.Contains(logged, expected) {
			t.Fatalf("missing correlation %q", expected)
		}
	}
	if strings.Contains(logged, "do-not-log") || strings.Count(logged, "client_ip") != 1 {
		t.Fatalf("unexpected log metadata: %s", logged)
	}
}
