package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/dotwaffle/sshpd/internal/observe"
	"github.com/dotwaffle/sshpd/internal/telemetry"
)

func TestHTTPTraceNamesExcludeRequestData(t *testing.T) {
	h := testApp(t)
	spans := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })
	recorder, err := observe.NewRecorder("test", tp, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.app.observer = recorder
	for _, path := range []string{"/fixture-path-secret?token=fixture-query-secret", "/login", "/auth/login/finish"} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody)
		r.Header.Set("Cookie", "fixture-cookie-secret")
		r.Header.Set("Traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
		h.app.ServeHTTP(httptest.NewRecorder(), r)
	}
	if len(spans.Ended()) != 3 {
		t.Fatal("missing HTTP spans")
	}
	for i, name := range []string{"http.not_found", "web.page", "auth.login.finish"} {
		span := spans.Ended()[i]
		if span.Name() != name || span.Parent().IsValid() || len(span.Attributes()) != 2 {
			t.Fatalf("unexpected HTTP trace: %s %v", span.Name(), span.Attributes())
		}
	}
	zero := 0.0
	next := h.app.cfg
	next.Telemetry = telemetry.Config{Enabled: true, SampleRatio: &zero}
	if err = h.app.Reload(t.Context(), next); err == nil {
		t.Fatal("telemetry changed without a restart")
	}
}
