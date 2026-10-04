package observe

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// Recorder measures fixed operation names and bounded outcome categories.
type Recorder struct {
	tracer   trace.Tracer
	Meter    metric.Meter
	count    metric.Int64Counter
	duration metric.Float64Histogram
}

// NewRecorder creates instruments from explicit providers, or no-op defaults.
func NewRecorder(scope string, traces trace.TracerProvider, metrics metric.MeterProvider) (*Recorder, error) {
	if traces == nil {
		traces = tracenoop.NewTracerProvider()
	}
	if metrics == nil {
		metrics = metricnoop.NewMeterProvider()
	}
	r := &Recorder{tracer: traces.Tracer(scope), Meter: metrics.Meter(scope)}
	var err error
	r.count, err = r.Meter.Int64Counter("sshpd.operations", metric.WithUnit("{operation}"))
	if err != nil {
		return nil, err
	}
	r.duration, err = r.Meter.Float64Histogram("sshpd.operation.duration", metric.WithUnit("s"))
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Operation owns a short span. End must run before a stream begins.
type Operation struct {
	span     trace.Span
	name     string
	started  time.Time
	recorder *Recorder
	once     sync.Once
}

// Start creates an internal operation without request URLs or identity fields.
func (r *Recorder) Start(ctx context.Context, name string, options ...trace.SpanStartOption) (context.Context, *Operation) {
	ctx, span := r.tracer.Start(ctx, name, options...)
	return ctx, &Operation{span: span, name: name, started: time.Now(), recorder: r}
}

// End records an outcome once. It never exports or waits on a collector.
func (o *Operation) End(ctx context.Context, outcome string) {
	o.once.Do(func() {
		attrs := []attribute.KeyValue{attribute.String("operation", o.name), attribute.String("outcome", outcome)}
		o.span.SetAttributes(attrs...)
		if outcome != "ok" {
			o.span.SetStatus(codes.Error, outcome)
		}
		o.span.End()
		o.recorder.count.Add(ctx, 1, metric.WithAttributes(attrs...))
		o.recorder.duration.Record(ctx, time.Since(o.started).Seconds(), metric.WithAttributes(attrs...))
	})
}
