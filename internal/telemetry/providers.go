// Package telemetry owns the daemon's bounded OTLP exporters.
package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// Config enables OTLP HTTP export. Nil SampleRatio selects ten percent.
type Config struct {
	Enabled     bool     `json:"enabled"`
	SampleRatio *float64 `json:"sample_ratio,omitempty"`
}

// Validate rejects invalid sampling ratios even when export is disabled.
func (c Config) Validate() error {
	if c.SampleRatio != nil && (math.IsNaN(*c.SampleRatio) || *c.SampleRatio < 0 || *c.SampleRatio > 1) {
		return errors.New("telemetry sample_ratio must be between zero and one")
	}
	return nil
}

// Providers owns explicit providers and their bounded export workers.
type Providers struct {
	Traces  trace.TracerProvider
	Metrics metric.MeterProvider
	stop    func(context.Context) error
}

// New configures optional exporters from standard OTLP HTTP environment values.
// It does not install global providers or read incoming propagation headers.
func New(ctx context.Context, cfg Config, logger *slog.Logger) (*Providers, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return &Providers{Traces: tracenoop.NewTracerProvider(), Metrics: metricnoop.NewMeterProvider(), stop: func(context.Context) error { return nil }}, nil
	}
	traceExport, err := otlptracehttp.New(ctx, otlptracehttp.WithTimeout(5*time.Second))
	if err != nil {
		return nil, errors.New("initialize trace exporter")
	}
	metricExport, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithTimeout(5*time.Second))
	if err != nil {
		_ = traceExport.Shutdown(ctx)
		return nil, errors.New("initialize metric exporter")
	}
	res := resource.NewSchemaless(attribute.String("service.name", "sshpd"))
	ratio := .1
	if cfg.SampleRatio != nil {
		ratio = *cfg.SampleRatio
	}
	limits := sdktrace.NewSpanLimits()
	limits.AttributeCountLimit, limits.AttributeValueLengthLimit = 16, 256
	limits.EventCountLimit, limits.LinkCountLimit = 8, 4
	limits.AttributePerEventCountLimit, limits.AttributePerLinkCountLimit = 8, 2
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
		sdktrace.WithRawSpanLimits(limits), sdktrace.WithBatcher(traceExporter{SpanExporter: traceExport, logger: logger},
			sdktrace.WithMaxQueueSize(256), sdktrace.WithMaxExportBatchSize(64), sdktrace.WithExportTimeout(5*time.Second)))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithCardinalityLimit(64),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter{Exporter: metricExport, logger: logger}, sdkmetric.WithTimeout(5*time.Second))))
	return &Providers{Traces: tp, Metrics: mp, stop: func(ctx context.Context) error {
		return errors.Join(tp.Shutdown(ctx), mp.Shutdown(ctx))
	}}, nil
}

// Close drains telemetry within one five-second deadline.
func (p *Providers) Close(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return p.stop(ctx)
}

var errExport = errors.New("telemetry export failed")

func exportResult(ctx context.Context, logger *slog.Logger, signal string, err error) error {
	if err == nil {
		return nil
	}
	if logger != nil {
		logger.WarnContext(ctx, "telemetry export failed", slog.String("signal", signal))
	}
	// Collector URLs, credentials, and response bodies do not belong in logs.
	return errExport
}

type traceExporter struct {
	sdktrace.SpanExporter
	logger *slog.Logger
}

// ExportSpans removes collector details from export errors.
func (e traceExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	return exportResult(ctx, e.logger, "traces", e.SpanExporter.ExportSpans(ctx, spans))
}

// Shutdown removes collector details from shutdown errors.
func (e traceExporter) Shutdown(ctx context.Context) error {
	return exportResult(ctx, e.logger, "traces", e.SpanExporter.Shutdown(ctx))
}

type metricExporter struct {
	sdkmetric.Exporter
	logger *slog.Logger
}

// Export removes collector details from export errors.
func (e metricExporter) Export(ctx context.Context, data *metricdata.ResourceMetrics) error {
	return exportResult(ctx, e.logger, "metrics", e.Exporter.Export(ctx, data))
}

// ForceFlush removes collector details from flush errors.
func (e metricExporter) ForceFlush(ctx context.Context) error {
	return exportResult(ctx, e.logger, "metrics", e.Exporter.ForceFlush(ctx))
}

// Shutdown removes collector details from shutdown errors.
func (e metricExporter) Shutdown(ctx context.Context) error {
	return exportResult(ctx, e.logger, "metrics", e.Exporter.Shutdown(ctx))
}
