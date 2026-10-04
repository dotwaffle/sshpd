package store

import (
	"context"
	"errors"
	"os"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/dotwaffle/sshpd/internal/observe"
)

type telemetryOptions struct {
	traces  trace.TracerProvider
	metrics metric.MeterProvider
}

// Option supplies an explicit storage dependency before the database opens.
type Option func(*telemetryOptions)

// WithTelemetry measures transactions and aggregate pool and WAL state.
func WithTelemetry(traces trace.TracerProvider, metrics metric.MeterProvider) Option {
	return func(options *telemetryOptions) { options.traces, options.metrics = traces, metrics }
}

func (s *Store) observe(path string, options []Option) error {
	var cfg telemetryOptions
	for _, option := range options {
		option(&cfg)
	}
	var err error
	s.observer, err = observe.NewRecorder("github.com/dotwaffle/sshpd/internal/store", cfg.traces, cfg.metrics)
	if err != nil {
		return err
	}
	s.busy, err = s.observer.Meter.Int64Counter("sshpd.sqlite.busy", metric.WithUnit("{error}"))
	if err != nil {
		return err
	}
	pool, err := s.observer.Meter.Int64ObservableGauge("sshpd.sqlite.pool.connections", metric.WithUnit("{connection}"))
	if err != nil {
		return err
	}
	waits, err := s.observer.Meter.Int64ObservableCounter("sshpd.sqlite.pool.waits", metric.WithUnit("{wait}"))
	if err != nil {
		return err
	}
	waitTime, err := s.observer.Meter.Float64ObservableCounter("sshpd.sqlite.pool.wait.duration", metric.WithUnit("s"))
	if err != nil {
		return err
	}
	wal, err := s.observer.Meter.Int64ObservableGauge("sshpd.sqlite.wal.size", metric.WithUnit("By"))
	if err != nil {
		return err
	}
	s.statsRegistration, err = s.observer.Meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		stats := s.Stats()
		observer.ObserveInt64(pool, int64(stats.OpenConnections))
		observer.ObserveInt64(waits, stats.WaitCount)
		observer.ObserveFloat64(waitTime, stats.WaitDuration.Seconds())
		info, statErr := os.Stat(path + "-wal")
		switch {
		case statErr == nil:
			observer.ObserveInt64(wal, info.Size())
		case errors.Is(statErr, os.ErrNotExist):
			observer.ObserveInt64(wal, 0)
		default:
			return errors.New("read SQLite WAL metadata")
		}
		return nil
	}, pool, waits, waitTime, wal)
	return err
}
