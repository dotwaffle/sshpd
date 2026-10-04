package relay

import (
	"context"
	"math"
	"net"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

func (s *Server) admit(ctx context.Context, r *http.Request, destination Endpoint) (Grant, error) {
	ctx, operation := s.observer.Start(ctx, "relay.admission")
	grant, err := s.cfg.Authorizer.Admit(ctx, r.WithContext(ctx), destination)
	outcome := "ok"
	if err != nil {
		outcome = "denied"
	}
	operation.End(ctx, outcome)
	return grant, err
}

func (s *Server) dial(ctx context.Context, backend Endpoint) (net.Conn, error) {
	ctx, operation := s.observer.Start(ctx, "relay.backend.dial")
	conn, err := s.cfg.Dialer.DialContext(ctx, "tcp", backend.Address())
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	operation.End(ctx, outcome)
	return conn, err
}

func (s *Server) observeStats() error {
	meter := s.observer.Meter
	var err error
	s.auditLoss, err = meter.Int64ObservableCounter("sshpd.relay.audit.lost", metric.WithUnit("{event}"))
	if err != nil {
		return err
	}
	sessions, err := meter.Int64ObservableGauge("sshpd.relay.sessions", metric.WithUnit("{session}"))
	if err != nil {
		return err
	}
	dialing, err := meter.Int64ObservableGauge("sshpd.relay.dialing", metric.WithUnit("{connection}"))
	if err != nil {
		return err
	}
	replay, err := meter.Int64ObservableGauge("sshpd.relay.replay.capacity", metric.WithUnit("By"))
	if err != nil {
		return err
	}
	s.statsRegistration, err = meter.RegisterCallback(func(_ context.Context, observer metric.Observer) error {
		stats := s.Stats()
		observer.ObserveInt64(sessions, int64(stats.Attached), metric.WithAttributes(attribute.String("state", "attached")))
		observer.ObserveInt64(sessions, int64(stats.Detached), metric.WithAttributes(attribute.String("state", "detached")))
		observer.ObserveInt64(dialing, int64(stats.Dialing))
		observer.ObserveInt64(replay, int64(stats.ReplayCapacity))
		observer.ObserveInt64(s.auditLoss, int64(min(stats.AuditLost, uint64(math.MaxInt64))))
		return nil
	}, sessions, dialing, replay, s.auditLoss)
	return err
}

func (s *Server) loseAudit() {
	s.auditLost.Add(1)
}
