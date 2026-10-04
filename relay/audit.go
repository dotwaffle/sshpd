package relay

import (
	"context"
	"log/slog"
)

func (s *Server) emit(event AuditEvent) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if s.auditClosed {
		s.auditLost.Add(1)
		s.cfg.Logger.Error("audit event dropped", slog.String("kind", event.Kind))
		return
	}
	select {
	case s.auditQueue <- event:
	default:
		s.auditLost.Add(1)
		s.cfg.Logger.Error("audit event dropped", slog.String("kind", event.Kind))
	}
}

func (s *Server) record(ctx context.Context, event AuditEvent) error {
	if s.cfg.Audit != nil {
		auditCtx, cancel := context.WithTimeout(ctx, s.cfg.AuditTimeout)
		defer cancel()
		if err := s.cfg.Audit.Record(auditCtx, event); err != nil {
			s.auditLost.Add(1)
			s.cfg.Logger.Error("audit sink failed", slog.String("kind", event.Kind))
			return err
		}
		return nil
	}
	s.cfg.Logger.Info("relay audit",
		slog.String("kind", event.Kind), slog.String("session_id", event.SessionID),
		slog.String("user_id", event.Grant.UserID), slog.String("login_id", event.Grant.LoginID),
		slog.String("client_kind", event.Grant.ClientKind), slog.String("client_id", event.Grant.ClientID),
		slog.String("destination_id", event.DestinationID), slog.String("backend", event.Backend.Address()),
		slog.String("reason", event.Reason), slog.Uint64("received_bytes", event.Received), slog.Uint64("sent_bytes", event.Sent))
	return nil
}

func (s *Server) auditLoop(ctx context.Context) {
	defer close(s.auditDone)
	for {
		select {
		case <-ctx.Done():
			s.drainAudit(ctx)
			return
		case event := <-s.auditQueue:
			_ = s.record(ctx, event)
		}
	}
}

func (s *Server) drainAudit(ctx context.Context) {
	s.auditMu.Lock()
	s.auditClosed = true
	s.auditMu.Unlock()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.AuditTimeout)
	defer cancel()
	for {
		select {
		case event := <-s.auditQueue:
			if ctx.Err() != nil {
				s.auditLost.Add(1)
				s.cfg.Logger.Error("audit event dropped", slog.String("kind", event.Kind))
			} else {
				_ = s.record(ctx, event)
			}
		default:
			return
		}
	}
}

func (s *Server) eventLocked(p *session, kind, reason string) AuditEvent {
	return AuditEvent{Time: s.cfg.Now(), Kind: kind, Reason: reason, SessionID: p.id,
		Grant: p.grant, DestinationID: p.target.ID, Requested: p.requested, Backend: p.target.Backend,
		Received: p.received, Sent: p.out.End()}
}
