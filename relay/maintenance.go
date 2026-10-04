package relay

import (
	"context"
	"time"
)

func (s *Server) maintenance(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = s.Close()
			return
		case <-ticker.C:
			used := uint64(0)
			if s.cfg.MemoryUsage != nil {
				used = s.cfg.MemoryUsage()
			}
			s.sweep(s.cfg.Now(), used)
		}
	}
}

func (s *Server) victimLocked(now time.Time) *session {
	var best *session
	for _, p := range s.sessions {
		if p.attached != nil || p.detached.IsZero() || now.Sub(p.detached) < s.cfg.Limits.EvictionAge || p.out.Capacity() == 0 {
			continue
		}
		if best == nil {
			best = p
			continue
		}
		oldest := p.detached.Before(best.detached)
		if s.cfg.Limits.OldestFirst {
			if oldest {
				best = p
			}
		} else if p.out.Capacity() > best.out.Capacity() || p.out.Capacity() == best.out.Capacity() && oldest {
			best = p
		}
	}
	return best
}

func (s *Server) sweep(now time.Time, used uint64) {
	s.mu.Lock()
	// Admission deadlines use the real clock, independent of session policy time.
	wallNow := time.Now()
	for _, revoked := range []map[string]revocation{s.revokedUsers, s.revokedLogins} {
		for id, mark := range revoked {
			if !wallNow.Before(mark.expires) {
				delete(revoked, id)
			}
		}
	}
	var victims []*session
	if used < s.lastMemoryUsed {
		s.pressureCredit -= min(s.pressureCredit, s.lastMemoryUsed-used)
	}
	s.lastMemoryUsed = used
	for _, p := range s.sessions {
		if p.attached == nil && !p.detached.IsZero() && now.Sub(p.detached) >= s.cfg.Limits.Retention {
			s.removeLocked(p, "retention_expired")
			victims = append(victims, p)
		}
	}
	limit := s.cfg.MemoryLimit
	used -= min(used, s.pressureCredit)
	if limit > 0 && used >= uint64(float64(limit)*s.cfg.Limits.PressureHigh) && !now.Before(s.pressureHold) {
		target := uint64(float64(limit) * s.cfg.Limits.PressureLow)
		for used > target {
			p := s.victimLocked(now)
			if p == nil {
				break
			}
			released := p.out.Allocated()
			s.removeLocked(p, "memory_pressure")
			victims = append(victims, p)
			used -= min(used, released)
		}
		if len(victims) > 0 {
			s.pressureHold = now.Add(5 * time.Second)
		}
	}
	s.pressureBlocked = limit > 0 && used >= uint64(float64(limit)*s.cfg.Limits.PressureHigh)
	// Wake blocked backend readers when another session released global capacity.
	for _, p := range s.sessions {
		p.signalLocked()
	}
	s.mu.Unlock()
	for _, p := range victims {
		closeSession(p)
	}
}
