package relay

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/dotwaffle/sshpd/internal/replay"
	"github.com/dotwaffle/sshpd/internal/requestmeta"
	"github.com/dotwaffle/sshpd/protocol"
)

type session struct {
	sid, id   string
	client    requestmeta.Client
	grant     Grant
	target    Target
	requested Endpoint
	backend   net.Conn
	inMu      sync.Mutex
	// Server.mu guards fields below. stop is immutable after construction.
	stop              context.CancelFunc
	out               replay.Buffer
	received, sentTop uint64
	attached          *attachment
	detached          time.Time
	wake              chan struct{}
	eof               bool
}

type attachment struct {
	ws     *websocket.Conn
	done   chan struct{}
	once   sync.Once
	cursor uint64
}

func (a *attachment) stop()      { a.once.Do(func() { close(a.done); _ = a.ws.CloseNow() }) }
func (p *session) signalLocked() { close(p.wake); p.wake = make(chan struct{}) }

type attachInput struct {
	session *session
	ws      *websocket.Conn
	ack     uint64
	resume  bool
	client  requestmeta.Client
}

func (s *Server) attach(input attachInput) (*attachment, error) {
	p, ws, ack, resume := input.session, input.ws, input.ack, input.resume
	// Wait for old backend writes before taking the reconnect ACK snapshot.
	p.inMu.Lock()
	defer p.inMu.Unlock()
	s.mu.Lock()
	if s.sessions[p.sid] != p {
		s.mu.Unlock()
		return nil, ErrGone
	}
	if resume && (ack < p.out.Base() || ack > p.sentTop) {
		s.mu.Unlock()
		return nil, ErrProtocol
	}
	before := p.out.Capacity()
	beforeBytes := p.out.Allocated()
	if err := p.out.Acknowledge(ack); err != nil {
		s.mu.Unlock()
		return nil, ErrProtocol
	}
	s.allocated -= before - p.out.Capacity()
	s.pressureCredit += beforeBytes - p.out.Allocated()
	old := p.attached
	a := &attachment{ws: ws, done: make(chan struct{}), cursor: ack}
	p.attached = a
	p.client = input.client
	p.detached = time.Time{}
	p.signalLocked()
	s.mu.Unlock()
	if old != nil {
		old.stop()
	}
	return a, nil
}

func (s *Server) run(ctx context.Context, p *session, a *attachment, hello protocol.Packet) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-a.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer s.detach(p, a)
	if err := writePacket(ctx, a.ws, hello, s.cfg.WriteTimeout); err != nil {
		return
	}
	written := make(chan struct{})
	go func() { defer close(written); s.sendOutput(ctx, p, a); a.stop() }()
	for {
		typ, b, err := a.ws.Read(ctx)
		if err != nil {
			break
		}
		packet, err := protocol.Decode(b)
		if err != nil || typ != websocket.MessageBinary {
			s.terminate(p, "protocol_error")
			break
		}
		if err := s.receive(ctx, p, a, packet); err != nil {
			if errors.Is(err, ErrProtocol) {
				s.terminate(p, "protocol_error")
			}
			break
		}
	}
	a.stop()
	cancel()
	<-written
}

func (s *Server) detach(p *session, a *attachment) {
	s.mu.Lock()
	if s.sessions[p.sid] == p && p.attached == a {
		p.attached = nil
		p.detached = s.cfg.Now()
		p.signalLocked()
		s.emit(s.eventLocked(p, "session.detach", "transport_closed"))
	}
	s.mu.Unlock()
	a.stop()
}

func (s *Server) receive(ctx context.Context, p *session, a *attachment, packet protocol.Packet) error {
	switch packet.Tag {
	case protocol.ACK:
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.sessions[p.sid] != p || p.attached != a {
			return ErrGone
		}
		if packet.Position > p.sentTop {
			return ErrProtocol
		}
		before := p.out.Capacity()
		beforeBytes := p.out.Allocated()
		if err := p.out.Acknowledge(packet.Position); err != nil {
			return ErrProtocol
		}
		s.allocated -= before - p.out.Capacity()
		s.pressureCredit += beforeBytes - p.out.Allocated()
		p.signalLocked()
		return nil
	case protocol.Data:
		return s.writeBackend(ctx, p, a, packet.Bytes)
	case protocol.ConnectSuccess, protocol.ReconnectSuccess:
		return ErrProtocol
	default:
		return nil
	}
}

func (s *Server) writeBackend(ctx context.Context, p *session, a *attachment, data []byte) error {
	p.inMu.Lock()
	defer p.inMu.Unlock()
	s.mu.Lock()
	if s.sessions[p.sid] != p || p.attached != a {
		s.mu.Unlock()
		return ErrGone
	}
	if uint64(len(data)) > math.MaxUint64-p.received {
		s.mu.Unlock()
		return ErrProtocol
	}
	s.mu.Unlock()
	if err := p.backend.SetWriteDeadline(time.Now().Add(s.cfg.BackendWriteTimeout)); err != nil {
		s.terminate(p, "backend_error")
		return err
	}
	remaining := data
	for len(remaining) > 0 {
		n, err := p.backend.Write(remaining)
		if err != nil || n == 0 {
			s.terminate(p, "backend_error")
			if err != nil {
				return err
			}
			return io.ErrNoProgress
		}
		remaining = remaining[n:]
	}
	s.mu.Lock()
	p.received += uint64(len(data))
	received := p.received
	s.mu.Unlock()
	return writePacket(ctx, a.ws, protocol.Packet{Tag: protocol.ACK, Position: received}, s.cfg.WriteTimeout)
}

func (s *Server) sendOutput(ctx context.Context, p *session, a *attachment) {
	for {
		s.mu.Lock()
		if s.sessions[p.sid] != p || p.attached != a {
			s.mu.Unlock()
			return
		}
		if p.eof && p.out.Len() == 0 {
			s.mu.Unlock()
			s.terminate(p, "backend_eof")
			return
		}
		data, err := p.out.ReadAt(a.cursor, protocol.MaxArray)
		if err != nil {
			s.mu.Unlock()
			s.terminate(p, "protocol_error")
			return
		}
		wake := p.wake
		if len(data) > 0 {
			p.sentTop = max(p.sentTop, a.cursor+uint64(len(data)))
		}
		s.mu.Unlock()
		if len(data) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-wake:
				continue
			}
		}
		if err := writePacket(ctx, a.ws, protocol.Packet{Tag: protocol.Data, Bytes: data}, s.cfg.WriteTimeout); err != nil {
			return
		}
		a.cursor += uint64(len(data))
	}
}

func (s *Server) readBackend(ctx context.Context, p *session) {
	defer p.stop()
	scratch := make([]byte, min(protocol.MaxArray, s.cfg.Limits.ReplayBytes, s.cfg.Limits.ReplayBudget))
	for {
		n, err := p.backend.Read(scratch)
		if n > 0 && !s.appendOutput(ctx, p, scratch[:n]) {
			return
		}
		if errors.Is(err, io.EOF) {
			s.mu.Lock()
			if s.sessions[p.sid] == p {
				p.eof = true
				p.signalLocked()
			}
			s.mu.Unlock()
			return
		}
		if err != nil {
			s.terminate(p, "backend_error")
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func (s *Server) appendOutput(ctx context.Context, p *session, data []byte) bool {
	for {
		s.mu.Lock()
		if s.sessions[p.sid] != p {
			s.mu.Unlock()
			return false
		}
		limit := min(s.cfg.Limits.ReplayBytes, s.cfg.Limits.ReplayBudget)
		capacity, ok := p.out.RequiredCapacity(len(data), limit)
		if s.pressureBlocked && capacity > p.out.Capacity() {
			ok = false
		}
		var victims []*session
		if ok {
			for s.allocated+capacity-p.out.Capacity() > s.cfg.Limits.ReplayBudget {
				victim := s.victimLocked(s.cfg.Now())
				if victim == nil {
					ok = false
					break
				}
				s.removeLocked(victim, "replay_budget")
				victims = append(victims, victim)
				if victim == p {
					break
				}
			}
		}
		if s.sessions[p.sid] != p {
			ok = false
		}
		if ok {
			before := p.out.Capacity()
			beforeBytes := p.out.Allocated()
			p.out.Append(data, capacity)
			s.allocated += p.out.Capacity() - before
			if p.out.Capacity() > before {
				s.pressureCredit -= min(s.pressureCredit, p.out.Allocated())
				s.pressureCredit += beforeBytes
			}
			p.signalLocked()
		}
		wake := p.wake
		s.mu.Unlock()
		for _, victim := range victims {
			closeSession(victim)
		}
		if ok {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-wake:
		}
	}
}

func (s *Server) terminate(p *session, reason string) {
	s.mu.Lock()
	if s.sessions[p.sid] != p {
		s.mu.Unlock()
		return
	}
	s.removeLocked(p, reason)
	s.mu.Unlock()
	closeSession(p)
}

func (s *Server) removeLocked(p *session, reason string) {
	delete(s.sessions, p.sid)
	s.allocated -= p.out.Capacity()
	s.emit(s.eventLocked(p, "session.close", reason))
	s.pressureCredit += p.out.Allocated()
	_ = p.out.Acknowledge(p.out.End())
	p.signalLocked()
}

func closeSession(p *session) {
	if p.stop != nil {
		p.stop()
	}
	if p.attached != nil {
		p.attached.stop()
	}
	_ = p.backend.Close()
}
