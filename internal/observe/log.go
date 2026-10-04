package observe

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"

	"github.com/dotwaffle/sshpd/internal/requestmeta"
)

// Handler adds internal trace correlation and validated transport addresses.
type Handler struct {
	slog.Handler
}

// Logger adds context fields once, including when the daemon embeds a relay.
func Logger(logger *slog.Logger) *slog.Logger {
	if _, ok := logger.Handler().(Handler); ok {
		return logger
	}
	return slog.New(Handler{Handler: logger.Handler()})
}

// Handle omits request headers, URLs, payloads, and credentials.
func (h Handler) Handle(ctx context.Context, record slog.Record) error {
	record = record.Clone()
	span := trace.SpanContextFromContext(ctx)
	if span.IsValid() {
		record.AddAttrs(slog.String("trace_id", span.TraceID().String()), slog.String("span_id", span.SpanID().String()))
	}
	if client, ok := requestmeta.FromContext(ctx); ok {
		hasClient, hasPeer := false, false
		record.Attrs(func(attr slog.Attr) bool {
			hasClient = hasClient || attr.Key == "client_ip"
			hasPeer = hasPeer || attr.Key == "peer_ip"
			return true
		})
		if !hasClient {
			record.AddAttrs(slog.String("client_ip", client.IP))
		}
		if !hasPeer {
			record.AddAttrs(slog.String("peer_ip", client.Peer))
		}
	}
	return h.Handler.Handle(ctx, record)
}

// WithAttrs retains context enrichment on derived loggers.
func (h Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return Handler{Handler: h.Handler.WithAttrs(attrs)}
}

// WithGroup retains context enrichment within a logger group.
func (h Handler) WithGroup(name string) slog.Handler {
	return Handler{Handler: h.Handler.WithGroup(name)}
}
