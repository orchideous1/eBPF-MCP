package server

import "context"

// AuditEvent is a compact protocol-layer audit record.
type AuditEvent struct {
	Tool     string
	Target   string
	Accepted bool
	Reason   string
}

// NoopAuditLogger is a safe default audit sink.
type NoopAuditLogger struct{}

// Record implements AuditLogger.
func (NoopAuditLogger) Record(context.Context, AuditEvent) {}
