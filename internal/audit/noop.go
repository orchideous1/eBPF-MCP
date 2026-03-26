package audit

import "context"

// NoopLogger is a safe default audit sink.
type NoopLogger struct{}

// Record implements Logger.
func (NoopLogger) Record(context.Context, Event) {}
