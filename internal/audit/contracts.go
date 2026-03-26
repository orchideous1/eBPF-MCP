package audit

import "context"

// ProbeRequest is the common auditing input for probe-related tool requests.
type ProbeRequest struct {
	Tool      string
	ProbeName string
	Operation string
	Params    map[string]any
}

// Decision captures one auditable decision.
type Decision struct {
	Allowed bool
	Reason  string
}

// Event is a compact protocol-layer audit record.
type Event struct {
	Tool      string
	Target    string
	Accepted  bool
	Reason    string
	Decisions []Decision
}

// ResourceAuditor checks request rules against resource definitions.
type ResourceAuditor interface {
	AuditByResource(ctx context.Context, req ProbeRequest) (Decision, error)
}

// MonitorAuditor checks request rules against probe monitor/runtime constraints.
type MonitorAuditor interface {
	AuditByMonitor(ctx context.Context, req ProbeRequest) (Decision, error)
}

// Logger records protocol-level audit events.
type Logger interface {
	Record(ctx context.Context, e Event)
}
