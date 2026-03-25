package server

import "context"

// CustomizeRequest is the protocol-layer request for the probe_customize tool.
type CustomizeRequest struct {
	Name         string
	Params       map[string]any
	DryRun       bool
	ReloadPolicy string
}

// CustomizeResult is the protocol-layer result for the probe_customize tool.
type CustomizeResult struct {
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
	NewState string `json:"newState,omitempty"`
	AuditID  string `json:"auditID,omitempty"`
}

// ObserveRequest is the protocol-layer request for the system_observe_control tool.
type ObserveRequest struct {
	ProbeName string
	Operation string
}

// ObserveResult is the protocol-layer result for the system_observe_control tool.
type ObserveResult struct {
	State       string         `json:"state,omitempty"`
	Admission   string         `json:"admission,omitempty"`
	QuotaReport map[string]any `json:"quotaReport,omitempty"`
	Reason      string         `json:"reason,omitempty"`
}

// CustomizeService defines probe customization orchestration expected by server.
type CustomizeService interface {
	Customize(ctx context.Context, req CustomizeRequest) (CustomizeResult, error)
}

// ObserveService defines probe lifecycle orchestration expected by server.
type ObserveService interface {
	Control(ctx context.Context, req ObserveRequest) (ObserveResult, error)
}

// AuditLogger records protocol-level decision summaries.
type AuditLogger interface {
	Record(ctx context.Context, e AuditEvent)
}

// Dependencies captures all runtime dependencies required by Server.
type Dependencies struct {
	Customize CustomizeService
	Observe   ObserveService
	Audit     AuditLogger
}
