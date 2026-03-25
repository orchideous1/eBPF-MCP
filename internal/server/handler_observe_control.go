package server

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

func (s *Server) handleSystemObserveControl(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.debugf("tool call received: system_observe_control")
	return s.handleSystemObserveControlArgs(ctx, req.GetArguments())
}

func (s *Server) handleSystemObserveControlArgs(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	observeReq, err := decodeObserveRequest(args)
	if err != nil {
		s.debugf("system_observe_control request decode failed: %v", err)
		return mcp.NewToolResultError(ToolError{Code: ErrorInvalidArgument, Message: err.Error()}.String()), nil
	}
	s.debugf("system_observe_control decoded: probe=%s op=%s", observeReq.ProbeName, observeReq.Operation)

	result, err := s.deps.Observe.Control(ctx, observeReq)
	if err != nil {
		mapped := mapDomainError(err)
		s.debugf("system_observe_control service rejected: %s", mapped.String())
		s.deps.Audit.Record(ctx, AuditEvent{Tool: "system_observe_control", Target: observeReq.ProbeName, Accepted: false, Reason: mapped.String()})
		return mcp.NewToolResultError(mapped.String()), nil
	}
	s.debugf("system_observe_control accepted: probe=%s state=%s admission=%s", observeReq.ProbeName, result.State, result.Admission)

	s.deps.Audit.Record(ctx, AuditEvent{Tool: "system_observe_control", Target: observeReq.ProbeName, Accepted: result.Admission == "allowed", Reason: result.Reason})
	text, err := toJSONText(result)
	if err != nil {
		return nil, fmt.Errorf("marshal observe result: %w", err)
	}
	return mcp.NewToolResultText(text), nil
}

func decodeObserveRequest(args map[string]any) (ObserveRequest, error) {
	if args == nil {
		return ObserveRequest{}, fmt.Errorf("arguments are required")
	}
	probeNameRaw, ok := args["probeName"]
	if !ok {
		return ObserveRequest{}, fmt.Errorf("probeName is required")
	}
	probeName, ok := probeNameRaw.(string)
	if !ok || probeName == "" {
		return ObserveRequest{}, fmt.Errorf("probeName must be a non-empty string")
	}
	operationRaw, ok := args["operation"]
	if !ok {
		return ObserveRequest{}, fmt.Errorf("operation is required")
	}
	operation, ok := operationRaw.(string)
	if !ok {
		return ObserveRequest{}, fmt.Errorf("operation must be a string")
	}
	switch operation {
	case "load", "unload", "status":
		return ObserveRequest{ProbeName: probeName, Operation: operation}, nil
	default:
		return ObserveRequest{}, fmt.Errorf("operation must be one of load|unload|status")
	}
}
