package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
)

func (s *Server) handleProbeCustomize(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.debugf("tool call received: probe_customize")
	return s.handleProbeCustomizeArgs(ctx, req.GetArguments())
}

func (s *Server) handleProbeCustomizeArgs(ctx context.Context, args map[string]any) (*mcp.CallToolResult, error) {
	customizeReq, err := decodeCustomizeRequest(args)
	if err != nil {
		s.debugf("probe_customize request decode failed: %v", err)
		return mcp.NewToolResultError(ToolError{Code: ErrorInvalidArgument, Message: err.Error()}.String()), nil
	}
	s.debugf("probe_customize decoded: name=%s dryRun=%t", customizeReq.Name, customizeReq.DryRun)

	result, err := s.deps.Customize.Customize(ctx, customizeReq)
	if err != nil {
		mapped := mapDomainError(err)
		s.debugf("probe_customize service rejected: %s", mapped.String())
		s.deps.Audit.Record(ctx, AuditEvent{Tool: "probe_customize", Target: customizeReq.Name, Accepted: false, Reason: mapped.String()})
		return mcp.NewToolResultError(mapped.String()), nil
	}
	s.debugf("probe_customize accepted: name=%s state=%s", customizeReq.Name, result.NewState)

	s.deps.Audit.Record(ctx, AuditEvent{Tool: "probe_customize", Target: customizeReq.Name, Accepted: result.Accepted, Reason: result.Reason})
	text, err := toJSONText(result)
	if err != nil {
		return nil, fmt.Errorf("marshal customize result: %w", err)
	}
	return mcp.NewToolResultText(text), nil
}

func decodeCustomizeRequest(args map[string]any) (CustomizeRequest, error) {
	if args == nil {
		return CustomizeRequest{}, fmt.Errorf("arguments are required")
	}

	nameRaw, ok := args["name"]
	if !ok {
		return CustomizeRequest{}, fmt.Errorf("name is required")
	}
	name, ok := nameRaw.(string)
	if !ok || name == "" {
		return CustomizeRequest{}, fmt.Errorf("name must be a non-empty string")
	}

	paramsRaw, ok := args["params"]
	if !ok {
		return CustomizeRequest{}, fmt.Errorf("params is required")
	}
	params, ok := paramsRaw.(map[string]any)
	if !ok {
		return CustomizeRequest{}, fmt.Errorf("params must be an object")
	}

	req := CustomizeRequest{Name: name, Params: params}
	if dryRun, ok := args["dryRun"].(bool); ok {
		req.DryRun = dryRun
	}
	if reloadPolicy, ok := args["reloadPolicy"].(string); ok {
		req.ReloadPolicy = reloadPolicy
	}
	return req, nil
}

func toJSONText(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
