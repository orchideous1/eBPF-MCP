package server

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
)

func (s *Server) registerRoutes() error {
	s.debugf("registering tool: probe_customize")
	s.mcpServer.AddTool(buildProbeCustomizeTool(), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return s.handleProbeCustomize(ctx, req)
	})

	s.debugf("registering tool: system_observe_control")
	s.mcpServer.AddTool(buildSystemObserveControlTool(), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return s.handleSystemObserveControl(ctx, req)
	})

	s.debugf("route registration completed")
	return nil
}

func buildProbeCustomizeTool() mcp.Tool {
	return mcp.NewTool(
		"probe_customize",
		mcp.WithDescription("Customize probe runtime parameters."),
		mcp.WithString("name", mcp.Required()),
		mcp.WithObject("params", mcp.Required()),
		mcp.WithBoolean("dryRun"),
		mcp.WithString("reloadPolicy"),
	)
}

func buildSystemObserveControlTool() mcp.Tool {
	return mcp.NewTool(
		"system_observe_control",
		mcp.WithDescription("Control probe lifecycle operations."),
		mcp.WithString("probeName", mcp.Required()),
		mcp.WithString("operation", mcp.Required(), mcp.Enum("load", "unload", "status")),
	)
}
