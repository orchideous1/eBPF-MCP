package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"ebpf-mcp/internal/logx"
	"ebpf-mcp/internal/probes"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Server is the MCP protocol access entrypoint.
type Server struct {
	cfg        ServerConfig
	controller *probes.Controller
	mcpServer  *server.MCPServer
	logger     *logx.Logger
}

// New creates a protocol server and registers all tools.
func New(cfg ServerConfig, controller *probes.Controller) (*Server, error) {
	if cfg.HTTPPort == "" {
		cfg.HTTPPort = "8080"
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if controller == nil {
		return nil, logx.ErrControllerRequired
	}

	logger, err := logx.NewRunLogger(cfg.Debug, logx.DetectScenario("server_"+cfg.Transport))
	if err != nil {
		return nil, logx.Wrap(err, "create logger")
	}
	logger.Infof("creating MCP server: name=ebpf-mcp version=0.1.0 transport=%s", cfg.Transport)
	if cfg.Debug {
		logger.Debugf("debug logging enabled")
	}

	s := &Server{
		cfg:        cfg,
		controller: controller,
		mcpServer:  server.NewMCPServer("ebpf-mcp", "0.1.0", server.WithRecovery()),
		logger:     logger,
	}
	s.registerTools()
	s.logger.Infof("tools registered: tool_count=%d", len(s.mcpServer.ListTools()))
	return s, nil
}

// Start runs the protocol server in selected transport mode.
func (s *Server) Start(ctx context.Context) error {
	switch s.cfg.Transport {
	case TransportStdio:
		s.logger.Infof("starting MCP stdio transport")
		return server.ServeStdio(s.mcpServer)
	case TransportHTTP:
		s.logger.Infof("starting MCP HTTP transport: addr=:%s", s.cfg.HTTPPort)
		h, err := s.newHTTPHandler()
		if err != nil {
			return err
		}

		httpServer := &http.Server{Addr: ":" + s.cfg.HTTPPort, Handler: h}
		errCh := make(chan error, 1)

		go func() {
			s.logger.Debugf("http server listen begin")
			errCh <- httpServer.ListenAndServe()
		}()

		select {
		case <-ctx.Done():
			s.logger.Infof("shutdown signal received, stopping HTTP server")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			shutdownErr := httpServer.Shutdown(shutdownCtx)
			if shutdownErr != nil {
				s.logger.Errorf("HTTP server shutdown error: %v", shutdownErr)
				return shutdownErr
			}
			s.logger.Infof("HTTP server stopped successfully")
			return nil
		case err := <-errCh:
			if err == nil || errors.Is(err, http.ErrServerClosed) {
				s.logger.Infof("http server stopped")
				return nil
			}
			s.logger.Errorf("http server stopped with error: %v", err)
			return err
		}
	default:
		return logx.Wrapf(logx.ErrUnsupportedTransport, "unsupported transport %q", s.cfg.Transport)
	}
}

// newHTTPHandler builds the HTTP chain for MCP requests.
func (s *Server) newHTTPHandler() (http.Handler, error) {
	if s.cfg.AuthToken == "" {
		return nil, logx.ErrAuthTokenRequired
	}
	base := server.NewStreamableHTTPServer(s.mcpServer)
	s.logger.Debugf("building HTTP handler with bearer auth middleware")
	return bearerAuthMiddlewareWithLogger(s.cfg.AuthToken, base, s.logger.StdLogger(), s.cfg.Debug), nil
}

// MCPServer returns the underlying server instance for testing.
func (s *Server) MCPServer() *server.MCPServer {
	return s.mcpServer
}

// MCPServerHTTPHandlerForTest exposes the HTTP handler for integration testing.
func (s *Server) MCPServerHTTPHandlerForTest() (http.Handler, error) {
	return s.newHTTPHandler()
}

// registerTools registers all MCP tools directly.
func (s *Server) registerTools() {
	s.logger.Debugf("registering tool: probe_customize")
	s.mcpServer.AddTool(buildProbeCustomizeTool(), s.handleProbeCustomize)

	s.logger.Debugf("registering tool: system_observe_control")
	s.mcpServer.AddTool(buildSystemObserveControlTool(), s.handleSystemObserveControl)

	s.logger.Debugf("registering tool: probe_resource_info")
	s.mcpServer.AddTool(buildProbeResourceInfoTool(), s.handleProbeResourceInfo)

	s.logger.Debugf("tool registration completed")
}

// buildProbeCustomizeTool defines the probe_customize tool schema.
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

// buildSystemObserveControlTool defines the system_observe_control tool schema.
func buildSystemObserveControlTool() mcp.Tool {
	return mcp.NewTool(
		"system_observe_control",
		mcp.WithDescription("Control probe lifecycle operations."),
		mcp.WithString("probeName", mcp.Required()),
		mcp.WithString("operation", mcp.Required(), mcp.Enum("load", "unload", "status")),
	)
}

// buildProbeResourceInfoTool defines the probe_resource_info tool schema.
func buildProbeResourceInfoTool() mcp.Tool {
	return mcp.NewTool(
		"probe_resource_info",
		mcp.WithDescription("Get probe resource information including metadata and runtime status."),
		mcp.WithString("probeName", mcp.Description("Specific probe ID to query. If empty, returns all probes.")),
	)
}

// handleProbeCustomize handles probe customization requests.
func (s *Server) handleProbeCustomize(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debugf("tool call received: probe_customize")

	args := req.GetArguments()
	if args == nil {
		return mcp.NewToolResultError("arguments are required"), nil
	}

	name, ok := args["name"].(string)
	if !ok || name == "" {
		return mcp.NewToolResultError("name must be a non-empty string"), nil
	}

	params, ok := args["params"].(map[string]any)
	if !ok {
		return mcp.NewToolResultError("params must be an object"), nil
	}

	dryRun, _ := args["dryRun"].(bool)

	s.logger.Debugf("probe_customize decoded: name=%s dryRun=%t", name, dryRun)

	if dryRun {
		result := map[string]any{"accepted": true, "reason": "dry run", "newState": "unchanged"}
		return newJSONResult(result)
	}

	status, err := s.controller.Update(name, params)
	if err != nil {
		mapped := logx.MapDomainError(err)
		s.logger.LogToolError("probe_customize failed", mapped)
		return mcp.NewToolResultError(mapped.String()), nil
	}

	s.logger.Debugf("probe_customize accepted: name=%s state=%s", name, status.State)

	result := map[string]any{"accepted": true, "newState": status.State}
	return newJSONResult(result)
}

// handleSystemObserveControl handles probe lifecycle operation requests.
func (s *Server) handleSystemObserveControl(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debugf("tool call received: system_observe_control")

	args := req.GetArguments()
	if args == nil {
		return mcp.NewToolResultError("arguments are required"), nil
	}

	probeName, ok := args["probeName"].(string)
	if !ok || probeName == "" {
		return mcp.NewToolResultError("probeName must be a non-empty string"), nil
	}

	operation, ok := args["operation"].(string)
	if !ok {
		return mcp.NewToolResultError("operation must be a string"), nil
	}

	s.logger.Debugf("system_observe_control decoded: probe=%s op=%s", probeName, operation)

	var status probes.Status
	var err error

	switch operation {
	case "load":
		status, err = s.controller.Load(ctx, probeName)
	case "unload":
		status, err = s.controller.Unload(probeName)
	case "status":
		status, err = s.controller.Status(probeName)
	default:
		return mcp.NewToolResultError("operation must be one of load|unload|status"), nil
	}

	if err != nil {
		mapped := logx.MapDomainError(err)
		s.logger.LogToolError("system_observe_control failed", mapped)
		return mcp.NewToolResultError(mapped.String()), nil
	}

	s.logger.Debugf("system_observe_control accepted: probe=%s state=%s", probeName, status.State)

	result := map[string]any{
		"state":     status.State,
		"admission": "allowed",
	}
	if operation == "status" {
		report := map[string]any{"loaded": status.Loaded}
		if status.LastError != "" {
			report["lastError"] = status.LastError
		}
		result["quotaReport"] = report
	}

	return newJSONResult(result)
}

// handleProbeResourceInfo handles probe resource information requests.
func (s *Server) handleProbeResourceInfo(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s.logger.Debugf("tool call received: probe_resource_info")

	args := req.GetArguments()
	if args == nil {
		args = make(map[string]any)
	}

	probeName, _ := args["probeName"].(string)

	// 如果指定了具体的探针名称，返回单个探针信息
	if probeName != "" {
		s.logger.Debugf("probe_resource_info: querying single probe=%s", probeName)

		info, err := s.controller.GetProbeInfo(probeName)
		if err != nil {
			mapped := logx.MapDomainError(err)
			s.logger.LogToolError("probe_resource_info failed", mapped)
			return mcp.NewToolResultError(mapped.String()), nil
		}

		return newJSONResult(info)
	}

	// 否则返回所有探针信息
	s.logger.Debugf("probe_resource_info: querying all probes")

	infos := s.controller.ListProbeInfos()
	return newJSONResult(map[string]any{
		"probes": infos,
		"count":  len(infos),
	})
}

// newJSONResult creates a tool result with JSON-encoded value.
func newJSONResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, logx.Wrap(err, "marshal result")
	}
	return mcp.NewToolResultText(string(b)), nil
}
