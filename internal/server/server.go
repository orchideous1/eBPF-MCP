package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/mark3labs/mcp-go/server"
)

// Server is the MCP protocol access entrypoint.
type Server struct {
	cfg       ServerConfig
	deps      Dependencies
	mcpServer *server.MCPServer
	logger    *log.Logger
}

// New creates a protocol server and registers all routes.
func New(cfg ServerConfig, deps Dependencies) (*Server, error) {
	if cfg.Transport == "" {
		cfg.Transport = TransportStdio
	}
	if cfg.HTTPPort == "" {
		cfg.HTTPPort = "8080"
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if deps.Customize == nil {
		return nil, fmt.Errorf("customize service is required")
	}
	if deps.Observe == nil {
		return nil, fmt.Errorf("observe service is required")
	}
	if deps.Audit == nil {
		deps.Audit = NoopAuditLogger{}
	}

	loggerFlags := log.LstdFlags
	if cfg.Debug {
		loggerFlags = log.LstdFlags | log.Lshortfile
	}
	logger := log.New(os.Stderr, "", loggerFlags)
	if cfg.Debug {
		logger.Printf("[DEBUG] debug logging enabled")
	}
	logger.Printf("[INFO] creating MCP server: name=ebpf-mcp version=0.1.0 transport=%s", cfg.Transport)

	s := &Server{
		cfg:       cfg,
		deps:      deps,
		mcpServer: server.NewMCPServer("ebpf-mcp", "0.1.0", server.WithRecovery()),
		logger:    logger,
	}
	if err := s.registerRoutes(); err != nil {
		return nil, err
	}
	s.infof("routes registered: tool_count=%d", len(s.mcpServer.ListTools()))
	return s, nil
}

// Start runs the protocol server in selected transport mode.
func (s *Server) Start(ctx context.Context) error {
	switch s.cfg.Transport {
	case TransportStdio:
		s.infof("starting MCP stdio transport")
		return server.ServeStdio(s.mcpServer)
	case TransportHTTP:
		s.infof("starting MCP HTTP transport: addr=:%s", s.cfg.HTTPPort)
		h, err := s.newHTTPHandler()
		if err != nil {
			return err
		}

		httpServer := &http.Server{Addr: ":" + s.cfg.HTTPPort, Handler: h}
		errCh := make(chan error, 1)

		go func() {
			s.debugf("http server listen begin")
			errCh <- httpServer.ListenAndServe()
		}()

		select {
		case <-ctx.Done():
			s.infof("shutdown signal received, stopping HTTP server")
			shutdownErr := httpServer.Shutdown(context.Background())
			if shutdownErr != nil {
				return shutdownErr
			}
			return nil
		case err := <-errCh:
			if err == nil || errors.Is(err, http.ErrServerClosed) {
				s.infof("http server stopped")
				return nil
			}
			s.infof("http server stopped with error: %v", err)
			return err
		}
	default:
		return fmt.Errorf("unsupported transport %q", s.cfg.Transport)
	}
}

// newHTTPHandler builds the HTTP chain for MCP requests.
func (s *Server) newHTTPHandler() (http.Handler, error) {
	if s.cfg.AuthToken == "" {
		return nil, fmt.Errorf("auth token is required")
	}
	base := server.NewStreamableHTTPServer(s.mcpServer)
	s.debugf("building HTTP handler with bearer auth middleware")
	return bearerAuthMiddlewareWithLogger(s.cfg.AuthToken, base, s.logger, s.cfg.Debug), nil
}

// MCPServer returns the underlying server instance for testing.
func (s *Server) MCPServer() *server.MCPServer {
	return s.mcpServer
}

// MCPServerHTTPHandlerForTest exposes the HTTP handler for integration testing.
func (s *Server) MCPServerHTTPHandlerForTest() (http.Handler, error) {
	return s.newHTTPHandler()
}
