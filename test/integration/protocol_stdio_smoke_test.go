package integration

import (
	"context"
	"testing"

	"ebpf-mcp/internal/server"
)

type stdioCustomizeSvc struct{}

type stdioObserveSvc struct{}

func (stdioCustomizeSvc) Customize(context.Context, server.CustomizeRequest) (server.CustomizeResult, error) {
	return server.CustomizeResult{Accepted: true}, nil
}

func (stdioObserveSvc) Control(context.Context, server.ObserveRequest) (server.ObserveResult, error) {
	return server.ObserveResult{Admission: "allowed"}, nil
}

func TestStdioServerSmoke(t *testing.T) {
	s, err := server.New(server.ServerConfig{Transport: server.TransportStdio}, server.Dependencies{
		Customize: stdioCustomizeSvc{},
		Observe:   stdioObserveSvc{},
		Audit:     server.NoopAuditLogger{},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	tools := s.MCPServer().ListTools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools got %d", len(tools))
	}
}
