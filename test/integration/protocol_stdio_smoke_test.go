package integration

import (
	"context"
	"testing"

	"ebpf-mcp/internal/audit"
	"ebpf-mcp/internal/server"
	"ebpf-mcp/internal/tool"
)

type stdioCustomizeSvc struct{}

type stdioObserveSvc struct{}

func (stdioCustomizeSvc) Customize(context.Context, tool.CustomizeRequest) (tool.CustomizeResult, error) {
	return tool.CustomizeResult{Accepted: true}, nil
}

func (stdioObserveSvc) Control(context.Context, tool.ObserveRequest) (tool.ObserveResult, error) {
	return tool.ObserveResult{Admission: "allowed"}, nil
}

func TestStdioServerSmoke(t *testing.T) {
	s, err := server.New(server.ServerConfig{Transport: server.TransportStdio}, server.Dependencies{
		Customize: stdioCustomizeSvc{},
		Observe:   stdioObserveSvc{},
		Audit:     audit.NoopLogger{},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	tools := s.MCPServer().ListTools()
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools got %d", len(tools))
	}
}
