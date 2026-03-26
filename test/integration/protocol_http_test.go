package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ebpf-mcp/internal/audit"
	"ebpf-mcp/internal/server"
	"ebpf-mcp/internal/tool"
)

type customizeSvc struct{}

type observeSvc struct{}

func (customizeSvc) Customize(context.Context, tool.CustomizeRequest) (tool.CustomizeResult, error) {
	return tool.CustomizeResult{Accepted: true, NewState: "loaded"}, nil
}

func (observeSvc) Control(context.Context, tool.ObserveRequest) (tool.ObserveResult, error) {
	return tool.ObserveResult{State: "loaded", Admission: "allowed"}, nil
}

func TestHTTPProtocolFlow(t *testing.T) {
	s, err := server.New(server.ServerConfig{Transport: server.TransportHTTP, HTTPPort: "8080", AuthToken: "t1"}, server.Dependencies{
		Customize: customizeSvc{},
		Observe:   observeSvc{},
		Audit:     audit.NoopLogger{},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	h, err := s.MCPServerHTTPHandlerForTest()
	if err != nil {
		t.Fatalf("build http handler: %v", err)
	}
	httpSrv := httptest.NewServer(h)
	defer httpSrv.Close()

	t.Run("missing token", func(t *testing.T) {
		payload := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name": "probe_customize",
				"arguments": map[string]any{
					"name":   "vfs-nfs-file-read",
					"params": map[string]any{"filter_pid": 1},
				},
			},
		}
		b, _ := json.Marshal(payload)
		resp, err := http.Post(httpSrv.URL, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 got %d", resp.StatusCode)
		}
	})

	t.Run("valid token", func(t *testing.T) {
		payload := map[string]any{
			"jsonrpc": "2.0",
			"id":      2,
			"method":  "tools/call",
			"params": map[string]any{
				"name": "system_observe_control",
				"arguments": map[string]any{
					"probeName": "vfs-nfs-file-read",
					"operation": "status",
				},
			},
		}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, httpSrv.URL, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer t1")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Fatalf("expected authenticated request to pass middleware")
		}
	})
}
