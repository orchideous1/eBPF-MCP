package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"ebpf-mcp/internal/probes"
	"ebpf-mcp/internal/server"
	_ "github.com/duckdb/duckdb-go/v2"
)

var integrationProbeSeq atomic.Uint64

type integrationProbe struct {
	name       string
	startCalls atomic.Int32
	stopCalls  atomic.Int32
}

func (p *integrationProbe) Name() string {
	return p.name
}

func (p *integrationProbe) Start(context.Context, *sql.DB) error {
	p.startCalls.Add(1)
	return nil
}

func (p *integrationProbe) Stop() error {
	p.stopCalls.Add(1)
	return nil
}

func (p *integrationProbe) Update(map[string]interface{}) error {
	return nil
}

func TestMCPObserveControlLoadFlow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "mcp-observe-flow.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("ping duckdb: %v", err)
	}

	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	defer func() {
		if err := controller.Shutdown(); err != nil {
			t.Fatalf("shutdown controller: %v", err)
		}
	}()

	probeName := fmt.Sprintf("integration_probe_%d", integrationProbeSeq.Add(1))
	testProbe := &integrationProbe{name: probeName}
	probes.Register(probeName, func() probes.Probe { return testProbe })

	if !probes.HasProbe(probeName) {
		t.Fatalf("probe should be registered: %s", probeName)
	}

	probeServices, err := server.NewProbeServices(controller)
	if err != nil {
		t.Fatalf("new probe services: %v", err)
	}

	s, err := server.New(server.ServerConfig{
		Transport: server.TransportHTTP,
		HTTPPort:  "18080",
		AuthToken: "test-token",
	}, server.Dependencies{
		Customize: probeServices,
		Observe:   probeServices,
		Audit:     server.NoopAuditLogger{},
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
	sessionID := initMCPSession(t, httpSrv.URL, "test-token")

	invalidBody := callTool(t, httpSrv.URL, "test-token", sessionID, 1, "system_observe_control", map[string]any{
		"probeName": probeName,
		"operation": "restart",
	})
	if !strings.Contains(invalidBody, string(server.ErrorInvalidArgument)) {
		t.Fatalf("expected invalid argument in response, got: %s", invalidBody)
	}

	loadBody := callTool(t, httpSrv.URL, "test-token", sessionID, 2, "system_observe_control", map[string]any{
		"probeName": probeName,
		"operation": "load",
	})
	if !strings.Contains(loadBody, "loaded") {
		t.Fatalf("expected loaded state in response, got: %s", loadBody)
	}

	loadedStatus, err := controller.Status(probeName)
	if err != nil {
		t.Fatalf("controller status after load: %v", err)
	}
	if !loadedStatus.Loaded || loadedStatus.State != "loaded" {
		t.Fatalf("unexpected loaded status: %+v", loadedStatus)
	}

	statusBody := callTool(t, httpSrv.URL, "test-token", sessionID, 3, "system_observe_control", map[string]any{
		"probeName": probeName,
		"operation": "status",
	})
	if !strings.Contains(statusBody, "\\\"loaded\\\":true") && !strings.Contains(statusBody, "\"loaded\":true") {
		t.Fatalf("expected loaded=true report in status response, got: %s", statusBody)
	}

	unloadBody := callTool(t, httpSrv.URL, "test-token", sessionID, 4, "system_observe_control", map[string]any{
		"probeName": probeName,
		"operation": "unload",
	})
	if !strings.Contains(unloadBody, "unloaded") {
		t.Fatalf("expected unloaded state in response, got: %s", unloadBody)
	}

	unloadedStatus, err := controller.Status(probeName)
	if err != nil {
		t.Fatalf("controller status after unload: %v", err)
	}
	if unloadedStatus.Loaded || unloadedStatus.State != "unloaded" {
		t.Fatalf("unexpected unloaded status: %+v", unloadedStatus)
	}

	if testProbe.startCalls.Load() != 1 {
		t.Fatalf("expected Start to be called once, got %d", testProbe.startCalls.Load())
	}
	if testProbe.stopCalls.Load() != 1 {
		t.Fatalf("expected Stop to be called once, got %d", testProbe.stopCalls.Load())
	}
}

func initMCPSession(t *testing.T, baseURL, token string) string {
	t.Helper()

	initializePayload := map[string]any{
		"jsonrpc": "2.0",
		"id":      0,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    "integration-test-client",
				"version": "1.0.0",
			},
		},
	}

	body, err := json.Marshal(initializePayload)
	if err != nil {
		t.Fatalf("marshal initialize payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new initialize request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("initialize request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected initialize status %d, body=%s", resp.StatusCode, string(raw))
	}

	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		t.Fatalf("missing Mcp-Session-Id in initialize response")
	}

	initializedPayload := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]any{},
	}
	body, err = json.Marshal(initializedPayload)
	if err != nil {
		t.Fatalf("marshal initialized notification: %v", err)
	}

	initializedReq, err := http.NewRequest(http.MethodPost, baseURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new initialized notification request: %v", err)
	}
	initializedReq.Header.Set("Authorization", "Bearer "+token)
	initializedReq.Header.Set("Content-Type", "application/json")
	initializedReq.Header.Set("Mcp-Session-Id", sessionID)

	initializedResp, err := http.DefaultClient.Do(initializedReq)
	if err != nil {
		t.Fatalf("initialized notification request: %v", err)
	}
	defer initializedResp.Body.Close()

	if initializedResp.StatusCode != http.StatusAccepted {
		raw, _ := io.ReadAll(initializedResp.Body)
		t.Fatalf("unexpected initialized notification status %d, body=%s", initializedResp.StatusCode, string(raw))
	}

	return sessionID
}

func callTool(t *testing.T, baseURL, token, sessionID string, id int, toolName string, arguments map[string]any) string {
	t.Helper()

	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      toolName,
			"arguments": arguments,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Session-Id", sessionID)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call tool %s: %v", toolName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected http status %d, body=%s", resp.StatusCode, string(raw))
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	return string(raw)
}
