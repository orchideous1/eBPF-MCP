package integration

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"ebpf-mcp/internal/probes"
	"ebpf-mcp/internal/server"
	_ "github.com/duckdb/duckdb-go/v2"
)

// testServer 封装测试服务器和控制器
type testServer struct {
	Server     *server.Server
	Controller *probes.Controller
	DB         *sql.DB
	HTTPServer *httptest.Server
	AuthToken  string
}

// findRepoRoot 查找仓库根目录
func findRepoRoot() (string, error) {
	// 从当前目录向上查找 go.mod
	wd, err := filepath.Abs(".")
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", os.ErrNotExist
		}
		wd = parent
	}
}

// setupTestServer 创建测试服务器实例（HTTP 模式）
func setupTestServer(t *testing.T) *testServer {
	t.Helper()

	// 加载探针元数据
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Logf("warning: failed to find repo root: %v", err)
	} else {
		if err := probes.LoadProbesFromYAML(repoRoot); err != nil {
			t.Logf("warning: failed to load probe YAML configs: %v", err)
		}
	}

	dbPath := filepath.Join(t.TempDir(), "test.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Fatalf("ping duckdb: %v", err)
	}

	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}

	token := "test-token"
	cfg := server.ServerConfig{
		Transport: server.TransportHTTP,
		HTTPPort:  "18080",
		AuthToken: token,
		Debug:     false,
	}

	srv, err := server.New(cfg, controller)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	handler, err := srv.MCPServerHTTPHandlerForTest()
	if err != nil {
		t.Fatalf("build http handler: %v", err)
	}

	return &testServer{
		Server:     srv,
		Controller: controller,
		DB:         db,
		HTTPServer: httptest.NewServer(handler),
		AuthToken:  token,
	}
}

// setupTestServerWithConfig 创建带自定义配置的测试服务器
func setupTestServerWithConfig(t *testing.T, cfg server.ServerConfig) *testServer {
	t.Helper()

	// 加载探针元数据（如果尚未加载）
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Logf("warning: failed to find repo root: %v", err)
	} else {
		// 只有在 registry 为空时才加载
		if len(probes.ListProbes()) == 0 {
			if err := probes.LoadProbesFromYAML(repoRoot); err != nil {
				t.Logf("warning: failed to load probe YAML configs: %v", err)
			}
		}
	}

	dbPath := filepath.Join(t.TempDir(), "test.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Fatalf("ping duckdb: %v", err)
	}

	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}

	srv, err := server.New(cfg, controller)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	handler, err := srv.MCPServerHTTPHandlerForTest()
	if err != nil {
		t.Fatalf("build http handler: %v", err)
	}

	token := cfg.AuthToken
	if token == "" {
		token = "test-token"
	}

	return &testServer{
		Server:     srv,
		Controller: controller,
		DB:         db,
		HTTPServer: httptest.NewServer(handler),
		AuthToken:  token,
	}
}

// Cleanup 清理测试资源
func (ts *testServer) Cleanup() {
	if ts.Controller != nil {
		ts.Controller.Shutdown()
	}
	if ts.DB != nil {
		ts.DB.Close()
	}
	if ts.HTTPServer != nil {
		ts.HTTPServer.Close()
	}
}

// initMCPSession 初始化 MCP HTTP session
// 返回 session ID 用于后续请求
func initMCPSession(t *testing.T, baseURL, token string) string {
	t.Helper()

	// 发送 initialize 请求
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

	// 发送 notifications/initialized 通知
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

// callTool 调用 MCP 工具并返回响应
func callTool(t *testing.T, baseURL, token, sessionID string, id int, toolName string, arguments map[string]any) *mcpResponse {
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
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call tool %s: %v", toolName, err)
	}
	defer resp.Body.Close()

	return parseMCPResponse(t, resp)
}

// mcpResponse 封装 MCP 响应
type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  *callToolResult `json:"result"`
	Error   *mcpError       `json:"error"`
}

// mcpError 封装 MCP 错误
type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// callToolResult 对应 MCP 的 CallToolResult
type callToolResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// content 对应 MCP 的内容结构
type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// parseMCPResponse 解析 MCP 响应
func parseMCPResponse(t *testing.T, resp *http.Response) *mcpResponse {
	t.Helper()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	var mcpResp mcpResponse
	if err := json.Unmarshal(raw, &mcpResp); err != nil {
		t.Fatalf("unmarshal response: %v, body=%s", err, string(raw))
	}

	return &mcpResp
}

// IsError 检查响应是否包含错误
func (r *mcpResponse) IsError() bool {
	// MCP 协议中工具错误放在 result 中，isError 设为 true
	if r.Result != nil && r.Result.IsError {
		return true
	}
	// 协议级别的错误
	return r.Error != nil
}

// GetTextResult 获取文本类型的结果内容
func (r *mcpResponse) GetTextResult() string {
	if r.Result == nil {
		return ""
	}

	// 拼接所有文本内容
	var text string
	for _, c := range r.Result.Content {
		if c.Type == "text" {
			text += c.Text
		}
	}
	return text
}

// registerMockProbe 注册 Mock 探针到 registry
func registerMockProbe(t *testing.T, name string) *MockProbe {
	t.Helper()

	mockProbe := NewMockProbe(name)
	probes.Register(name, func() probes.Probe { return mockProbe })
	return mockProbe
}

// registerMockProbeWithMetadata 注册带元数据的 Mock 探针
func registerMockProbeWithMetadata(t *testing.T, name string, metadata probes.ProbeMetadata) *MockProbe {
	t.Helper()

	mockProbe := NewMockProbe(name)
	// 由于 BaseProbe 的 metadata 是嵌入的，我们需要通过继承的方式来设置
	// 这里我们直接使用探针名称作为类型
	probes.Register(name, func() probes.Probe { return mockProbe })
	return mockProbe
}
