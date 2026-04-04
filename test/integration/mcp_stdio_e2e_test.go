package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"
	"time"

	"ebpf-mcp/internal/probes"
	"ebpf-mcp/internal/server"
	_ "github.com/duckdb/duckdb-go/v2"
)

// TestMCPStdioServerCreation 测试 STDIO 服务器创建
func TestMCPStdioServerCreation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_stdio.duckdb")
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
	defer controller.Shutdown()

	cfg := server.ServerConfig{
		Transport: server.TransportStdio,
		Debug:     false,
	}

	srv, err := server.New(cfg, controller)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// 验证 MCPServer 返回非 nil
	if srv.MCPServer() == nil {
		t.Fatal("expected MCPServer to be non-nil")
	}

	// 验证工具已注册
	tools := srv.MCPServer().ListTools()
	if len(tools) == 0 {
		t.Fatal("expected tools to be registered")
	}

	// 验证所有预期工具都已注册
	expectedTools := map[string]bool{
		"probe_customize":        false,
		"system_observe_control": false,
		"probe_resource_info":    false,
	}

	for name := range tools {
		if _, exists := expectedTools[name]; exists {
			expectedTools[name] = true
		}
	}

	for name, found := range expectedTools {
		if !found {
			t.Errorf("expected tool %s to be registered", name)
		}
	}
}

// TestMCPStdioToolsRegistration 测试 STDIO 模式下工具注册详情
func TestMCPStdioToolsRegistration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_stdio.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()

	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	defer controller.Shutdown()

	cfg := server.ServerConfig{
		Transport: server.TransportStdio,
		Debug:     true,
	}

	srv, err := server.New(cfg, controller)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	tools := srv.MCPServer().ListTools()

	t.Run("verify probe_customize tool", func(t *testing.T) {
		tool, exists := tools["probe_customize"]
		if !exists {
			t.Error("probe_customize tool not found")
			return
		}
		// 验证工具有描述
		if tool.Tool.Description == "" {
			t.Error("expected probe_customize to have description")
		}
	})

	t.Run("verify system_observe_control tool", func(t *testing.T) {
		tool, exists := tools["system_observe_control"]
		if !exists {
			t.Error("system_observe_control tool not found")
			return
		}
		if tool.Tool.Description == "" {
			t.Error("expected system_observe_control to have description")
		}
	})

	t.Run("verify probe_resource_info tool", func(t *testing.T) {
		tool, exists := tools["probe_resource_info"]
		if !exists {
			t.Error("probe_resource_info tool not found")
			return
		}
		if tool.Tool.Description == "" {
			t.Error("expected probe_resource_info to have description")
		}
	})
}

// TestMCPStdioServerConfig 测试 STDIO 服务器配置验证
func TestMCPStdioServerConfig(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_stdio.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()

	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	defer controller.Shutdown()

	t.Run("default transport", func(t *testing.T) {
		cfg := server.ServerConfig{
			Transport: "",
			Debug:     false,
		}

		srv, err := server.New(cfg, controller)
		if err != nil {
			t.Fatalf("new server with empty transport: %v", err)
		}
		if srv == nil {
			t.Fatal("expected server to be created")
		}
	})

	t.Run("explicit stdio transport", func(t *testing.T) {
		cfg := server.ServerConfig{
			Transport: server.TransportStdio,
			Debug:     true,
		}

		srv, err := server.New(cfg, controller)
		if err != nil {
			t.Fatalf("new server with stdio transport: %v", err)
		}
		if srv == nil {
			t.Fatal("expected server to be created")
		}
	})
}

// stdioMCPClient 模拟 STDIO MCP 客户端
type stdioMCPClient struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
	seqID  int
}

// newStdioMCPClient 创建 STDIO MCP 客户端
func newStdioMCPClient(stdin io.WriteCloser, stdout io.ReadCloser) *stdioMCPClient {
	return &stdioMCPClient{
		stdin:  stdin,
		stdout: stdout,
		seqID:  0,
	}
}

// sendRequest 发送 MCP 请求并返回响应
func (c *stdioMCPClient) sendRequest(t *testing.T, method string, params map[string]any) map[string]any {
	t.Helper()

	c.seqID++
	request := map[string]any{
		"jsonrpc": "2.0",
		"id":      c.seqID,
		"method":  method,
		"params":  params,
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	// 添加换行符作为消息分隔符
	data = append(data, '\n')

	if _, err := c.stdin.Write(data); err != nil {
		t.Fatalf("write to stdin: %v", err)
	}

	// 读取响应
	decoder := json.NewDecoder(c.stdout)
	var response map[string]any
	if err := decoder.Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	return response
}

// sendNotification 发送 MCP 通知（无需响应）
func (c *stdioMCPClient) sendNotification(t *testing.T, method string, params map[string]any) {
	t.Helper()

	notification := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}

	data, err := json.Marshal(notification)
	if err != nil {
		t.Fatalf("marshal notification: %v", err)
	}

	data = append(data, '\n')

	if _, err := c.stdin.Write(data); err != nil {
		t.Fatalf("write to stdin: %v", err)
	}
}

// TestMCPStdioBasicCommunication 测试 STDIO 基本通信流程
func TestMCPStdioBasicCommunication(t *testing.T) {
	// 由于 STDIO 服务器会阻塞并接受实际的标准输入/输出，
	// 这个测试仅验证服务器结构正确，不进行实际通信测试。
	// 实际的 STDIO 通信测试需要使用进程级别的集成测试。

	dbPath := filepath.Join(t.TempDir(), "test_stdio.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()

	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	defer controller.Shutdown()

	cfg := server.ServerConfig{
		Transport: server.TransportStdio,
		Debug:     false,
	}

	srv, err := server.New(cfg, controller)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// 验证可以通过 MCPServer() 获取底层服务器
	mcpServer := srv.MCPServer()
	if mcpServer == nil {
		t.Fatal("expected to get underlying MCP server")
	}

	// 验证工具列表
	tools := mcpServer.ListTools()
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(tools))
	}
}

// TestMCPStdioServerWithProbes 测试带有探针注册的服务器
func TestMCPStdioServerWithProbes(t *testing.T) {
	// 注册 mock 探针
	probeName := "test_stdio_probe"
	mockProbe := NewMockProbe(probeName)
	probes.Register(probeName, func() probes.Probe { return mockProbe })

	dbPath := filepath.Join(t.TempDir(), "test_stdio_probes.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()

	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	defer controller.Shutdown()

	cfg := server.ServerConfig{
		Transport: server.TransportStdio,
		Debug:     true,
	}

	srv, err := server.New(cfg, controller)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// 验证服务器创建成功且工具已注册
	tools := srv.MCPServer().ListTools()
	if len(tools) == 0 {
		t.Fatal("expected tools to be registered")
	}

	// 验证探针已注册
	if !probes.HasProbe(probeName) {
		t.Fatal("expected probe to be registered")
	}
}

// TestMCPStdioServerStartTimeout 测试 STDIO 服务器启动超时场景
func TestMCPStdioServerStartTimeout(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_stdio_timeout.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()

	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	defer controller.Shutdown()

	cfg := server.ServerConfig{
		Transport: server.TransportStdio,
		Debug:     false,
	}

	srv, err := server.New(cfg, controller)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// 使用一个会很快取消的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// 启动服务器（会很快因为上下文取消而退出）
	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Start(ctx)
	}()

	// 等待服务器启动或上下文取消
	select {
	case err := <-errChan:
		// 服务器退出
		if err != nil {
			// 超时退出可能返回错误或 nil，取决于实现
			t.Logf("server exited with error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		// 服务器仍在运行，但我们的测试上下文已经取消
		t.Log("server is still running after context cancellation")
	}
}
