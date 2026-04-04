package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestMCPHTTPAuthentication 测试 HTTP 认证流程
func TestMCPHTTPAuthentication(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Cleanup()

	t.Run("missing token", func(t *testing.T) {
		payload := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "probe_resource_info",
				"arguments": map[string]any{},
			},
		}
		b, _ := json.Marshal(payload)
		resp, err := http.Post(ts.HTTPServer.URL, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 got %d", resp.StatusCode)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		payload := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "probe_resource_info",
				"arguments": map[string]any{},
			},
		}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, ts.HTTPServer.URL, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer invalid-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 got %d", resp.StatusCode)
		}
	})

	t.Run("valid token", func(t *testing.T) {
		sessionID := initMCPSession(t, ts.HTTPServer.URL, ts.AuthToken)
		if sessionID == "" {
			t.Fatal("expected session ID")
		}
	})
}

// TestMCPProbeResourceInfo 测试 probe_resource_info 工具
func TestMCPProbeResourceInfo(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Cleanup()

	sessionID := initMCPSession(t, ts.HTTPServer.URL, ts.AuthToken)

	t.Run("list all probes", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 1, "probe_resource_info", map[string]any{})

		if resp.IsError() {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		result := resp.GetTextResult()
		if result == "" {
			t.Fatal("expected non-empty result")
		}

		// 验证返回的 JSON 包含 probes 和 count
		if !strings.Contains(result, "probes") {
			t.Fatalf("expected 'probes' in result, got: %s", result)
		}
		if !strings.Contains(result, "count") {
			t.Fatalf("expected 'count' in result, got: %s", result)
		}
	})

	t.Run("get specific probe", func(t *testing.T) {
		// 使用从 YAML 加载的现有探针
		probeName := "nfs_file_read"

		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 2, "probe_resource_info", map[string]any{
			"probeName": probeName,
		})

		if resp.IsError() {
			resultText := resp.GetTextResult()
			t.Fatalf("unexpected error: %s", resultText)
		}

		result := resp.GetTextResult()
		if result == "" {
			t.Fatal("expected non-empty result")
		}
	})

	t.Run("get non-existent probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 3, "probe_resource_info", map[string]any{
			"probeName": "non_existent_probe_12345",
		})

		if !resp.IsError() {
			t.Fatal("expected error for non-existent probe")
		}

		// 服务器返回 RUNTIME_FAILURE: probe not found
		resultText := resp.GetTextResult()
		if !strings.Contains(resultText, "probe not found") {
			t.Fatalf("expected 'probe not found' error, got: %s", resultText)
		}
	})
}

// TestMCPProbeLifecycle 测试探针生命周期
func TestMCPProbeLifecycle(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Cleanup()

	// 注册 mock 探针
	probeName := "test_lifecycle_probe"
	mockProbe := registerMockProbe(t, probeName)

	sessionID := initMCPSession(t, ts.HTTPServer.URL, ts.AuthToken)

	t.Run("load probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 1, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "load",
		})

		if resp.IsError() {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		result := resp.GetTextResult()
		if !strings.Contains(result, "loaded") {
			t.Fatalf("expected 'loaded' in result, got: %s", result)
		}

		// 验证探针的 Start 被调用
		if mockProbe.GetStartCalls() != 1 {
			t.Fatalf("expected Start to be called once, got %d", mockProbe.GetStartCalls())
		}
	})

	t.Run("status of loaded probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 2, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "status",
		})

		if resp.IsError() {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		result := resp.GetTextResult()
		if !strings.Contains(result, "loaded") {
			t.Fatalf("expected 'loaded' in result, got: %s", result)
		}
	})

	t.Run("unload probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 3, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "unload",
		})

		if resp.IsError() {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		result := resp.GetTextResult()
		if !strings.Contains(result, "unloaded") {
			t.Fatalf("expected 'unloaded' in result, got: %s", result)
		}

		// 验证探针的 Stop 被调用
		if mockProbe.GetStopCalls() != 1 {
			t.Fatalf("expected Stop to be called once, got %d", mockProbe.GetStopCalls())
		}
	})

	t.Run("status of unloaded probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 4, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "status",
		})

		if resp.IsError() {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		result := resp.GetTextResult()
		if !strings.Contains(result, "unloaded") {
			t.Fatalf("expected 'unloaded' in result, got: %s", result)
		}
	})
}

// TestMCPProbeCustomize 测试 probe_customize 工具
func TestMCPProbeCustomize(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Cleanup()

	// 注册并加载 mock 探针
	probeName := "test_customize_probe"
	mockProbe := registerMockProbe(t, probeName)

	sessionID := initMCPSession(t, ts.HTTPServer.URL, ts.AuthToken)

	// 先加载探针
	resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 1, "system_observe_control", map[string]any{
		"probeName": probeName,
		"operation": "load",
	})
	if resp.IsError() {
		t.Fatalf("failed to load probe: %v", resp.Error)
	}

	t.Run("customize probe params", func(t *testing.T) {
		config := map[string]any{
			"filter_pid":  uint32(1234),
			"filter_file": "*.log",
		}

		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 2, "probe_customize", map[string]any{
			"name":   probeName,
			"params": config,
		})

		if resp.IsError() {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		result := resp.GetTextResult()
		if !strings.Contains(result, "accepted") {
			t.Fatalf("expected 'accepted' in result, got: %s", result)
		}

		// 验证 Update 被调用且参数正确
		if mockProbe.GetUpdateCalls() != 1 {
			t.Fatalf("expected Update to be called once, got %d", mockProbe.GetUpdateCalls())
		}
	})

	t.Run("customize with dryRun", func(t *testing.T) {
		config := map[string]any{
			"filter_pid": uint32(5678),
		}

		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 3, "probe_customize", map[string]any{
			"name":   probeName,
			"params": config,
			"dryRun": true,
		})

		if resp.IsError() {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		result := resp.GetTextResult()
		if !strings.Contains(result, "dry run") {
			t.Fatalf("expected 'dry run' in result, got: %s", result)
		}

		// dryRun 不应该调用实际的 Update
		// Update 调用次数应该保持不变
		if mockProbe.GetUpdateCalls() != 1 {
			t.Fatalf("expected Update call count to remain 1, got %d", mockProbe.GetUpdateCalls())
		}
	})

	t.Run("customize unloaded probe", func(t *testing.T) {
		// 先卸载探针
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 4, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "unload",
		})
		if resp.IsError() {
			t.Fatalf("failed to unload probe: %v", resp.Error)
		}

		// 尝试更新未加载的探针
		resp = callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 5, "probe_customize", map[string]any{
			"name":   probeName,
			"params": map[string]any{"filter_pid": uint32(9999)},
		})

		if !resp.IsError() {
			t.Fatal("expected error for customize unloaded probe")
		}
	})
}

// TestMCPErrorScenarios 测试错误场景
func TestMCPErrorScenarios(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Cleanup()

	probeName := "test_error_probe"
	registerMockProbe(t, probeName)

	sessionID := initMCPSession(t, ts.HTTPServer.URL, ts.AuthToken)

	t.Run("invalid operation", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 1, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "restart", // 无效操作
		})

		if !resp.IsError() {
			t.Fatal("expected error for invalid operation")
		}
	})

	t.Run("missing probeName", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 2, "system_observe_control", map[string]any{
			"operation": "load",
		})

		if !resp.IsError() {
			t.Fatal("expected error for missing probeName")
		}
	})

	t.Run("missing operation", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 3, "system_observe_control", map[string]any{
			"probeName": probeName,
		})

		if !resp.IsError() {
			t.Fatal("expected error for missing operation")
		}
	})

	t.Run("double load conflict", func(t *testing.T) {
		// 第一次加载
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 4, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "load",
		})
		if resp.IsError() {
			t.Fatalf("failed to load probe: %v", resp.Error)
		}

		// 第二次加载应该失败
		resp = callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 5, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "load",
		})

		if !resp.IsError() {
			t.Fatal("expected error for double load")
		}

		// 清理
		callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 6, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "unload",
		})
	})

	t.Run("unload not loaded probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 7, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "unload",
		})

		// 探针存在但未加载，unload 会返回错误
		if !resp.IsError() {
			t.Fatal("expected error for unloading not loaded probe")
		}
	})

	t.Run("missing name in customize", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 8, "probe_customize", map[string]any{
			"params": map[string]any{"filter_pid": uint32(1234)},
		})

		if !resp.IsError() {
			t.Fatal("expected error for missing name")
		}
	})

	t.Run("missing params in customize", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 9, "probe_customize", map[string]any{
			"name": probeName,
		})

		if !resp.IsError() {
			t.Fatal("expected error for missing params")
		}
	})
}

// TestMCPEndToEndWorkflow 测试完整端到端工作流
func TestMCPEndToEndWorkflow(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Cleanup()

	// 注册 mock 探针
	probeName := "test_e2e_probe"
	mockProbe := registerMockProbe(t, probeName)

	sessionID := initMCPSession(t, ts.HTTPServer.URL, ts.AuthToken)

	// 步骤1: 获取所有探针信息
	t.Run("step 1: list probes", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 1, "probe_resource_info", map[string]any{})
		if resp.IsError() {
			t.Fatalf("failed to list probes: %v", resp.Error)
		}
	})

	// 步骤2: 加载探针
	t.Run("step 2: load probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 2, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "load",
		})
		if resp.IsError() {
			t.Fatalf("failed to load probe: %v", resp.Error)
		}
	})

	// 步骤3: 获取探针状态
	t.Run("step 3: get probe status", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 3, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "status",
		})
		if resp.IsError() {
			t.Fatalf("failed to get status: %v", resp.Error)
		}

		result := resp.GetTextResult()
		if !strings.Contains(result, "loaded") {
			t.Fatalf("expected probe to be loaded, got: %s", result)
		}
	})

	// 步骤4: 自定义探针参数
	t.Run("step 4: customize probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 4, "probe_customize", map[string]any{
			"name": probeName,
			"params": map[string]any{
				"filter_pid":  uint32(1234),
				"filter_file": "*.log",
			},
		})
		if resp.IsError() {
			t.Fatalf("failed to customize probe: %v", resp.Error)
		}
	})

	// 步骤5: 获取特定探针信息
	// 注意：mock 探针没有 metadata，所以这个步骤会失败
	// 在实际测试中，应该使用从 YAML 加载的探针
	t.Run("step 5: get specific probe info", func(t *testing.T) {
		// 使用已存在的探针来测试 probe_resource_info
		existingProbeName := "nfs_file_read"
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 5, "probe_resource_info", map[string]any{
			"probeName": existingProbeName,
		})
		if resp.IsError() {
			resultText := resp.GetTextResult()
			t.Fatalf("failed to get probe info: %s", resultText)
		}
	})

	// 步骤6: 卸载探针
	t.Run("step 6: unload probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 6, "system_observe_control", map[string]any{
			"probeName": probeName,
			"operation": "unload",
		})
		if resp.IsError() {
			t.Fatalf("failed to unload probe: %v", resp.Error)
		}
	})

	// 验证所有操作都被正确调用
	if mockProbe.GetStartCalls() != 1 {
		t.Fatalf("expected Start to be called once, got %d", mockProbe.GetStartCalls())
	}
	if mockProbe.GetStopCalls() != 1 {
		t.Fatalf("expected Stop to be called once, got %d", mockProbe.GetStopCalls())
	}
	if mockProbe.GetUpdateCalls() != 1 {
		t.Fatalf("expected Update to be called once, got %d", mockProbe.GetUpdateCalls())
	}
}

// TestMCPProbeNotFound 测试探针不存在的场景
func TestMCPProbeNotFound(t *testing.T) {
	ts := setupTestServer(t)
	defer ts.Cleanup()

	sessionID := initMCPSession(t, ts.HTTPServer.URL, ts.AuthToken)

	t.Run("load non-existent probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 1, "system_observe_control", map[string]any{
			"probeName": "non_existent_probe_xyz",
			"operation": "load",
		})

		if !resp.IsError() {
			t.Fatal("expected error for non-existent probe")
		}

		// 服务器返回 RUNTIME_FAILURE: probe not found
		resultText := resp.GetTextResult()
		if !strings.Contains(resultText, "probe not found") {
			t.Fatalf("expected 'probe not found' error, got: %s", resultText)
		}
	})

	t.Run("status of non-existent probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 2, "system_observe_control", map[string]any{
			"probeName": "non_existent_probe_xyz",
			"operation": "status",
		})

		if !resp.IsError() {
			t.Fatal("expected error for non-existent probe")
		}
	})

	t.Run("customize non-existent probe", func(t *testing.T) {
		resp := callTool(t, ts.HTTPServer.URL, ts.AuthToken, sessionID, 3, "probe_customize", map[string]any{
			"name":   "non_existent_probe_xyz",
			"params": map[string]any{"filter_pid": uint32(1234)},
		})

		if !resp.IsError() {
			t.Fatal("expected error for non-existent probe")
		}
	})
}
