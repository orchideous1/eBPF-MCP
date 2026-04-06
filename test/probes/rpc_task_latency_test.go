//go:build linux

package probes

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	_ "ebpf-mcp/ebpf/RPC/rpc_task_latency"
	"ebpf-mcp/internal/logx"
	"ebpf-mcp/internal/probes"
)

// TestRPCTaskLatencyProbe_Registration 测试探针注册
// 验证 rpc_task_latency 探针已正确注册到全局注册表
func TestRPCTaskLatencyProbe_Registration(t *testing.T) {
	// 验证探针已注册
	if !probes.HasProbe("rpc_task_latency") {
		t.Fatal("rpc_task_latency probe should be registered")
	}

	// 验证可以通过工厂创建实例
	probe, ok := probes.GetProbe("rpc_task_latency")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	if probe.Name() != "rpc_task_latency" {
		t.Fatalf("expected name 'rpc_task_latency', got '%s'", probe.Name())
	}

	// 验证元数据
	meta := probe.GetMetadata()
	if meta.Type != "rpc_task_latency" {
		t.Fatalf("expected Type 'rpc_task_latency', got '%s'", meta.Type)
	}
	if meta.Title == "" {
		t.Fatal("metadata Title should not be empty")
	}
	if meta.Layer != "RPC" {
		t.Fatalf("expected Layer 'RPC', got '%s'", meta.Layer)
	}

	// 验证参数定义
	if len(meta.Params) < 2 {
		t.Fatalf("expected at least 2 params, got %d", len(meta.Params))
	}

	paramNames := make(map[string]bool)
	for _, param := range meta.Params {
		paramNames[param.Name] = true
	}

	// 验证期望的参数存在
	expectedParams := []string{"filter_pid", "filter_comm"}
	for _, name := range expectedParams {
		if !paramNames[name] {
			t.Errorf("expected param '%s' not found", name)
		}
	}

	// 验证输出字段
	if len(meta.Outputs.Fields) == 0 {
		t.Fatal("metadata Outputs.Fields should not be empty")
	}

	outputNames := make(map[string]bool)
	for _, field := range meta.Outputs.Fields {
		outputNames[field.Name] = true
	}

	expectedOutputs := []string{"pid", "xid", "proc_name", "latency", "start_timestamp", "status"}
	for _, name := range expectedOutputs {
		if !outputNames[name] {
			t.Errorf("expected output field '%s' not found", name)
		}
	}
}

// TestRPCTaskLatencyProbe_ControllerLifecycle 测试 Controller 生命周期管理
// 验证探针的加载、状态查询、更新、卸载完整流程
func TestRPCTaskLatencyProbe_ControllerLifecycle(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	db := openTestDB(t)
	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	defer controller.Shutdown()

	ctx := context.Background()

	// 1. 测试加载探针
	t.Log("Step 1: 加载探针")
	status, err := controller.Load(ctx, "rpc_task_latency")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	if !status.Loaded {
		t.Fatal("probe should be loaded after Load()")
	}
	if status.State != "loaded" {
		t.Fatalf("expected state 'loaded', got '%s'", status.State)
	}

	// 2. 测试重复加载（应该失败）
	t.Log("Step 2: 验证重复加载返回错误")
	_, err = controller.Load(ctx, "rpc_task_latency")
	if !errors.Is(err, logx.ErrProbeAlreadyLoaded) {
		t.Fatalf("expected ErrProbeAlreadyLoaded, got: %v", err)
	}

	// 3. 测试查询状态
	t.Log("Step 3: 查询探针状态")
	status, err = controller.Status("rpc_task_latency")
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}
	if !status.Loaded {
		t.Fatal("probe should be loaded")
	}

	// 4. 测试更新配置（宏变量）
	t.Log("Step 4: 更新宏变量配置")
	status, err = controller.Update("rpc_task_latency", map[string]any{
		"filter_pid":  uint32(1234),
		"filter_comm": "nfs",
	})
	if err != nil {
		t.Fatalf("failed to update probe: %v", err)
	}
	if status.State != "loaded" {
		t.Fatalf("expected state 'loaded' after update, got '%s'", status.State)
	}

	// 5. 测试卸载探针
	t.Log("Step 5: 卸载探针")
	status, err = controller.Unload("rpc_task_latency")
	if err != nil {
		t.Fatalf("failed to unload probe: %v", err)
	}
	if status.Loaded {
		t.Fatal("probe should not be loaded after Unload()")
	}
	if status.State != "unloaded" {
		t.Fatalf("expected state 'unloaded', got '%s'", status.State)
	}

	// 6. 测试重复卸载（应该失败）
	t.Log("Step 6: 验证重复卸载返回错误")
	_, err = controller.Unload("rpc_task_latency")
	if !errors.Is(err, logx.ErrProbeNotLoaded) {
		t.Fatalf("expected ErrProbeNotLoaded, got: %v", err)
	}
}

// TestRPCTaskLatencyProbe_MacroVariables 测试宏变量更新
func TestRPCTaskLatencyProbe_MacroVariables(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	db := openTestDB(t)
	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	defer controller.Shutdown()

	ctx := context.Background()

	// 加载探针
	_, err = controller.Load(ctx, "rpc_task_latency")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	defer controller.Unload("rpc_task_latency")

	// 测试各种宏变量更新
	testCases := []struct {
		name   string
		config map[string]any
	}{
		{
			name: "更新 filter_pid",
			config: map[string]any{
				"filter_pid": uint32(1234),
			},
		},
		{
			name: "更新 filter_comm",
			config: map[string]any{
				"filter_comm": "nfs",
			},
		},
		{
			name: "同时更新多个变量",
			config: map[string]any{
				"filter_pid":  uint32(5678),
				"filter_comm": "rpcbind",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status, err := controller.Update("rpc_task_latency", tc.config)
			if err != nil {
				t.Fatalf("failed to update macro variables: %v", err)
			}
			if status.State != "loaded" {
				t.Fatalf("expected state 'loaded', got '%s'", status.State)
			}
			t.Logf("%s 成功", tc.name)
		})
	}

	// 测试无效参数
	t.Log("测试无效参数类型...")
	_, err = controller.Update("rpc_task_latency", map[string]any{
		"filter_pid": "invalid_string",
	})
	if err == nil {
		t.Fatal("expected error for invalid filter_pid type")
	}
	t.Logf("无效参数正确返回错误: %v", err)
}

// TestRPCTaskLatencyProbe_FastStop 验证探针能快速停止（< 500ms）
func TestRPCTaskLatencyProbe_FastStop(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	db := openTestDB(t)
	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	defer controller.Shutdown()

	ctx := context.Background()

	t.Log("加载探针...")
	_, err = controller.Load(ctx, "rpc_task_latency")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}

	// 让探针运行一小段时间
	time.Sleep(100 * time.Millisecond)

	t.Log("停止探针...")
	start := time.Now()

	// 使用带超时的 channel 来强制兜底
	type result struct {
		status probes.Status
		err    error
	}
	done := make(chan result, 1)

	go func() {
		status, err := controller.Unload("rpc_task_latency")
		done <- result{status, err}
	}()

	var status probes.Status
	select {
	case res := <-done:
		status = res.status
		err = res.err
	case <-time.After(5 * time.Second):
		t.Fatalf("Unload timed out after 5s - possible deadlock in probe stop")
	}

	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("failed to unload probe: %v", err)
	}
	if status.Loaded {
		t.Fatal("probe should be unloaded")
	}

	t.Logf("停止耗时: %v", elapsed)

	// 验证停止时间 < 500ms
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Stop took too long: %v (expected < 500ms)", elapsed)
	}

	t.Log("✓ 快速停止测试通过")
}

// TestRPCTaskLatencyProbe_MetadataIntegrity 测试元数据完整性
func TestRPCTaskLatencyProbe_MetadataIntegrity(t *testing.T) {
	probe, ok := probes.GetProbe("rpc_task_latency")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	meta := probe.GetMetadata()

	// 验证必需字段
	tests := []struct {
		name  string
		value string
	}{
		{"Type", meta.Type},
		{"Title", meta.Title},
		{"Layer", meta.Layer},
		{"Level", meta.Level},
		{"Scene", meta.Scene},
		{"Risks", meta.Risks},
	}

	for _, tt := range tests {
		if tt.value == "" {
			t.Errorf("metadata %s should not be empty", tt.name)
		}
	}

	// 验证 Entrypoints
	if len(meta.Entrypoints) == 0 {
		t.Error("metadata Entrypoints should not be empty")
	}

	// 验证 Params
	if len(meta.Params) == 0 {
		t.Error("metadata Params should not be empty")
	}

	for _, param := range meta.Params {
		if param.Name == "" {
			t.Error("param name should not be empty")
		}
		if param.Type == "" {
			t.Error("param type should not be empty")
		}
		if param.Description == "" {
			t.Error("param description should not be empty")
		}
	}

	// 验证 Outputs
	if len(meta.Outputs.Fields) == 0 {
		t.Error("metadata Outputs.Fields should not be empty")
	}

	for _, field := range meta.Outputs.Fields {
		if field.Name == "" {
			t.Error("output field name should not be empty")
		}
		if field.Type == "" {
			t.Error("output field type should not be empty")
		}
	}

	t.Log("元数据完整性测试通过")
}
