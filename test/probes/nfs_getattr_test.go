//go:build linux

package probes

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	_ "ebpf-mcp/ebpf/NFS-client/nfs_getattr"
	"ebpf-mcp/internal/logx"
	"ebpf-mcp/internal/probes"
)

// TestNFSGetattrProbe_Registration 测试探针注册
func TestNFSGetattrProbe_Registration(t *testing.T) {
	if !probes.HasProbe("nfs_getattr") {
		t.Fatal("nfs_getattr probe should be registered")
	}

	probe, ok := probes.GetProbe("nfs_getattr")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	if probe.Name() != "nfs_getattr" {
		t.Fatalf("expected name 'nfs_getattr', got '%s'", probe.Name())
	}

	meta := probe.GetMetadata()
	if meta.Type != "nfs_getattr" {
		t.Fatalf("expected Type 'nfs_getattr', got '%s'", meta.Type)
	}
	if meta.Layer != "nfs-client" {
		t.Fatalf("expected Layer 'nfs-client', got '%s'", meta.Layer)
	}

	// 验证参数定义
	if len(meta.Params) < 1 {
		t.Fatalf("expected at least 1 param, got %d", len(meta.Params))
	}

	paramNames := make(map[string]bool)
	for _, param := range meta.Params {
		paramNames[param.Name] = true
	}

	if !paramNames["filter_pid"] {
		t.Error("expected param 'filter_pid' not found")
	}

	// 验证输出字段
	if len(meta.Outputs.Fields) == 0 {
		t.Fatal("metadata Outputs.Fields should not be empty")
	}

	outputNames := make(map[string]bool)
	for _, field := range meta.Outputs.Fields {
		outputNames[field.Name] = true
	}

	expectedOutputs := []string{"pid", "comm", "time_stamp", "lat", "ret"}
	for _, name := range expectedOutputs {
		if !outputNames[name] {
			t.Errorf("expected output field '%s' not found", name)
		}
	}
}

// TestNFSGetattrProbe_ControllerLifecycle 测试 Controller 生命周期管理
func TestNFSGetattrProbe_ControllerLifecycle(t *testing.T) {
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
	status, err := controller.Load(ctx, "nfs_getattr")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	if !status.Loaded {
		t.Fatal("probe should be loaded after Load()")
	}

	// 2. 测试重复加载（应该失败）
	t.Log("Step 2: 验证重复加载返回错误")
	_, err = controller.Load(ctx, "nfs_getattr")
	if !errors.Is(err, logx.ErrProbeAlreadyLoaded) {
		t.Fatalf("expected ErrProbeAlreadyLoaded, got: %v", err)
	}

	// 3. 测试查询状态
	t.Log("Step 3: 查询探针状态")
	status, err = controller.Status("nfs_getattr")
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}
	if !status.Loaded {
		t.Fatal("probe should be loaded")
	}

	// 4. 测试更新配置
	t.Log("Step 4: 更新宏变量配置")
	status, err = controller.Update("nfs_getattr", map[string]any{
		"filter_pid": uint32(1234),
	})
	if err != nil {
		t.Fatalf("failed to update probe: %v", err)
	}
	if status.State != "loaded" {
		t.Fatalf("expected state 'loaded' after update, got '%s'", status.State)
	}

	// 5. 测试卸载探针
	t.Log("Step 5: 卸载探针")
	status, err = controller.Unload("nfs_getattr")
	if err != nil {
		t.Fatalf("failed to unload probe: %v", err)
	}
	if status.Loaded {
		t.Fatal("probe should not be loaded after Unload()")
	}

	// 6. 测试重复卸载（应该失败）
	t.Log("Step 6: 验证重复卸载返回错误")
	_, err = controller.Unload("nfs_getattr")
	if !errors.Is(err, logx.ErrProbeNotLoaded) {
		t.Fatalf("expected ErrProbeNotLoaded, got: %v", err)
	}
}

// TestNFSGetattrProbe_FilterByPID 测试 PID 过滤功能
func TestNFSGetattrProbe_FilterByPID(t *testing.T) {
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
	t.Log("加载探针...")
	_, err = controller.Load(ctx, "nfs_getattr")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	defer controller.Unload("nfs_getattr")

	// 设置 filter_pid 为当前进程 PID
	currentPID := uint32(os.Getpid())
	t.Logf("设置 filter_pid = %d (当前进程)", currentPID)
	_, err = controller.Update("nfs_getattr", map[string]any{
		"filter_pid": currentPID,
	})
	if err != nil {
		t.Fatalf("failed to set filter_pid: %v", err)
	}

	// 等待 eBPF 程序处理
	time.Sleep(100 * time.Millisecond)

	t.Log("PID 过滤测试完成")
}

// TestNFSGetattrProbe_MacroVariables 测试宏变量更新
func TestNFSGetattrProbe_MacroVariables(t *testing.T) {
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
	_, err = controller.Load(ctx, "nfs_getattr")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	defer controller.Unload("nfs_getattr")

	// 测试更新 filter_pid
	status, err := controller.Update("nfs_getattr", map[string]any{
		"filter_pid": uint32(1234),
	})
	if err != nil {
		t.Fatalf("failed to update filter_pid: %v", err)
	}
	if status.State != "loaded" {
		t.Fatalf("expected state 'loaded', got '%s'", status.State)
	}

	// 测试无效参数
	t.Log("测试无效参数类型...")
	_, err = controller.Update("nfs_getattr", map[string]any{
		"filter_pid": "invalid_string",
	})
	if err == nil {
		t.Fatal("expected error for invalid filter_pid type")
	}
	t.Logf("无效参数正确返回错误: %v", err)
}

// TestNFSGetattrProbe_MetadataIntegrity 测试元数据完整性
func TestNFSGetattrProbe_MetadataIntegrity(t *testing.T) {
	probe, ok := probes.GetProbe("nfs_getattr")
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
