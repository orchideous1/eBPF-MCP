//go:build linux

package probes

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	_ "ebpf-mcp/ebpf/Sys-call/sys_call_trace"
	"ebpf-mcp/internal/probes"
)

// TestSysCallTraceProbe_Registration 测试探针注册
func TestSysCallTraceProbe_Registration(t *testing.T) {
	if !probes.HasProbe("sys_call_trace") {
		t.Fatal("sys_call_trace probe should be registered")
	}

	probe, ok := probes.GetProbe("sys_call_trace")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	if probe.Name() != "sys_call_trace" {
		t.Fatalf("expected name 'sys_call_trace', got '%s'", probe.Name())
	}

	meta := probe.GetMetadata()
	if meta.Type != "sys_call_trace" {
		t.Fatalf("expected Type 'sys_call_trace', got '%s'", meta.Type)
	}
	if meta.Title == "" {
		t.Fatal("metadata Title should not be empty")
	}
	if meta.Layer != "Sys-call" {
		t.Fatalf("expected Layer 'Sys-call', got '%s'", meta.Layer)
	}

	paramNames := make(map[string]bool)
	for _, param := range meta.Params {
		paramNames[param.Name] = true
	}

	expectedParams := []string{"filter_pid", "filter_syscall_id"}
	for _, name := range expectedParams {
		if !paramNames[name] {
			t.Errorf("expected param '%s' not found", name)
		}
	}

	if len(meta.Outputs.Fields) == 0 {
		t.Fatal("metadata Outputs.Fields should not be empty")
	}

	outputNames := make(map[string]bool)
	for _, field := range meta.Outputs.Fields {
		outputNames[field.Name] = true
	}

	expectedOutputs := []string{"pid", "comm", "syscall_id", "ret", "duration", "enter_time_stamp"}
	for _, name := range expectedOutputs {
		if !outputNames[name] {
			t.Errorf("expected output field '%s' not found", name)
		}
	}
}

// TestSysCallTraceProbe_ControllerLifecycle 测试 Controller 生命周期管理
func TestSysCallTraceProbe_ControllerLifecycle(t *testing.T) {
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

	t.Log("Step 1: 加载探针")
	status, err := controller.Load(ctx, "sys_call_trace")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	if !status.Loaded {
		t.Fatal("probe should be loaded after Load()")
	}
	if status.State != "loaded" {
		t.Fatalf("expected state 'loaded', got '%s'", status.State)
	}

	t.Log("Step 2: 重复加载应失败")
	_, err = controller.Load(ctx, "sys_call_trace")
	if !errors.Is(err, probes.ErrProbeAlreadyLoaded) {
		t.Fatalf("expected ErrProbeAlreadyLoaded, got: %v", err)
	}

	t.Log("Step 3: 查询状态")
	status, err = controller.Status("sys_call_trace")
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}
	if !status.Loaded {
		t.Fatal("probe should be loaded")
	}

	t.Log("Step 4: 更新宏变量")
	status, err = controller.Update("sys_call_trace", map[string]any{
		"filter_pid":        uint32(1234),
		"filter_syscall_id": uint32(0),
	})
	if err != nil {
		t.Fatalf("failed to update probe: %v", err)
	}
	if status.State != "loaded" {
		t.Fatalf("expected state 'loaded' after update, got '%s'", status.State)
	}

	t.Log("Step 5: 卸载探针")
	status, err = controller.Unload("sys_call_trace")
	if err != nil {
		t.Fatalf("failed to unload probe: %v", err)
	}
	if status.Loaded {
		t.Fatal("probe should not be loaded after Unload()")
	}
	if status.State != "unloaded" {
		t.Fatalf("expected state 'unloaded', got '%s'", status.State)
	}

	t.Log("Step 6: 重复卸载应失败")
	_, err = controller.Unload("sys_call_trace")
	if !errors.Is(err, probes.ErrProbeNotLoaded) {
		t.Fatalf("expected ErrProbeNotLoaded, got: %v", err)
	}
}

// TestSysCallTraceProbe_MacroVariables 测试宏变量更新
func TestSysCallTraceProbe_MacroVariables(t *testing.T) {
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
	_, err = controller.Load(ctx, "sys_call_trace")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	defer controller.Unload("sys_call_trace")

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
			name: "更新 filter_syscall_id",
			config: map[string]any{
				"filter_syscall_id": uint32(1),
			},
		},
		{
			name: "同时更新多个变量",
			config: map[string]any{
				"filter_pid":        uint32(5678),
				"filter_syscall_id": uint32(0),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status, err := controller.Update("sys_call_trace", tc.config)
			if err != nil {
				t.Fatalf("failed to update macro variables: %v", err)
			}
			if status.State != "loaded" {
				t.Fatalf("expected state 'loaded', got '%s'", status.State)
			}
		})
	}

	t.Log("测试无效参数类型...")
	_, err = controller.Update("sys_call_trace", map[string]any{
		"filter_pid": "invalid_string",
	})
	if err == nil {
		t.Fatal("expected error for invalid filter_pid type")
	}
}

// TestSysCallTraceProbe_DataCollection 测试数据收集和持久化
func TestSysCallTraceProbe_DataCollection(t *testing.T) {
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
	_, err = controller.Load(ctx, "sys_call_trace")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	defer controller.Unload("sys_call_trace")

	// 验证表已创建
	var tableExists bool
	err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sys_call_trace')").Scan(&tableExists)
	if err != nil {
		t.Logf("无法查询表存在性: %v", err)
	} else if !tableExists {
		t.Error("sys_call_trace 表应该在探针加载时创建")
	}

	// 过滤当前进程 PID 以减少干扰
	currentPID := uint32(os.Getpid())
	_, err = controller.Update("sys_call_trace", map[string]any{
		"filter_pid": currentPID,
	})
	if err != nil {
		t.Fatalf("failed to set filter_pid: %v", err)
	}

	// 触发系统调用（读写临时文件）
	tmpFile := t.TempDir() + "/syscall_test.txt"
	for i := 0; i < 5; i++ {
		_ = os.WriteFile(tmpFile, []byte("test"), 0644)
		_, _ = os.ReadFile(tmpFile)
	}

	time.Sleep(300 * time.Millisecond)

	// 查询 DuckDB
	rows, err := db.Query("SELECT COUNT(*) FROM sys_call_trace WHERE pid = ?", uint64(currentPID)<<32)
	if err != nil {
		t.Logf("查询数据失败（可能无事件）: %v", err)
		return
	}
	defer rows.Close()

	var count int
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			t.Fatalf("failed to scan count: %v", err)
		}
	}

	t.Logf("数据库中包含 %d 条当前进程的事件记录", count)
}

// TestSysCallTraceProbe_MetadataIntegrity 测试元数据完整性
func TestSysCallTraceProbe_MetadataIntegrity(t *testing.T) {
	probe, ok := probes.GetProbe("sys_call_trace")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	meta := probe.GetMetadata()

	requiredFields := []struct {
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

	for _, tt := range requiredFields {
		if tt.value == "" {
			t.Errorf("metadata %s should not be empty", tt.name)
		}
	}

	if len(meta.Entrypoints) == 0 {
		t.Error("metadata Entrypoints should not be empty")
	}

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
}
