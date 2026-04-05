//go:build linux

package probes

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	_ "ebpf-mcp/ebpf/Sys-call/sys_call_trace"
	"ebpf-mcp/internal/logx"
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
	if !errors.Is(err, logx.ErrProbeAlreadyLoaded) {
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
	if !errors.Is(err, logx.ErrProbeNotLoaded) {
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

	// 查询 DuckDB - pid 存储的是 pid_tgid（高32位PID + 低32位TID），使用 >> 32 提取PID部分
	rows, err := db.Query("SELECT COUNT(*) FROM sys_call_trace WHERE pid >> 32 = ?", uint32(currentPID))
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

// TestSysCallTraceProbe_FastStop 验证探针能快速停止（< 500ms）
// 这是 Context 驱动并发控制的核心测试
func TestSysCallTraceProbe_FastStop(t *testing.T) {
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

	// 让探针运行一小段时间
	time.Sleep(100 * time.Millisecond)

	t.Log("停止探针...")
	start := time.Now()

	// 使用带超时的 channel 来强制兜底，防止测试挂起
	type result struct {
		status probes.Status
		err    error
	}
	done := make(chan result, 1)

	go func() {
		status, err := controller.Unload("sys_call_trace")
		done <- result{status, err}
	}()

	var status probes.Status
	select {
	case res := <-done:
		status = res.status
		err = res.err
	case <-time.After(5 * time.Second): // 强制兜底：5秒超时
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

	// 验证停止时间 < 500ms（原实现需要 2s 超时）
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Stop took too long: %v (expected < 500ms)", elapsed)
	}

	t.Log("✓ 快速停止测试通过")
}

// TestSysCallTraceProbe_ContextCancellation 验证 Context 取消机制
// 确保 consume 能正确响应 ctx.Done() 并优雅退出
func TestSysCallTraceProbe_ContextCancellation(t *testing.T) {
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

	// 带强制超时的辅助函数
	loadWithTimeout := func(round int) {
		done := make(chan error, 1)
		go func() {
			_, err := controller.Load(ctx, "sys_call_trace")
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("round %d: failed to load probe: %v", round, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("round %d: Load timed out after 10s", round)
		}
	}

	unloadWithTimeout := func(round int) {
		done := make(chan error, 1)
		go func() {
			_, err := controller.Unload("sys_call_trace")
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("round %d: failed to unload probe: %v", round, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: Unload timed out after 5s - possible deadlock", round)
		}
	}

	// 测试：连续多次加载/卸载，验证没有 goroutine 泄漏
	for i := 0; i < 3; i++ {
		t.Logf("第 %d 轮加载/卸载测试...", i+1)

		loadWithTimeout(i + 1)
		time.Sleep(50 * time.Millisecond)
		unloadWithTimeout(i + 1)

		// 验证状态正确（带超时）
		statusDone := make(chan struct {
			status probes.Status
			err    error
		}, 1)
		go func() {
			status, err := controller.Status("sys_call_trace")
			statusDone <- struct {
				status probes.Status
				err    error
			}{status, err}
		}()

		select {
		case res := <-statusDone:
			if res.err != nil {
				t.Fatalf("round %d: failed to get status: %v", i+1, res.err)
			}
			if res.status.State != "unloaded" {
				t.Fatalf("round %d: expected state 'unloaded', got '%s'", i+1, res.status.State)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("round %d: Status timed out after 2s", i+1)
		}
	}

	t.Log("✓ Context 取消机制测试通过")
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
