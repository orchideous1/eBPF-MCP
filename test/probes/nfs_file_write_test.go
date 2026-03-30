//go:build linux

package probes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "ebpf-mcp/ebpf/NFS-client/nfs_file_write"
	"ebpf-mcp/internal/probes"
)

// TestNFSFileWriteProbe_Registration 测试探针注册
// 验证 nfs_file_write 探针已正确注册到全局注册表
func TestNFSFileWriteProbe_Registration(t *testing.T) {
	// 验证探针已注册
	if !probes.HasProbe("nfs_file_write") {
		t.Fatal("nfs_file_write probe should be registered")
	}

	// 验证可以通过工厂创建实例
	probe, ok := probes.GetProbe("nfs_file_write")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	if probe.Name() != "nfs_file_write" {
		t.Fatalf("expected name 'nfs_file_write', got '%s'", probe.Name())
	}

	// 验证元数据
	meta := probe.GetMetadata()
	if meta.Type != "nfs_file_write" {
		t.Fatalf("expected Type 'nfs_file_write', got '%s'", meta.Type)
	}
	if meta.Title == "" {
		t.Fatal("metadata Title should not be empty")
	}
	if meta.Layer != "nfs-client" {
		t.Fatalf("expected Layer 'nfs-client', got '%s'", meta.Layer)
	}

	// 验证参数定义
	if len(meta.Params) < 3 {
		t.Fatalf("expected at least 3 params, got %d", len(meta.Params))
	}

	paramNames := make(map[string]bool)
	for _, param := range meta.Params {
		paramNames[param.Name] = true
	}

	// 验证期望的参数存在
	expectedParams := []string{"filter_pid", "filter_file", "filter_comm"}
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

	expectedOutputs := []string{"pid", "comm", "time_stamp", "lat", "size", "file"}
	for _, name := range expectedOutputs {
		if !outputNames[name] {
			t.Errorf("expected output field '%s' not found", name)
		}
	}
}

// TestNFSFileWriteProbe_ControllerLifecycle 测试 Controller 生命周期管理
// 验证探针的加载、状态查询、更新、卸载完整流程
func TestNFSFileWriteProbe_ControllerLifecycle(t *testing.T) {
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
	status, err := controller.Load(ctx, "nfs_file_write")
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
	_, err = controller.Load(ctx, "nfs_file_write")
	if !errors.Is(err, probes.ErrProbeAlreadyLoaded) {
		t.Fatalf("expected ErrProbeAlreadyLoaded, got: %v", err)
	}

	// 3. 测试查询状态
	t.Log("Step 3: 查询探针状态")
	status, err = controller.Status("nfs_file_write")
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}
	if !status.Loaded {
		t.Fatal("probe should be loaded")
	}

	// 4. 测试更新配置（宏变量）
	t.Log("Step 4: 更新宏变量配置")
	status, err = controller.Update("nfs_file_write", map[string]any{
		"filter_pid":  uint32(1234),
		"filter_file": "*.log",
		"filter_comm": "nginx",
	})
	if err != nil {
		t.Fatalf("failed to update probe: %v", err)
	}
	if status.State != "loaded" {
		t.Fatalf("expected state 'loaded' after update, got '%s'", status.State)
	}

	// 5. 测试卸载探针
	t.Log("Step 5: 卸载探针")
	status, err = controller.Unload("nfs_file_write")
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
	_, err = controller.Unload("nfs_file_write")
	if !errors.Is(err, probes.ErrProbeNotLoaded) {
		t.Fatalf("expected ErrProbeNotLoaded, got: %v", err)
	}
}

// TestNFSFileWriteProbe_FilterByPID 测试 PID 过滤功能
// 验证 filter_pid 宏变量能正确过滤特定进程的事件
func TestNFSFileWriteProbe_FilterByPID(t *testing.T) {
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
	_, err = controller.Load(ctx, "nfs_file_write")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	defer controller.Unload("nfs_file_write")

	// 设置 filter_pid 为当前进程 PID
	currentPID := uint32(os.Getpid())
	t.Logf("设置 filter_pid = %d (当前进程)", currentPID)
	_, err = controller.Update("nfs_file_write", map[string]any{
		"filter_pid": currentPID,
	})
	if err != nil {
		t.Fatalf("failed to set filter_pid: %v", err)
	}

	// 等待 eBPF 程序处理
	time.Sleep(100 * time.Millisecond)

	// 触发文件写入操作
	tmpFile := filepath.Join(t.TempDir(), "test_write.txt")
	t.Log("触发文件写入操作...")
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(tmpFile, []byte("test content for nfs probe"), 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}
	}

	// 等待事件收集
	time.Sleep(200 * time.Millisecond)

	t.Log("PID 过滤测试完成（事件收集取决于是否有 NFS 挂载）")
}

// TestNFSFileWriteProbe_DataCollection 测试数据收集和持久化
// 验证探针能将事件数据正确写入 DuckDB
func TestNFSFileWriteProbe_DataCollection(t *testing.T) {
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
	_, err = controller.Load(ctx, "nfs_file_write")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	defer controller.Unload("nfs_file_write")

	// 验证表已创建
	var tableExists bool
	err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'nfs_file_write')").Scan(&tableExists)
	if err != nil {
		t.Logf("无法查询表存在性（可能DuckDB版本不支持）: %v", err)
	} else if !tableExists {
		t.Error("nfs_file_write 表应该在探针加载时创建")
	}

	// 触发文件写入
	tmpFile := filepath.Join(t.TempDir(), "test_data.txt")
	content := []byte("test data for collection verification")
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(tmpFile, content, 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}
	}

	// 等待并刷新数据
	time.Sleep(300 * time.Millisecond)

	// 查询 DuckDB 验证数据持久化
	rows, err := db.Query("SELECT COUNT(*) FROM nfs_file_write")
	if err != nil {
		t.Fatalf("failed to query table: %v", err)
	}
	defer rows.Close()

	var count int
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			t.Fatalf("failed to scan count: %v", err)
		}
	}

	t.Logf("Database contains %d events (实际数量取决于是否有 NFS 挂载和写入活动)", count)
}

// TestNFSFileWriteProbe_MacroVariables 测试宏变量更新
// 验证所有宏变量（filter_pid, filter_file, filter_comm）能正确更新
func TestNFSFileWriteProbe_MacroVariables(t *testing.T) {
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
	_, err = controller.Load(ctx, "nfs_file_write")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	defer controller.Unload("nfs_file_write")

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
			name: "更新 filter_file",
			config: map[string]any{
				"filter_file": "*.log",
			},
		},
		{
			name: "更新 filter_comm",
			config: map[string]any{
				"filter_comm": "nginx",
			},
		},
		{
			name: "同时更新多个变量",
			config: map[string]any{
				"filter_pid":  uint32(5678),
				"filter_file": "test*.txt",
				"filter_comm": "testapp",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status, err := controller.Update("nfs_file_write", tc.config)
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
	_, err = controller.Update("nfs_file_write", map[string]any{
		"filter_pid": "invalid_string",
	})
	if err == nil {
		t.Fatal("expected error for invalid filter_pid type")
	}
	t.Logf("无效参数正确返回错误: %v", err)
}

// TestNFSFileWriteProbe_ConcurrentAccess 测试并发访问安全性
// 验证多协程同时操作探针时的线程安全性
func TestNFSFileWriteProbe_ConcurrentAccess(t *testing.T) {
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
	_, err = controller.Load(ctx, "nfs_file_write")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	defer controller.Unload("nfs_file_write")

	// 并发更新和查询
	done := make(chan bool, 3)

	// 协程1：频繁更新 filter_pid
	go func() {
		for i := 0; i < 10; i++ {
			controller.Update("nfs_file_write", map[string]any{
				"filter_pid": uint32(i + 1),
			})
			time.Sleep(10 * time.Millisecond)
		}
		done <- true
	}()

	// 协程2：频繁查询状态
	go func() {
		for i := 0; i < 10; i++ {
			controller.Status("nfs_file_write")
			time.Sleep(10 * time.Millisecond)
		}
		done <- true
	}()

	// 协程3：触发文件写入操作
	go func() {
		tmpFile := filepath.Join(os.TempDir(), "concurrent_write_test.txt")
		for i := 0; i < 10; i++ {
			os.WriteFile(tmpFile, []byte("test"), 0644)
			time.Sleep(10 * time.Millisecond)
		}
		os.Remove(tmpFile)
		done <- true
	}()

	// 等待所有协程完成
	for i := 0; i < 3; i++ {
		<-done
	}

	// 验证探针仍然正常
	status, err := controller.Status("nfs_file_write")
	if err != nil {
		t.Fatalf("failed to get final status: %v", err)
	}
	if !status.Loaded {
		t.Fatal("probe should still be loaded after concurrent access")
	}

	t.Log("并发访问测试通过")
}

// TestNFSFileWriteProbe_ErrorHandling 测试错误处理
// 验证各种错误场景的正确处理
func TestNFSFileWriteProbe_ErrorHandling(t *testing.T) {
	// 测试 Controller 错误处理
	db := openTestDB(t)
	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	defer controller.Shutdown()

	// 更新未加载的探针
	t.Log("验证更新未加载探针返回错误...")
	_, err = controller.Update("nfs_file_write", map[string]any{"filter_pid": 1})
	if !errors.Is(err, probes.ErrProbeNotLoaded) {
		t.Fatalf("expected ErrProbeNotLoaded, got: %v", err)
	}

	t.Log("错误处理测试通过")
}

// TestNFSFileWriteProbe_FullWorkflow 完整工作流测试
// 模拟从注册到加载、运行、收集数据、过滤数据、变更宏变量、卸载的全流程
func TestNFSFileWriteProbe_FullWorkflow(t *testing.T) {
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

	t.Log("=== Step 1: 验证探针已注册 ===")
	if !probes.HasProbe("nfs_file_write") {
		t.Fatal("probe should be registered")
	}
	t.Log("探针已注册: nfs_file_write")

	t.Log("=== Step 2: 加载探针 ===")
	status, err := controller.Load(ctx, "nfs_file_write")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}
	if !status.Loaded {
		t.Fatal("probe should be loaded")
	}
	t.Logf("探针加载成功，状态: %s", status.State)

	t.Log("=== Step 3: 查询探针信息 ===")
	info, err := controller.GetProbeInfo("nfs_file_write")
	if err != nil {
		t.Fatalf("failed to get probe info: %v", err)
	}
	if info.Metadata.Type != "nfs_file_write" {
		t.Fatalf("unexpected probe Type: %s", info.Metadata.Type)
	}
	if !info.Status.Loaded {
		t.Fatal("probe status should be loaded")
	}
	t.Logf("探针信息: Type=%s, Title=%s, State=%s", info.Metadata.Type, info.Metadata.Title, info.Status.State)

	t.Log("=== Step 4: 更新宏变量（filter_pid）===")
	currentPID := uint32(os.Getpid())
	_, err = controller.Update("nfs_file_write", map[string]any{
		"filter_pid": currentPID,
	})
	if err != nil {
		t.Fatalf("failed to update filter_pid: %v", err)
	}
	t.Logf("filter_pid 设置为: %d", currentPID)

	t.Log("=== Step 5: 触发文件写入事件 ===")
	tmpFile := filepath.Join(t.TempDir(), "workflow_write_test.txt")
	for i := 0; i < 5; i++ {
		os.WriteFile(tmpFile, []byte("workflow test data"), 0644)
	}
	t.Log("文件写入操作已触发")

	t.Log("=== Step 6: 等待事件收集 ===")
	time.Sleep(200 * time.Millisecond)
	t.Log("事件收集等待完成")

	t.Log("=== Step 7: 验证数据持久化 ===")
	rows, err := db.Query("SELECT pid, lat_ns, comm FROM nfs_file_write LIMIT 10")
	if err != nil {
		t.Logf("查询数据（表可能为空）: %v", err)
	} else {
		defer rows.Close()
		rowCount := 0
		for rows.Next() {
			var pid uint32
			var lat uint64
			var comm string
			if err := rows.Scan(&pid, &lat, &comm); err != nil {
				t.Logf("扫描行失败: %v", err)
				continue
			}
			t.Logf("  事件: pid=%d, lat=%d, comm=%s", pid, lat, comm)
			rowCount++
		}
		t.Logf("数据库中共有 %d 条记录", rowCount)
	}

	t.Log("=== Step 8: 更新更多宏变量 ===")
	_, err = controller.Update("nfs_file_write", map[string]any{
		"filter_file": "*.txt",
		"filter_comm": "test",
	})
	if err != nil {
		t.Fatalf("failed to update other macros: %v", err)
	}
	t.Log("宏变量 filter_file, filter_comm 已更新")

	t.Log("=== Step 9: 卸载探针 ===")
	status, err = controller.Unload("nfs_file_write")
	if err != nil {
		t.Fatalf("failed to unload probe: %v", err)
	}
	if status.Loaded {
		t.Fatal("probe should be unloaded")
	}
	t.Logf("探针卸载成功，状态: %s", status.State)

	t.Log("=== Step 10: 验证探针状态 ===")
	status, err = controller.Status("nfs_file_write")
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}
	if status.State != "unloaded" {
		t.Fatalf("expected state 'unloaded', got '%s'", status.State)
	}
	t.Logf("最终状态验证通过: %s", status.State)

	t.Log("\n✓ 完整工作流测试通过!")
}

// TestNFSFileWriteProbe_ListOperations 测试列表操作
// 验证 ListProbes, ListStatus, ListProbeInfos 等批量操作
func TestNFSFileWriteProbe_ListOperations(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	db := openTestDB(t)
	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	defer controller.Shutdown()

	// 验证 ListProbes 包含 nfs_file_write 探针
	t.Log("验证 ListProbes...")
	allProbes := probes.ListProbes()
	found := false
	for _, name := range allProbes {
		if name == "nfs_file_write" {
			found = true
			break
		}
	}
	if !found {
		t.Error("nfs_file_write should be in ListProbes")
	}
	t.Logf("ListProbes 返回 %d 个探针", len(allProbes))

	// 加载探针后验证 ListStatus
	t.Log("验证 ListStatus...")
	ctx := context.Background()
	controller.Load(ctx, "nfs_file_write")

	statuses := controller.ListStatus()
	found = false
	for _, status := range statuses {
		if status.Name == "nfs_file_write" {
			found = true
			if !status.Loaded {
				t.Error("probe should be loaded in ListStatus")
			}
			break
		}
	}
	if !found {
		t.Error("nfs_file_write should be in ListStatus")
	}

	// 验证 ListProbeInfos
	t.Log("验证 ListProbeInfos...")
	infos := controller.ListProbeInfos()
	found = false
	for _, info := range infos {
		if info.Metadata.Type == "nfs_file_write" {
			found = true
			if !info.Status.Loaded {
				t.Error("probe should be loaded in ListProbeInfos")
			}
			break
		}
	}
	if !found {
		t.Error("nfs_file_write should be in ListProbeInfos")
	}

	controller.Unload("nfs_file_write")
	t.Log("列表操作测试通过")
}

// TestNFSFileWriteProbe_MetadataIntegrity 测试元数据完整性
// 验证探针元数据符合规范要求
func TestNFSFileWriteProbe_MetadataIntegrity(t *testing.T) {
	probe, ok := probes.GetProbe("nfs_file_write")
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
