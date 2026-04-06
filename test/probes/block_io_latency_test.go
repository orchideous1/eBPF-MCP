package probes

import (
	"context"
	"os"
	"testing"
	"time"

	_ "ebpf-mcp/ebpf/Disk/block_io_latency"
	"ebpf-mcp/internal/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlockIoLatencyProbe_Registration(t *testing.T) {
	// 验证探针已注册
	if !probes.HasProbe("block_io_latency") {
		t.Fatal("block_io_latency probe should be registered")
	}

	// 验证可以通过工厂创建实例
	probe, ok := probes.GetProbe("block_io_latency")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	if probe.Name() != "block_io_latency" {
		t.Fatalf("expected name 'block_io_latency', got '%s'", probe.Name())
	}

	// 验证元数据
	meta := probe.GetMetadata()
	if meta.Type != "block_io_latency" {
		t.Fatalf("expected Type 'block_io_latency', got '%s'", meta.Type)
	}
	if meta.Title == "" {
		t.Fatal("metadata Title should not be empty")
	}
	if meta.Layer != "Disk" {
		t.Fatalf("expected Layer 'Disk', got '%s'", meta.Layer)
	}

	// 验证参数定义
	paramNames := make(map[string]bool)
	for _, param := range meta.Params {
		paramNames[param.Name] = true
	}

	expectedParams := []string{"filter_pid", "filter_comm"}
	for _, name := range expectedParams {
		if !paramNames[name] {
			t.Errorf("expected param '%s' not found", name)
		}
	}

	// 验证输出字段
	outputNames := make(map[string]bool)
	for _, field := range meta.Outputs.Fields {
		outputNames[field.Name] = true
	}

	expectedOutputs := []string{"pid", "comm", "latency", "time_stamp"}
	for _, name := range expectedOutputs {
		if !outputNames[name] {
			t.Errorf("expected output field '%s' not found", name)
		}
	}
}

func TestBlockIoLatencyProbe_MetadataIntegrity(t *testing.T) {
	probe, ok := probes.GetProbe("block_io_latency")
	require.True(t, ok, "probe should exist")

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
	assert.Contains(t, meta.Entrypoints, "block/block_io_start")
	assert.Contains(t, meta.Entrypoints, "block/block_io_done")

	// 验证 Params
	assert.GreaterOrEqual(t, len(meta.Params), 2, "should have at least 2 params")

	for _, param := range meta.Params {
		assert.NotEmpty(t, param.Name, "param name should not be empty")
		assert.NotEmpty(t, param.Type, "param type should not be empty")
		assert.NotEmpty(t, param.Description, "param description should not be empty")
	}

	// 验证 Outputs
	assert.GreaterOrEqual(t, len(meta.Outputs.Fields), 4, "should have at least 4 output fields")

	for _, field := range meta.Outputs.Fields {
		assert.NotEmpty(t, field.Name, "output field name should not be empty")
		assert.NotEmpty(t, field.Type, "output field type should not be empty")
	}
}

func TestBlockIoLatencyProbe_ControllerLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	db := openTestDB(t)
	controller, err := probes.NewController(db)
	require.NoError(t, err)
	defer controller.Shutdown()

	ctx := context.Background()

	// 1. 测试加载探针
	t.Log("Step 1: 加载探针")
	status, err := controller.Load(ctx, "block_io_latency")
	require.NoError(t, err)
	assert.True(t, status.Loaded)
	assert.Equal(t, "loaded", status.State)

	// 2. 测试查询状态
	t.Log("Step 2: 查询探针状态")
	status, err = controller.Status("block_io_latency")
	require.NoError(t, err)
	assert.True(t, status.Loaded)

	// 3. 测试更新配置
	t.Log("Step 3: 更新宏变量配置")
	status, err = controller.Update("block_io_latency", map[string]any{
		"filter_pid":  uint32(1234),
		"filter_comm": "test",
	})
	require.NoError(t, err)
	assert.Equal(t, "loaded", status.State)

	// 4. 等待一些事件
	t.Log("Step 4: 等待事件收集")
	time.Sleep(1 * time.Second)

	// 5. 测试卸载探针
	t.Log("Step 5: 卸载探针")
	status, err = controller.Unload("block_io_latency")
	require.NoError(t, err)
	assert.False(t, status.Loaded)
	assert.Equal(t, "unloaded", status.State)
}

func TestBlockIoLatencyProbe_FilterByPID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	db := openTestDB(t)
	controller, err := probes.NewController(db)
	require.NoError(t, err)
	defer controller.Shutdown()

	ctx := context.Background()

	// 加载探针
	t.Log("加载探针...")
	_, err = controller.Load(ctx, "block_io_latency")
	require.NoError(t, err)
	defer controller.Unload("block_io_latency")

	// 设置 filter_pid 为当前进程 PID
	currentPID := uint32(os.Getpid())
	t.Logf("设置 filter_pid = %d (当前进程)", currentPID)
	_, err = controller.Update("block_io_latency", map[string]any{
		"filter_pid": currentPID,
	})
	require.NoError(t, err)

	// 触发磁盘I/O操作
	tmpFile := t.TempDir() + "/test_io.txt"
	for i := 0; i < 5; i++ {
		os.WriteFile(tmpFile, []byte("test content for block io probe"), 0644)
		os.ReadFile(tmpFile)
	}

	// 等待事件收集
	time.Sleep(500 * time.Millisecond)

	t.Log("PID 过滤测试完成")
}

func TestBlockIoLatencyProbe_DataCollection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	db := openTestDB(t)
	controller, err := probes.NewController(db)
	require.NoError(t, err)
	defer controller.Shutdown()

	ctx := context.Background()

	// 加载探针
	t.Log("加载探针...")
	_, err = controller.Load(ctx, "block_io_latency")
	require.NoError(t, err)
	defer controller.Unload("block_io_latency")

	// 验证表已创建
	var tableExists bool
	err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'block_io_latency')").Scan(&tableExists)
	if err != nil {
		t.Logf("无法查询表存在性: %v", err)
	} else if !tableExists {
		t.Error("block_io_latency 表应该在探针加载时创建")
	}

	// 触发磁盘I/O
	tmpFile := t.TempDir() + "/test_data.txt"
	content := []byte("test data for collection verification")
	for i := 0; i < 5; i++ {
		os.WriteFile(tmpFile, content, 0644)
		os.ReadFile(tmpFile)
	}

	// 等待并刷新数据
	time.Sleep(500 * time.Millisecond)

	// 查询数据库验证
	rows, err := db.Query("SELECT COUNT(*) FROM block_io_latency")
	if err != nil {
		t.Logf("查询数据（表可能为空）: %v", err)
	} else {
		defer rows.Close()
		var count int
		if rows.Next() {
			rows.Scan(&count)
			t.Logf("数据库中共有 %d 条记录", count)
		}
	}
}
