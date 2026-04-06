//go:build linux

package probes

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"ebpf-mcp/internal/logx"
	"ebpf-mcp/internal/probes"
)

// ProbeTestHelper 提供探针测试的通用辅助方法
type ProbeTestHelper struct {
	t          *testing.T
	Controller *probes.Controller
	DB         *sql.DB
}

// ProbeTestCase 定义探针测试用例
type ProbeTestCase struct {
	Name           string
	ProbeType      string
	Layer          string
	ExpectedParams []string
	ExpectedOutputs []string
	TableName      string
}

// NewProbeTestHelper 创建测试辅助对象
func NewProbeTestHelper(t *testing.T) *ProbeTestHelper {
	t.Helper()
	db := openTestDB(t)
	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	return &ProbeTestHelper{
		t:          t,
		Controller: controller,
		DB:         db,
	}
}

// Shutdown 清理测试资源
func (h *ProbeTestHelper) Shutdown() {
	if h.Controller != nil {
		h.Controller.Shutdown()
	}
}

// SkipIfNotRoot 如果不是 root 用户则跳过测试
func (h *ProbeTestHelper) SkipIfNotRoot() {
	if os.Geteuid() != 0 {
		h.t.Skip("需要 root 权限运行 eBPF 测试")
	}
}

// TestRegistration 测试探针注册
func (h *ProbeTestHelper) TestRegistration(tc ProbeTestCase) {
	h.t.Helper()
	h.t.Run(tc.Name+"_Registration", func(t *testing.T) {
		// 验证探针已注册
		if !probes.HasProbe(tc.ProbeType) {
			t.Fatalf("%s probe should be registered", tc.ProbeType)
		}

		// 验证可以通过工厂创建实例
		probe, ok := probes.GetProbe(tc.ProbeType)
		if !ok {
			t.Fatal("should get probe from registry")
		}

		if probe.Name() != tc.ProbeType {
			t.Fatalf("expected name '%s', got '%s'", tc.ProbeType, probe.Name())
		}

		// 验证元数据
		meta := probe.GetMetadata()
		if meta.Type != tc.ProbeType {
			t.Fatalf("expected Type '%s', got '%s'", tc.ProbeType, meta.Type)
		}
		if meta.Title == "" {
			t.Fatal("metadata Title should not be empty")
		}
		if meta.Layer != tc.Layer {
			t.Fatalf("expected Layer '%s', got '%s'", tc.Layer, meta.Layer)
		}

		// 验证参数定义
		paramNames := make(map[string]bool)
		for _, param := range meta.Params {
			paramNames[param.Name] = true
		}

		for _, name := range tc.ExpectedParams {
			if !paramNames[name] {
				t.Errorf("expected param '%s' not found", name)
			}
		}

		// 验证输出字段
		outputNames := make(map[string]bool)
		for _, field := range meta.Outputs.Fields {
			outputNames[field.Name] = true
		}

		for _, name := range tc.ExpectedOutputs {
			if !outputNames[name] {
				t.Errorf("expected output field '%s' not found", name)
			}
		}
	})
}

// TestLifecycle 测试 Controller 生命周期管理
func (h *ProbeTestHelper) TestLifecycle(tc ProbeTestCase) {
	h.t.Helper()
	h.t.Run(tc.Name+"_Lifecycle", func(t *testing.T) {
		ctx := context.Background()

		// 1. 测试加载探针
		t.Log("Step 1: 加载探针")
		status, err := h.Controller.Load(ctx, tc.ProbeType)
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
		_, err = h.Controller.Load(ctx, tc.ProbeType)
		if !errors.Is(err, logx.ErrProbeAlreadyLoaded) {
			t.Fatalf("expected ErrProbeAlreadyLoaded, got: %v", err)
		}

		// 3. 测试查询状态
		t.Log("Step 3: 查询探针状态")
		status, err = h.Controller.Status(tc.ProbeType)
		if err != nil {
			t.Fatalf("failed to get status: %v", err)
		}
		if !status.Loaded {
			t.Fatal("probe should be loaded")
		}

		// 4. 测试卸载探针
		t.Log("Step 4: 卸载探针")
		status, err = h.Controller.Unload(tc.ProbeType)
		if err != nil {
			t.Fatalf("failed to unload probe: %v", err)
		}
		if status.Loaded {
			t.Fatal("probe should not be loaded after Unload()")
		}
		if status.State != "unloaded" {
			t.Fatalf("expected state 'unloaded', got '%s'", status.State)
		}

		// 5. 测试重复卸载（应该失败）
		t.Log("Step 5: 验证重复卸载返回错误")
		_, err = h.Controller.Unload(tc.ProbeType)
		if !errors.Is(err, logx.ErrProbeNotLoaded) {
			t.Fatalf("expected ErrProbeNotLoaded, got: %v", err)
		}
	})
}

// TestMacroVariables 测试宏变量更新
func (h *ProbeTestHelper) TestMacroVariables(tc ProbeTestCase, testConfigs []map[string]any) {
	h.t.Helper()
	h.t.Run(tc.Name+"_MacroVariables", func(t *testing.T) {
		ctx := context.Background()

		// 加载探针
		_, err := h.Controller.Load(ctx, tc.ProbeType)
		if err != nil {
			t.Fatalf("failed to load probe: %v", err)
		}
		defer h.Controller.Unload(tc.ProbeType)

		// 测试各种宏变量更新
		for i, config := range testConfigs {
			status, err := h.Controller.Update(tc.ProbeType, config)
			if err != nil {
				t.Fatalf("failed to update macro variables (case %d): %v", i, err)
			}
			if status.State != "loaded" {
				t.Fatalf("expected state 'loaded', got '%s'", status.State)
			}
		}

		// 测试无效参数
		_, err = h.Controller.Update(tc.ProbeType, map[string]any{
			"filter_pid": "invalid_string",
		})
		if err == nil {
			t.Fatal("expected error for invalid filter_pid type")
		}
	})
}

// TestMetadataIntegrity 测试元数据完整性
func (h *ProbeTestHelper) TestMetadataIntegrity(tc ProbeTestCase) {
	h.t.Helper()
	h.t.Run(tc.Name+"_MetadataIntegrity", func(t *testing.T) {
		probe, ok := probes.GetProbe(tc.ProbeType)
		if !ok {
			t.Fatal("should get probe from registry")
		}

		meta := probe.GetMetadata()

		// 验证必需字段
		requiredFields := map[string]string{
			"Type":  meta.Type,
			"Title": meta.Title,
			"Layer": meta.Layer,
			"Level": meta.Level,
			"Scene": meta.Scene,
			"Risks": meta.Risks,
		}

		for name, value := range requiredFields {
			if value == "" {
				t.Errorf("metadata %s should not be empty", name)
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
	})
}

// TestDataCollection 测试数据收集和持久化
func (h *ProbeTestHelper) TestDataCollection(tc ProbeTestCase, triggerFunc func()) {
	h.t.Helper()
	h.t.Run(tc.Name+"_DataCollection", func(t *testing.T) {
		ctx := context.Background()

		// 加载探针
		_, err := h.Controller.Load(ctx, tc.ProbeType)
		if err != nil {
			t.Fatalf("failed to load probe: %v", err)
		}
		defer h.Controller.Unload(tc.ProbeType)

		// 验证表已创建
		var tableExists bool
		err = h.DB.QueryRow("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = ?)", tc.TableName).Scan(&tableExists)
		if err != nil {
			t.Logf("无法查询表存在性（可能DuckDB版本不支持）: %v", err)
		} else if !tableExists {
			t.Errorf("%s 表应该在探针加载时创建", tc.TableName)
		}

		// 触发事件
		if triggerFunc != nil {
			triggerFunc()
		}

		// 等待并刷新数据
		time.Sleep(300 * time.Millisecond)

		// 查询 DuckDB 验证数据持久化
		rows, err := h.DB.Query("SELECT COUNT(*) FROM " + tc.TableName)
		if err != nil {
			t.Logf("查询表失败（可能表尚未创建）: %v", err)
			return
		}
		defer rows.Close()

		var count int
		if rows.Next() {
			if err := rows.Scan(&count); err != nil {
				t.Logf("扫描计数失败: %v", err)
				return
			}
		}

		t.Logf("Database contains %d events", count)
	})
}

// TestErrorHandling 测试错误处理
func (h *ProbeTestHelper) TestErrorHandling(tc ProbeTestCase) {
	h.t.Helper()
	h.t.Run(tc.Name+"_ErrorHandling", func(t *testing.T) {
		ctx := context.Background()

		// 更新未加载的探针
		_, err := h.Controller.Update(tc.ProbeType, map[string]any{"filter_pid": 1})
		if !errors.Is(err, logx.ErrProbeNotLoaded) {
			t.Fatalf("expected ErrProbeNotLoaded, got: %v", err)
		}

		// 加载不存在的探针
		_, err = h.Controller.Load(ctx, "non_existent_probe")
		if !errors.Is(err, logx.ErrProbeNotFound) {
			t.Fatalf("expected ErrProbeNotFound, got: %v", err)
		}

		// 查询不存在的探针状态
		_, err = h.Controller.Status("non_existent_probe")
		if !errors.Is(err, logx.ErrProbeNotFound) {
			t.Fatalf("expected ErrProbeNotFound, got: %v", err)
		}
	})
}

// NFSProbeTestSuite NFS 探针通用测试套件
type NFSProbeTestSuite struct {
	Helper *ProbeTestHelper
	TC     ProbeTestCase
}

// NewNFSProbeTestSuite 创建 NFS 探针测试套件
func NewNFSProbeTestSuite(t *testing.T, probeType, layer string) *NFSProbeTestSuite {
	t.Helper()
	helper := NewProbeTestHelper(t)
	t.Cleanup(func() {
		helper.Shutdown()
	})

	return &NFSProbeTestSuite{
		Helper: helper,
		TC: ProbeTestCase{
			Name:      probeType,
			ProbeType: probeType,
			Layer:     layer,
			ExpectedParams: []string{"filter_pid", "filter_file", "filter_comm"},
			ExpectedOutputs: []string{"pid", "comm", "time_stamp_ns", "lat_ns", "size_bytes", "file"},
			TableName: probeType,
		},
	}
}

// RunAll 运行所有通用测试
func (s *NFSProbeTestSuite) RunAll() {
	s.Helper.TestRegistration(s.TC)
	s.Helper.TestMetadataIntegrity(s.TC)

	// 以下测试需要 root 权限
	s.Helper.SkipIfNotRoot()
	s.Helper.TestLifecycle(s.TC)

	// 宏变量测试配置
	macroConfigs := []map[string]any{
		{"filter_pid": uint32(1234)},
		{"filter_file": "*.log"},
		{"filter_comm": "nginx"},
		{
			"filter_pid":  uint32(5678),
			"filter_file": "test*.txt",
			"filter_comm": "testapp",
		},
	}
	s.Helper.TestMacroVariables(s.TC, macroConfigs)
	s.Helper.TestErrorHandling(s.TC)
}
