//go:build linux

package probes

import (
	"os"
	"testing"
	"time"

	_ "ebpf-mcp/ebpf/SVC/svc_rqst_latency"
	"ebpf-mcp/internal/probes"
)

// TestSvcRqstLatencyProbe_Registration 验证探针已正确注册
func TestSvcRqstLatencyProbe_Registration(t *testing.T) {
	// 验证探针已注册
	if !probes.HasProbe("svc_rqst_latency") {
		t.Fatal("svc_rqst_latency probe should be registered")
	}

	// 验证可以通过工厂创建实例
	probe, ok := probes.GetProbe("svc_rqst_latency")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	// 验证探针名称
	if probe.Name() != "svc_rqst_latency" {
		t.Errorf("expected probe name 'svc_rqst_latency', got '%s'", probe.Name())
	}
}

// TestSvcRqstLatencyProbe_MetadataIntegrity 验证探针元数据完整性
func TestSvcRqstLatencyProbe_MetadataIntegrity(t *testing.T) {
	probe, ok := probes.GetProbe("svc_rqst_latency")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	metadata := probe.GetMetadata()

	// 验证基本字段
	if metadata.Type != "svc_rqst_latency" {
		t.Errorf("expected type 'svc_rqst_latency', got '%s'", metadata.Type)
	}

	if metadata.Layer != "SVC" {
		t.Errorf("expected layer 'SVC', got '%s'", metadata.Layer)
	}

	// 验证入口点
	if len(metadata.Entrypoints) != 2 {
		t.Errorf("expected 2 entrypoints, got %d", len(metadata.Entrypoints))
	}

	foundProcess := false
	foundSend := false
	for _, ep := range metadata.Entrypoints {
		if ep == "svc_process" {
			foundProcess = true
		}
		if ep == "svc_send" {
			foundSend = true
		}
	}
	if !foundProcess {
		t.Error("expected entrypoint 'svc_process' not found")
	}
	if !foundSend {
		t.Error("expected entrypoint 'svc_send' not found")
	}

	// 验证输出字段
	if len(metadata.Outputs.Fields) != 3 {
		t.Errorf("expected 3 output fields, got %d", len(metadata.Outputs.Fields))
	}

	expectedFields := map[string]string{
		"xid":             "u32",
		"latency":         "u64",
		"start_timestamp": "u64",
	}

	for name, expectedType := range expectedFields {
		found := false
		for _, field := range metadata.Outputs.Fields {
			if field.Name == name {
				found = true
				if field.Type != expectedType {
					t.Errorf("expected field '%s' to have type '%s', got '%s'", name, expectedType, field.Type)
				}
				break
			}
		}
		if !found {
			t.Errorf("expected output field '%s' not found", name)
		}
	}

	// 验证无参数
	if len(metadata.Params) != 0 {
		t.Errorf("expected 0 params, got %d", len(metadata.Params))
	}
}

// TestSvcRqstLatencyProbe_MacroVariables 验证宏变量（本探针无过滤参数）
func TestSvcRqstLatencyProbe_MacroVariables(t *testing.T) {
	probe, ok := probes.GetProbe("svc_rqst_latency")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	metadata := probe.GetMetadata()

	// 验证无过滤参数
	if len(metadata.Params) != 0 {
		t.Errorf("expected 0 filter params, got %d", len(metadata.Params))
	}

	// 验证 Update 方法接受空配置
	if err := probe.Update(map[string]interface{}{}); err != nil {
		t.Errorf("Update with empty config should not fail: %v", err)
	}

	// 验证 Update 方法接受 nil 配置
	if err := probe.Update(nil); err != nil {
		t.Errorf("Update with nil config should not fail: %v", err)
	}
}

// TestSvcRqstLatencyProbe_Lifecycle 验证探针生命周期
func TestSvcRqstLatencyProbe_Lifecycle(t *testing.T) {
	helper := NewProbeTestHelper(t)
	defer helper.Shutdown()

	tc := ProbeTestCase{
		Name:            "SvcRqstLatency",
		ProbeType:       "svc_rqst_latency",
		Layer:           "SVC",
		ExpectedParams:  []string{},
		ExpectedOutputs: []string{"xid", "latency", "start_timestamp"},
		TableName:       "svc_rqst_latency",
	}

	helper.TestRegistration(tc)
	// Note: helper.TestMetadataIntegrity 要求 Params 非空，本探针无参数，跳过

	// 以下测试需要 root 权限
	if os.Geteuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	helper.TestLifecycle(tc)
	helper.TestErrorHandling(tc)
}

// TestSvcRqstLatencyProbe_FastStop 验证探针能在500ms内停止
func TestSvcRqstLatencyProbe_FastStop(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	helper := NewProbeTestHelper(t)
	defer helper.Shutdown()

	ctx := t.Context()

	// 加载探针
	_, err := helper.Controller.Load(ctx, "svc_rqst_latency")
	if err != nil {
		t.Fatalf("failed to load probe: %v", err)
	}

	// 快速停止
	done := make(chan error, 1)
	go func() {
		_, err := helper.Controller.Unload("svc_rqst_latency")
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("failed to unload probe: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("probe stop took too long (>500ms), possible deadlock")
	}
}
