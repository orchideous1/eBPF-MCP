package integration

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"

	"ebpf-mcp/internal/probes"
)

// MockProbe 是用于 E2E 测试的内存探针实现
// 无 eBPF 依赖，可在非 root 环境运行
type MockProbe struct {
	probes.BaseProbe
	name        string
	startCalls  atomic.Int32
	stopCalls   atomic.Int32
	updateCalls atomic.Int32
	lastConfig  map[string]any
	shouldError bool // 用于测试错误场景
	errorMsg    string
}

// NewMockProbe 创建一个新的 Mock 探针
func NewMockProbe(name string) *MockProbe {
	return &MockProbe{
		name:        name,
		lastConfig:  make(map[string]any),
		shouldError: false,
		errorMsg:    "",
	}
}

// Name 返回探针名称
func (p *MockProbe) Name() string {
	return p.name
}

// Start 模拟启动探针
func (p *MockProbe) Start(ctx context.Context, dbConn *sql.DB) error {
	if p.shouldError {
		return errors.New("runtime failure")
	}
	p.startCalls.Add(1)
	return nil
}

// Stop 模拟停止探针
func (p *MockProbe) Stop() error {
	if p.shouldError {
		return errors.New("runtime failure")
	}
	p.stopCalls.Add(1)
	return nil
}

// Update 模拟更新探针配置
func (p *MockProbe) Update(config map[string]interface{}) error {
	if p.shouldError {
		return errors.New("runtime failure")
	}
	p.updateCalls.Add(1)
	p.lastConfig = config
	return nil
}

// Flush 模拟刷新探针缓冲区
func (p *MockProbe) Flush() error {
	return nil
}

// GetStartCalls 返回 Start 被调用的次数
func (p *MockProbe) GetStartCalls() int32 {
	return p.startCalls.Load()
}

// GetStopCalls 返回 Stop 被调用的次数
func (p *MockProbe) GetStopCalls() int32 {
	return p.stopCalls.Load()
}

// GetUpdateCalls 返回 Update 被调用的次数
func (p *MockProbe) GetUpdateCalls() int32 {
	return p.updateCalls.Load()
}

// GetLastConfig 返回最后一次更新的配置
func (p *MockProbe) GetLastConfig() map[string]any {
	return p.lastConfig
}

// SetShouldError 设置是否模拟错误场景
func (p *MockProbe) SetShouldError(shouldError bool) {
	p.shouldError = shouldError
}

// Reset 重置探针状态
func (p *MockProbe) Reset() {
	p.startCalls.Store(0)
	p.stopCalls.Store(0)
	p.updateCalls.Store(0)
	p.lastConfig = make(map[string]any)
	p.shouldError = false
	p.errorMsg = ""
}

// mockProbeFactory 是创建 MockProbe 的工厂函数类型
type mockProbeFactory struct {
	probe *MockProbe
}

// newMockProbeFactory 创建一个新的 Mock 探针工厂
func newMockProbeFactory(name string) *mockProbeFactory {
	return &mockProbeFactory{
		probe: NewMockProbe(name),
	}
}

// Create 创建探针实例
func (f *mockProbeFactory) Create() probes.Probe {
	return f.probe
}

// GetProbe 获取工厂创建的探针实例（用于验证）
func (f *mockProbeFactory) GetProbe() *MockProbe {
	return f.probe
}
