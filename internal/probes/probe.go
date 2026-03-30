package probes

import (
	"context"
	"database/sql"
)

// ProbeState 表示探针的状态
type ProbeState string

const (
	StateUnloaded ProbeState = "unloaded"
	StateLoaded   ProbeState = "loaded"
	StateError    ProbeState = "error"
)

// ParamField 表示探针参数字段定义
type ParamField struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type" yaml:"type"`
	Description string `json:"description" yaml:"description"`
	Optional    bool   `json:"optional" yaml:"optional"`
	Example     string `json:"example,omitempty" yaml:"example,omitempty"`
}

// OutputField 表示探针输出字段定义
type OutputField struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type" yaml:"type"`
	Description string `json:"description" yaml:"description"`
}

// ProbeMetadata 包含探针的静态元数据（来自YAML配置）
type ProbeMetadata struct {
	Type        string        `json:"type" yaml:"type"` // 探针类型标识，如 nfs_file_read
	Title       string        `json:"title" yaml:"title"`
	Layer       string        `json:"layer" yaml:"layer"`
	Level       string        `json:"level" yaml:"level"`
	Scene       string        `json:"scene" yaml:"scene"`
	Entrypoints []string      `json:"entrypoints" yaml:"entrypoints"`
	Params      []ParamField  `json:"params" yaml:"params"`
	Outputs     OutputConfig  `json:"outputs" yaml:"outputs"`
	Risks       string        `json:"risks" yaml:"risks"`
}

// OutputConfig 表示输出配置
type OutputConfig struct {
	Fields []OutputField `json:"fields" yaml:"fields"`
}

// ProbeStatus 表示探针运行时状态
type ProbeStatus struct {
	State     ProbeState `json:"state"`
	Loaded    bool       `json:"loaded"`
	LastError string     `json:"last_error,omitempty"`
}

// ProbeInfo 包含探针的完整信息（元数据+状态）
type ProbeInfo struct {
	Metadata ProbeMetadata `json:"metadata"`
	Status   ProbeStatus   `json:"status"`
}

// Probe defines the interface for eBPF probes
type Probe interface {
	Name() string
	Start(ctx context.Context, dbConn *sql.DB) error
	Stop() error
	Update(config map[string]interface{}) error

	// 新增接口方法
	GetMetadata() ProbeMetadata
	GetStatus() ProbeStatus
	SetState(state ProbeState, errMsg ...string)

	// Flush 强制将缓冲区中的数据写入数据库
	Flush() error
}

// BaseProbe 提供Probe接口的基础实现，可被具体探针嵌入
type BaseProbe struct {
	metadata ProbeMetadata
	status   ProbeStatus
}

// NewBaseProbe 创建基础探针，从YAML加载元数据
func NewBaseProbe(metadata ProbeMetadata) BaseProbe {
	return BaseProbe{
		metadata: metadata,
		status: ProbeStatus{
			State:  StateUnloaded,
			Loaded: false,
		},
	}
}

// GetMetadata 返回探针元数据
func (b *BaseProbe) GetMetadata() ProbeMetadata {
	return b.metadata
}

// GetStatus 返回探针状态
func (b *BaseProbe) GetStatus() ProbeStatus {
	return b.status
}

// SetState 设置探针状态
func (b *BaseProbe) SetState(state ProbeState, errMsg ...string) {
	b.status.State = state
	b.status.Loaded = (state == StateLoaded)
	if len(errMsg) > 0 {
		b.status.LastError = errMsg[0]
	} else {
		b.status.LastError = ""
	}
}

// GetID 返回探针类型标识
func (b *BaseProbe) GetID() string {
	return b.metadata.Type
}

// GetTitle 返回探针标题
func (b *BaseProbe) GetTitle() string {
	return b.metadata.Title
}

// Flush 默认实现，具体探针可以覆盖此方法
func (b *BaseProbe) Flush() error {
	// 默认实现为空，具体探针需要覆盖此方法
	return nil
}