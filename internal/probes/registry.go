package probes

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const (
	// ProbesDir 是探针YAML配置文件所在目录
	ProbesDir = "probes"
)

var (
	registryMu sync.RWMutex
	// registry 存储探针工厂函数
	registry = make(map[string]func() Probe)
	// metadataRegistry 存储从YAML加载的探针元数据
	metadataRegistry = make(map[string]ProbeMetadata)
)

// ProbeConfigFile 表示YAML配置文件顶层结构
type ProbeConfigFile struct {
	Probes []ProbeMetadata `yaml:"probes"`
}

// LoadProbesFromYAML 从probes目录加载所有YAML配置文件
func LoadProbesFromYAML(baseDir string) error {
	probesPath := filepath.Join(baseDir, ProbesDir)

	entries, err := os.ReadDir(probesPath)
	if err != nil {
		return fmt.Errorf("读取probes目录失败: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}

		filePath := filepath.Join(probesPath, entry.Name())
		if err := loadYAMLFile(filePath); err != nil {
			return fmt.Errorf("加载YAML文件 %s 失败: %w", entry.Name(), err)
		}
	}

	return nil
}

// loadYAMLFile 加载单个YAML文件，仅注册静态元数据
// 探针的动态实例化在加载时由 controller 完成
func loadYAMLFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	var config ProbeConfigFile
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析YAML失败: %w", err)
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	for _, probe := range config.Probes {
		if probe.Type == "" {
			continue
		}
		// 仅存储元数据（静态注册）
		// 探针工厂在加载时动态创建
		metadataRegistry[probe.Type] = probe
	}

	return nil
}

// GetProbeMetadata 获取探针的元数据
func GetProbeMetadata(name string) (ProbeMetadata, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	meta, exists := metadataRegistry[name]
	return meta, exists
}

// GetProbeInfo 获取探针的完整信息（元数据+运行时状态）
// 如果探针已加载，会合并其运行时状态
func GetProbeInfo(name string, status *ProbeStatus) (ProbeInfo, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	meta, exists := metadataRegistry[name]
	if !exists {
		return ProbeInfo{}, false
	}

	info := ProbeInfo{
		Metadata: meta,
		Status: ProbeStatus{
			State:  StateUnloaded,
			Loaded: false,
		},
	}

	// 如果提供了运行时状态，则使用它
	if status != nil {
		info.Status = *status
	}

	return info, true
}

// ListProbeInfos 列出所有探针的完整信息
func ListProbeInfos(statusMap map[string]ProbeStatus) []ProbeInfo {
	registryMu.RLock()
	defer registryMu.RUnlock()

	infos := make([]ProbeInfo, 0, len(metadataRegistry))
	for probeType, meta := range metadataRegistry {
		info := ProbeInfo{
			Metadata: meta,
			Status: ProbeStatus{
				State:  StateUnloaded,
				Loaded: false,
			},
		}

		// 合并运行时状态
		if status, ok := statusMap[probeType]; ok {
			info.Status = status
		}

		infos = append(infos, info)
	}

	return infos
}

// Register registers a new probe factory.
func Register(name string, factory func() Probe) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("probe already registered: %s", name))
	}
	registry[name] = factory
}

// GetProbe retrieves a probe by using its factory.
// 探针工厂通过 probe_registry_gen.go 自动导入并注册
func GetProbe(name string) (Probe, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	factory, exists := registry[name]
	if !exists {
		return nil, false
	}

	return factory(), true
}

// HasProbe reports whether a probe factory is registered.
func HasProbe(name string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, exists := registry[name]
	return exists
}

// HasMetadata reports whether a probe metadata is loaded from YAML.
func HasMetadata(name string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, exists := metadataRegistry[name]
	return exists
}

// ListProbes returns the names of all registered probes.
func ListProbes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	// 合并registry和metadataRegistry中的所有探针名称
	probeSet := make(map[string]struct{})
	for k := range registry {
		probeSet[k] = struct{}{}
	}
	for k := range metadataRegistry {
		probeSet[k] = struct{}{}
	}

	var probes []string
	for k := range probeSet {
		probes = append(probes, k)
	}
	return probes
}

// ListProbeTypes 返回所有从YAML加载的探针类型
func ListProbeTypes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var types []string
	for k := range metadataRegistry {
		types = append(types, k)
	}
	return types
}
