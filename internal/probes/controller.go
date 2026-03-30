package probes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"sync"
)

var (
	ErrProbeNotFound      = errors.New("probe not found")
	ErrProbeAlreadyLoaded = errors.New("probe already loaded")
	ErrProbeNotLoaded     = errors.New("probe not loaded")
)

// Status captures probe runtime state managed by Controller.
// 注意：保留此类型以兼容现有代码，但内部使用 ProbeStatus
type Status struct {
	Name      string
	State     string
	Loaded    bool
	LastError string
}

// Controller coordinates probe lifecycle and runtime updates.
type Controller struct {
	mu       sync.RWMutex
	db       *sql.DB
	probes   map[string]Probe // 已加载的探针实例
	statuses map[string]ProbeStatus
}

// NewController creates a controller bound to one shared database handle.
func NewController(db *sql.DB) (*Controller, error) {
	if db == nil {
		return nil, fmt.Errorf("db is nil")
	}
	return &Controller{
		db:       db,
		probes:   make(map[string]Probe),
		statuses: make(map[string]ProbeStatus),
	}, nil
}

// Load instantiates and starts a registered probe.
func (c *Controller) Load(ctx context.Context, name string) (Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, loaded := c.probes[name]; loaded {
		return c.statusLocked(name), ErrProbeAlreadyLoaded
	}
	probe, ok := GetProbe(name)
	if !ok {
		// 检查是否有元数据（YAML配置），如果没有则返回错误
		if !HasMetadata(name) {
			return Status{}, ErrProbeNotFound
		}
		return Status{}, fmt.Errorf("probe %s has metadata but no implementation registered", name)
	}

	if err := probe.Start(ctx, c.db); err != nil {
		probe.SetState(StateError, err.Error())
		st := Status{Name: name, State: "error", Loaded: false, LastError: err.Error()}
		c.statuses[name] = probe.GetStatus()
		return st, fmt.Errorf("start probe %s: %w", name, err)
	}

	probe.SetState(StateLoaded)
	c.probes[name] = probe
	c.statuses[name] = probe.GetStatus()
	st := Status{Name: name, State: "loaded", Loaded: true}
	return st, nil
}

// Unload stops one loaded probe.
func (c *Controller) Unload(name string) (Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	probe, loaded := c.probes[name]
	if !loaded {
		if !HasProbe(name) && !HasMetadata(name) {
			return Status{}, ErrProbeNotFound
		}
		return c.statusLocked(name), ErrProbeNotLoaded
	}

	if err := probe.Stop(); err != nil {
		probe.SetState(StateError, err.Error())
		st := Status{Name: name, State: "error", Loaded: true, LastError: err.Error()}
		c.statuses[name] = probe.GetStatus()
		return st, fmt.Errorf("stop probe %s: %w", name, err)
	}

	probe.SetState(StateUnloaded)
	delete(c.probes, name)
	c.statuses[name] = probe.GetStatus()
	st := Status{Name: name, State: "unloaded", Loaded: false}
	return st, nil
}

// Status returns runtime state for one probe.
func (c *Controller) Status(name string) (Status, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if probe, loaded := c.probes[name]; loaded {
		status := probe.GetStatus()
		return Status{
			Name:      name,
			State:     string(status.State),
			Loaded:    status.Loaded,
			LastError: status.LastError,
		}, nil
	}
	if st, ok := c.statuses[name]; ok {
		return Status{
			Name:      name,
			State:     string(st.State),
			Loaded:    st.Loaded,
			LastError: st.LastError,
		}, nil
	}
	if !HasProbe(name) && !HasMetadata(name) {
		return Status{}, ErrProbeNotFound
	}
	return Status{Name: name, State: "unloaded", Loaded: false}, nil
}

// ListStatus returns states for all registered probes.
func (c *Controller) ListStatus() []Status {
	c.mu.RLock()
	defer c.mu.RUnlock()

	names := ListProbes()
	statuses := make([]Status, 0, len(names))
	for _, name := range names {
		statuses = append(statuses, c.statusLocked(name))
	}
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Name < statuses[j].Name
	})
	return statuses
}

// Update applies runtime settings to one loaded probe.
func (c *Controller) Update(name string, config map[string]any) (Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	probe, loaded := c.probes[name]
	if !loaded {
		if !HasProbe(name) && !HasMetadata(name) {
			return Status{}, ErrProbeNotFound
		}
		return c.statusLocked(name), ErrProbeNotLoaded
	}

	if err := probe.Update(config); err != nil {
		probe.SetState(StateError, err.Error())
		st := Status{Name: name, State: "error", Loaded: true, LastError: err.Error()}
		c.statuses[name] = probe.GetStatus()
		return st, fmt.Errorf("update probe %s: %w", name, err)
	}

	probe.SetState(StateLoaded)
	c.statuses[name] = probe.GetStatus()
	st := Status{Name: name, State: "loaded", Loaded: true}
	return st, nil
}

// Shutdown stops all loaded probes and returns the first stopping error if any.
func (c *Controller) Shutdown() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var shutdownErr error
	for name, probe := range c.probes {
		if err := probe.Stop(); err != nil && shutdownErr == nil {
			shutdownErr = fmt.Errorf("stop probe %s: %w", name, err)
			probe.SetState(StateError, err.Error())
			c.statuses[name] = probe.GetStatus()
			continue
		}
		probe.SetState(StateUnloaded)
		c.statuses[name] = probe.GetStatus()
	}
	c.probes = make(map[string]Probe)
	return shutdownErr
}

// GetProbeInfo 获取单个探针的完整信息（元数据+运行时状态）
// 这是暴露给server的新方法
func (c *Controller) GetProbeInfo(name string) (ProbeInfo, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var status *ProbeStatus
	if probe, loaded := c.probes[name]; loaded {
		s := probe.GetStatus()
		status = &s
	} else if st, ok := c.statuses[name]; ok {
		status = &st
	}

	info, exists := GetProbeInfo(name, status)
	if !exists {
		return ProbeInfo{}, ErrProbeNotFound
	}

	return info, nil
}

// ListProbeInfos 列出所有探针的完整信息
// 这是暴露给server的新方法
func (c *Controller) ListProbeInfos() []ProbeInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 构建状态映射
	statusMap := make(map[string]ProbeStatus)
	for name, probe := range c.probes {
		statusMap[name] = probe.GetStatus()
	}
	for name, status := range c.statuses {
		if _, ok := statusMap[name]; !ok {
			statusMap[name] = status
		}
	}

	infos := ListProbeInfos(statusMap)

	// 按Type排序
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Metadata.Type < infos[j].Metadata.Type
	})

	return infos
}

// GetProbeMetadata 获取探针的静态元数据
func (c *Controller) GetProbeMetadata(name string) (ProbeMetadata, error) {
	meta, exists := GetProbeMetadata(name)
	if !exists {
		return ProbeMetadata{}, ErrProbeNotFound
	}
	return meta, nil
}

// Flush 强制将指定探针的缓冲区数据写入数据库
func (c *Controller) Flush(name string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	probe, loaded := c.probes[name]
	if !loaded {
		if !HasProbe(name) && !HasMetadata(name) {
			return ErrProbeNotFound
		}
		return ErrProbeNotLoaded
	}

	return probe.Flush()
}

func (c *Controller) statusLocked(name string) Status {
	if probe, loaded := c.probes[name]; loaded {
		status := probe.GetStatus()
		return Status{
			Name:      name,
			State:     string(status.State),
			Loaded:    status.Loaded,
			LastError: status.LastError,
		}
	}
	if st, ok := c.statuses[name]; ok {
		return Status{
			Name:      name,
			State:     string(st.State),
			Loaded:    st.Loaded,
			LastError: st.LastError,
		}
	}
	return Status{Name: name, State: "unloaded", Loaded: false}
}
