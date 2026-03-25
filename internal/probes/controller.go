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
	probes   map[string]Probe
	statuses map[string]Status
}

// NewController creates a controller bound to one shared database handle.
func NewController(db *sql.DB) (*Controller, error) {
	if db == nil {
		return nil, fmt.Errorf("db is nil")
	}
	return &Controller{
		db:       db,
		probes:   make(map[string]Probe),
		statuses: make(map[string]Status),
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
		return Status{}, ErrProbeNotFound
	}

	if err := probe.Start(ctx, c.db); err != nil {
		st := Status{Name: name, State: "error", Loaded: false, LastError: err.Error()}
		c.statuses[name] = st
		return st, fmt.Errorf("start probe %s: %w", name, err)
	}

	c.probes[name] = probe
	st := Status{Name: name, State: "loaded", Loaded: true}
	c.statuses[name] = st
	return st, nil
}

// Unload stops one loaded probe.
func (c *Controller) Unload(name string) (Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	probe, loaded := c.probes[name]
	if !loaded {
		if !HasProbe(name) {
			return Status{}, ErrProbeNotFound
		}
		return c.statusLocked(name), ErrProbeNotLoaded
	}

	if err := probe.Stop(); err != nil {
		st := Status{Name: name, State: "error", Loaded: true, LastError: err.Error()}
		c.statuses[name] = st
		return st, fmt.Errorf("stop probe %s: %w", name, err)
	}

	delete(c.probes, name)
	st := Status{Name: name, State: "unloaded", Loaded: false}
	c.statuses[name] = st
	return st, nil
}

// Status returns runtime state for one probe.
func (c *Controller) Status(name string) (Status, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if _, loaded := c.probes[name]; loaded {
		return c.statusLocked(name), nil
	}
	if st, ok := c.statuses[name]; ok {
		return st, nil
	}
	if !HasProbe(name) {
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
		if st, ok := c.statuses[name]; ok {
			statuses = append(statuses, st)
			continue
		}
		if _, loaded := c.probes[name]; loaded {
			statuses = append(statuses, Status{Name: name, State: "loaded", Loaded: true})
			continue
		}
		statuses = append(statuses, Status{Name: name, State: "unloaded", Loaded: false})
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
		if !HasProbe(name) {
			return Status{}, ErrProbeNotFound
		}
		return c.statusLocked(name), ErrProbeNotLoaded
	}

	if err := probe.Update(config); err != nil {
		st := Status{Name: name, State: "error", Loaded: true, LastError: err.Error()}
		c.statuses[name] = st
		return st, fmt.Errorf("update probe %s: %w", name, err)
	}

	st := Status{Name: name, State: "loaded", Loaded: true}
	c.statuses[name] = st
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
			c.statuses[name] = Status{Name: name, State: "error", Loaded: true, LastError: err.Error()}
			continue
		}
		c.statuses[name] = Status{Name: name, State: "unloaded", Loaded: false}
	}
	c.probes = make(map[string]Probe)
	return shutdownErr
}

func (c *Controller) statusLocked(name string) Status {
	if st, ok := c.statuses[name]; ok {
		return st
	}
	if _, loaded := c.probes[name]; loaded {
		return Status{Name: name, State: "loaded", Loaded: true}
	}
	return Status{Name: name, State: "unloaded", Loaded: false}
}
