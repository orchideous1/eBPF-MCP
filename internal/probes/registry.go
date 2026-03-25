package probes

import (
	"fmt"
	"sync"
)

var (
	registryMu sync.RWMutex
	registry   = make(map[string]func() Probe)
)

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

// ListProbes returns the names of all registered probes.
func ListProbes() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var probes []string
	for k := range registry {
		probes = append(probes, k)
	}
	return probes
}
