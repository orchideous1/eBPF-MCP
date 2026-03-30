package probes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
)

var testProbeCounter uint64

type stubProbe struct {
	BaseProbe
	name       string
	startErr   error
	stopErr    error
	updateErr  error
	startCalls int
	stopCalls  int
}

func (p *stubProbe) Name() string { return p.name }

func (p *stubProbe) Start(context.Context, *sql.DB) error {
	p.startCalls++
	if p.startErr != nil {
		p.SetState(StateError, p.startErr.Error())
		return p.startErr
	}
	p.SetState(StateLoaded)
	return nil
}

func (p *stubProbe) Stop() error {
	p.stopCalls++
	if p.stopErr != nil {
		p.SetState(StateError, p.stopErr.Error())
		return p.stopErr
	}
	p.SetState(StateUnloaded)
	return nil
}

func (p *stubProbe) Update(map[string]interface{}) error {
	return p.updateErr
}

func registerStubProbe(t *testing.T, factory func() Probe) string {
	t.Helper()
	name := fmt.Sprintf("stub_probe_%d", atomic.AddUint64(&testProbeCounter, 1))
	Register(name, factory)
	return name
}

func TestControllerLifecycle(t *testing.T) {
	probe := &stubProbe{}
	name := registerStubProbe(t, func() Probe {
		probe.name = ""
		return probe
	})
	probe.name = name

	controller, err := NewController(&sql.DB{})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}

	st, err := controller.Load(context.Background(), name)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !st.Loaded || st.State != "loaded" {
		t.Fatalf("unexpected state after load: %+v", st)
	}

	if _, err := controller.Update(name, map[string]any{"k": "v"}); err != nil {
		t.Fatalf("update: %v", err)
	}

	st, err = controller.Status(name)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !st.Loaded {
		t.Fatalf("expected loaded status: %+v", st)
	}

	st, err = controller.Unload(name)
	if err != nil {
		t.Fatalf("unload: %v", err)
	}
	if st.Loaded || st.State != "unloaded" {
		t.Fatalf("unexpected state after unload: %+v", st)
	}

	if probe.startCalls != 1 {
		t.Fatalf("expected one start call, got %d", probe.startCalls)
	}
	if probe.stopCalls != 1 {
		t.Fatalf("expected one stop call, got %d", probe.stopCalls)
	}
}

func TestControllerConflicts(t *testing.T) {
	name := registerStubProbe(t, func() Probe { return &stubProbe{name: "tmp"} })
	controller, err := NewController(&sql.DB{})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}

	if _, err := controller.Load(context.Background(), name); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := controller.Load(context.Background(), name); !errors.Is(err, ErrProbeAlreadyLoaded) {
		t.Fatalf("expected ErrProbeAlreadyLoaded, got %v", err)
	}

	if _, err := controller.Unload(name); err != nil {
		t.Fatalf("unload: %v", err)
	}
	if _, err := controller.Unload(name); !errors.Is(err, ErrProbeNotLoaded) {
		t.Fatalf("expected ErrProbeNotLoaded, got %v", err)
	}
}

func TestControllerNotFound(t *testing.T) {
	controller, err := NewController(&sql.DB{})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}

	if _, err := controller.Load(context.Background(), "not_registered"); !errors.Is(err, ErrProbeNotFound) {
		t.Fatalf("expected ErrProbeNotFound on load, got %v", err)
	}
	if _, err := controller.Status("not_registered"); !errors.Is(err, ErrProbeNotFound) {
		t.Fatalf("expected ErrProbeNotFound on status, got %v", err)
	}
	if _, err := controller.Update("not_registered", map[string]any{"a": 1}); !errors.Is(err, ErrProbeNotFound) {
		t.Fatalf("expected ErrProbeNotFound on update, got %v", err)
	}
}
