package probes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
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

// dbWriteProbe is a probe that creates a table and inserts one row on Start.
type dbWriteProbe struct {
	BaseProbe
	name string
}

func (p *dbWriteProbe) Name() string { return p.name }

func (p *dbWriteProbe) Start(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS test_events (id INTEGER)"); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO test_events VALUES (42)"); err != nil {
		return err
	}
	p.SetState(StateLoaded)
	return nil
}

func (p *dbWriteProbe) Stop() error {
	p.SetState(StateUnloaded)
	return nil
}

func (p *dbWriteProbe) Update(map[string]interface{}) error { return nil }

func (p *dbWriteProbe) Flush() error { return nil }

func TestControllerLazyDBLifecycle(t *testing.T) {
	dbDir := t.TempDir()

	controller, err := NewController(nil)
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}

	// 模拟带时间戳的数据库文件创建
	dbOpener := func(dir string) (*sql.DB, error) {
		timestamp := time.Now().Format("20060102-150405")
		dbPath := filepath.Join(dir, fmt.Sprintf("test.%s.duckdb", timestamp))
		db2, err := sql.Open("duckdb", dbPath)
		if err != nil {
			return nil, err
		}
		if err := db2.Ping(); err != nil {
			_ = db2.Close()
			return nil, err
		}
		return db2, nil
	}
	controller.EnableLazyDB(dbDir, dbOpener)

	name := fmt.Sprintf("db_write_probe_%d", atomic.AddUint64(&testProbeCounter, 1))
	Register(name, func() Probe {
		return &dbWriteProbe{name: name}
	})

	ctx := context.Background()

	// Step 1: Load probe -> should auto open db, write data
	st, err := controller.Load(ctx, name)
	if err != nil {
		t.Fatalf("load probe: %v", err)
	}
	if st.State != "loaded" {
		t.Fatalf("expected loaded state, got %+v", st)
	}

	if controller.db == nil {
		t.Fatalf("expected db to be open after load")
	}

	// Step 2: Unload probe -> should auto close db
	st, err = controller.Unload(name)
	if err != nil {
		t.Fatalf("unload probe: %v", err)
	}
	if st.State != "unloaded" {
		t.Fatalf("expected unloaded state, got %+v", st)
	}

	if controller.db != nil {
		t.Fatalf("expected db to be closed after last probe unloaded")
	}

	// Step 3: Reload probe -> should auto reopen a new db (timestamped filename)
	st, err = controller.Load(ctx, name)
	if err != nil {
		t.Fatalf("reload probe: %v", err)
	}
	if st.State != "loaded" {
		t.Fatalf("expected loaded state after reload, got %+v", st)
	}
	if controller.db == nil {
		t.Fatalf("expected db to be reopened after reload")
	}

	// Cleanup
	if _, err := controller.Unload(name); err != nil {
		t.Fatalf("final unload: %v", err)
	}
}
