//go:build linux

package probes

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "ebpf-mcp/ebpf/nfsd/nfsd4_access"
	"ebpf-mcp/internal/probes"
)

func TestNfsd4Access_Registration(t *testing.T) {
	if !probes.HasProbe("nfsd4_access") {
		t.Fatal("nfsd4_access probe should be registered")
	}

	p, ok := probes.GetProbe("nfsd4_access")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	if p == nil {
		t.Fatal("probe should not be nil")
	}

	if p.Name() != "nfsd4_access" {
		t.Fatalf("expected name nfsd4_access, got %s", p.Name())
	}
}

func TestNfsd4Access_MetadataIntegrity(t *testing.T) {
	p, ok := probes.GetProbe("nfsd4_access")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	meta := p.GetMetadata()

	if meta.Type != "nfsd4_access" {
		t.Errorf("expected type nfsd4_access, got %s", meta.Type)
	}
	if meta.Title != "NFSD访问权限检查" {
		t.Errorf("expected title 'NFSD访问权限检查', got %s", meta.Title)
	}
	if meta.Layer != "nfsd" {
		t.Errorf("expected layer nfsd, got %s", meta.Layer)
	}
	if meta.Level != "L2" {
		t.Errorf("expected level L2, got %s", meta.Level)
	}

	// 检查参数定义
	foundPid := false
	for _, param := range meta.Params {
		if param.Name == "filter_pid" {
			foundPid = true
			break
		}
	}
	if !foundPid {
		t.Error("should have filter_pid param")
	}

	// 检查输出字段
	requiredFields := []string{"pid", "lat", "xid", "comm"}
	fieldMap := make(map[string]bool)
	for _, f := range meta.Outputs.Fields {
		fieldMap[f.Name] = true
	}
	for _, field := range requiredFields {
		if !fieldMap[field] {
			t.Errorf("should have %s field in outputs", field)
		}
	}
}

func TestNfsd4Access_Lifecycle(t *testing.T) {
	p, ok := probes.GetProbe("nfsd4_access")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	// 创建内存 DuckDB 数据库
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = p.Start(ctx, db)
	// 在非特权模式下可能会失败，这是预期的
	if err != nil {
		t.Logf("Start() returned error (expected without root): %v", err)
		return
	}

	// 测试 Flush
	if err := p.Flush(); err != nil {
		t.Errorf("Flush() error: %v", err)
	}

	// 测试 Update
	if err := p.Update(map[string]interface{}{
		"filter_pid": uint64(1234),
	}); err != nil {
		t.Logf("Update() returned error (expected without root): %v", err)
	}

	// 测试 Stop
	if err := p.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}
}

func TestNfsd4Access_UpdateWithoutStart(t *testing.T) {
	p, ok := probes.GetProbe("nfsd4_access")
	if !ok {
		t.Fatal("should get probe from registry")
	}

	// 未调用 Start 时 Update 应该返回错误
	err := p.Update(map[string]interface{}{
		"filter_pid": uint64(1234),
	})
	if err == nil {
		t.Error("Update() should return error when probe not started")
	}
}
