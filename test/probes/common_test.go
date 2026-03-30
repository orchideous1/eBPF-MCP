//go:build linux

package probes

import (
	"database/sql"
	"path/filepath"
	"runtime"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2"

	"ebpf-mcp/internal/probes"
)

func init() {
	// 从项目根目录加载 YAML 配置文件
	_, filename, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	if err := probes.LoadProbesFromYAML(projectRoot); err != nil {
		panic("failed to load probes from YAML: " + err.Error())
	}
}

// openTestDB 创建临时 DuckDB 数据库
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})
	return db
}
