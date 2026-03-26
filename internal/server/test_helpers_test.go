package server

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"ebpf-mcp/internal/probes"
	_ "github.com/duckdb/duckdb-go/v2"
)

// openTestDB creates a temporary DuckDB database for testing.
func openTestDB() (*sql.DB, error) {
	dbPath := filepath.Join(os.TempDir(), "ebpf-mcp-test-*.duckdb")
	f, err := os.CreateTemp("", filepath.Base(dbPath))
	if err != nil {
		return nil, err
	}
	f.Close()

	db, err := sql.Open("duckdb", f.Name())
	if err != nil {
		os.Remove(f.Name())
		return nil, err
	}
	return db, nil
}

// newTestServer creates a test server with a mock controller.
func newTestServer(t *testing.T) *Server {
	db, err := openTestDB()
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})

	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}

	s, err := New(ServerConfig{Transport: TransportStdio}, controller)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	return s
}
