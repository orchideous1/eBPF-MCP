//go:build linux

package integration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "ebpf-mcp/ebpf/NFS-client"
	"ebpf-mcp/internal/probes"
	_ "github.com/duckdb/duckdb-go/v2"
)

func TestNFSProbeLoadAndDuckDBIngestionE2E(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges to load and attach eBPF programs")
	}

	if _, err := exec.LookPath("fio"); err != nil {
		t.Skip("fio is required for this e2e test")
	}

	mountPath, ok := findNFSMountPath()
	if !ok {
		t.Skip("no NFS mount found in /proc/mounts")
	}

	dbPath := filepath.Join(t.TempDir(), "nfs-probe-e2e.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("open duckdb: %v", err)
	}
	defer db.Close()

	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if _, err := controller.Load(ctx, "nfs_file_read"); err != nil {
		t.Fatalf("load nfs_file_read probe: %v", err)
	}

	testFile := filepath.Join(mountPath, fmt.Sprintf("ebpf_mcp_fio_%d.dat", time.Now().UnixNano()))
	defer os.Remove(testFile)

	// First run a small write workload to satisfy write-path coverage on NFS.
	if err := runFIO(ctx,
		"--name=ebpfmcp_write",
		"--filename="+testFile,
		"--rw=write",
		"--bs=4k",
		"--size=128k",
		"--ioengine=sync",
		"--iodepth=1",
		"--numjobs=1",
		"--direct=0",
	); err != nil {
		_, _ = controller.Unload("nfs_file_read")
		t.Fatalf("fio write workload failed: %v", err)
	}

	// Then run a small read workload so nfs_file_read probe emits events.
	if err := runFIO(ctx,
		"--name=ebpfmcp_read",
		"--filename="+testFile,
		"--rw=read",
		"--bs=4k",
		"--size=128k",
		"--ioengine=sync",
		"--iodepth=1",
		"--numjobs=1",
		"--direct=0",
	); err != nil {
		_, _ = controller.Unload("nfs_file_read")
		t.Fatalf("fio read workload failed: %v", err)
	}

	if _, err := controller.Unload("nfs_file_read"); err != nil {
		t.Fatalf("unload nfs_file_read probe: %v", err)
	}

	var rowCount int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM nfs_file_read").Scan(&rowCount); err != nil {
		t.Fatalf("query nfs_file_read count: %v", err)
	}

	if rowCount <= 0 {
		t.Fatalf("expected nfs_file_read table to contain events, got %d", rowCount)
	}
}

func runFIO(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "fio", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fio failed: %w, output: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func findNFSMountPath() (string, bool) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[2] == "nfs" || fields[2] == "nfs4" {
			return fields[1], true
		}
	}

	return "", false
}
