//go:generate go run ./cmd/probe-registry-gen

package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	// 自动导入所有探针包以触发 init() 注册
	_ "ebpf-mcp/internal/probes/registry"
	"ebpf-mcp/internal/probes"
	"ebpf-mcp/internal/server"
	_ "github.com/duckdb/duckdb-go/v2"
)

func main() {
	var transport string
	var port string
	var token string
	var debug bool

	flag.StringVar(&transport, "transport", server.TransportStdio, "transport type: stdio or http")
	flag.StringVar(&port, "port", "8080", "http port")
	flag.StringVar(&token, "token", "", "bearer token for http transport")
	flag.BoolVar(&debug, "debug", false, "enable debug mode")
	flag.Parse()

	if token == "" {
		token = os.Getenv("MCP_AUTH_TOKEN")
	}
	dbPath := os.Getenv("EBPF_MCP_DUCKDB_PATH")
	if dbPath == "" {
		dbPath = "database/ebpf-mcp.duckdb"
	}

	dbPath, err := resolveDuckDBPath(dbPath)
	if err != nil {
		log.Fatalf("failed to resolve duckdb path: %v", err)
	}

	// 加载探针静态元数据（从YAML配置文件）
	// 这是探针的静态注册阶段，仅加载元数据到registry，不实例化探针
	repoRoot, err := findRepoRoot()
	if err != nil {
		log.Printf("warning: failed to find repo root: %v", err)
	} else {
		if err := probes.LoadProbesFromYAML(repoRoot); err != nil {
			log.Printf("warning: failed to load probe YAML configs: %v", err)
		} else {
			log.Printf("loaded probe metadata from YAML")
		}
	}

	db, err := openDuckDB(dbPath)
	if err != nil {
		log.Fatalf("failed to open duckdb: %v", err)
	}
	defer db.Close()

	controller, err := probes.NewController(db)
	if err != nil {
		log.Fatalf("failed to create probe controller: %v", err)
	}
	defer func() {
		if err := controller.Shutdown(); err != nil {
			log.Printf("failed to shutdown probes cleanly: %v", err)
		}
	}()

	cfg := server.ServerConfig{
		Transport: transport,
		HTTPPort:  port,
		AuthToken: token,
		Debug:     debug,
	}

	s, err := server.New(cfg, controller)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := s.Start(ctx); err != nil {
		log.Fatalf("server stopped with error: %v", err)
	}
}

func openDuckDB(dbPath string) (*sql.DB, error) {
	dir := filepath.Dir(dbPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}

	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureDuckDBOwnership(dbPath); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func ensureDuckDBOwnership(dbPath string) error {
	if os.Geteuid() != 0 {
		return nil
	}

	owner := os.Getenv("SUDO_USER")
	if owner == "" {
		owner = "shasha"
	}

	u, err := user.Lookup(owner)
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}

	if err := os.Chown(dbPath, uid, gid); err != nil {
		return err
	}

	return nil
}

func resolveDuckDBPath(dbPath string) (string, error) {
	if filepath.IsAbs(dbPath) {
		return dbPath, nil
	}

	repoRoot, err := findRepoRoot()
	if err == nil {
		return filepath.Join(repoRoot, dbPath), nil
	}

	return filepath.Abs(dbPath)
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, statErr := os.Stat(filepath.Join(wd, "go.mod")); statErr == nil {
			return wd, nil
		}

		parent := filepath.Dir(wd)
		if parent == wd {
			return "", os.ErrNotExist
		}
		wd = parent
	}
}
