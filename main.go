package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	_ "ebpf-mcp/ebpf/NFS-client"
	"ebpf-mcp/internal/probes"
	"ebpf-mcp/internal/server"
	_ "github.com/duckdb/duckdb-go/v2"
)

func main() {
	var transport string
	var port string
	var token string
	var debug bool
	var allowLoad bool
	var loaderSocket string

	flag.StringVar(&transport, "transport", server.TransportStdio, "transport type: stdio or http")
	flag.StringVar(&port, "port", "8080", "http port")
	flag.StringVar(&token, "token", "", "bearer token for http transport")
	flag.BoolVar(&debug, "debug", false, "enable debug mode")
	flag.BoolVar(&allowLoad, "allow-load", true, "allow probe load operation")
	flag.StringVar(&loaderSocket, "loader-socket", "", "unix socket path for privileged loader executor")
	flag.Parse()

	if token == "" {
		token = os.Getenv("MCP_AUTH_TOKEN")
	}
	if loaderSocket == "" {
		loaderSocket = os.Getenv("EBPF_MCP_LOADER_SOCKET")
	}
	if envAllow := os.Getenv("EBPF_MCP_ALLOW_PROBE_LOAD"); envAllow != "" {
		parsed, err := strconv.ParseBool(envAllow)
		if err != nil {
			log.Fatalf("invalid EBPF_MCP_ALLOW_PROBE_LOAD: %v", err)
		}
		allowLoad = parsed
	}

	dbPath := os.Getenv("EBPF_MCP_DUCKDB_PATH")
	if dbPath == "" {
		dbPath = "database/ebpf-mcp.duckdb"
	}

	loadAuthorizer := server.ToggleLoadAuthorizer{Allow: allowLoad}

	var (
		observeSvc   server.ObserveService
		customizeSvc server.CustomizeService
		shutdownFn   func()
	)

	if loaderSocket != "" {
		rpcExecutor, err := server.NewRPCObserveExecutor(loaderSocket)
		if err != nil {
			log.Fatalf("failed to create rpc observe executor: %v", err)
		}
		probeServices, err := server.NewProbeServicesWithExecutor(rpcExecutor, loadAuthorizer)
		if err != nil {
			log.Fatalf("failed to create probe services: %v", err)
		}
		observeSvc = probeServices
		customizeSvc = server.DisabledCustomizeService{Reason: "customization is disabled when using remote loader executor"}
		shutdownFn = func() {}
		log.Printf("using remote loader executor over unix socket: %s", loaderSocket)
	} else {
		db, err := openDuckDB(dbPath)
		if err != nil {
			log.Fatalf("failed to open duckdb: %v", err)
		}

		controller, err := probes.NewController(db)
		if err != nil {
			_ = db.Close()
			log.Fatalf("failed to create probe controller: %v", err)
		}

		probeServices, err := server.NewProbeServicesWithExecutorAndCustomizer(
			server.NewControllerObserveExecutor(controller),
			server.NewControllerProbeCustomizer(controller),
			loadAuthorizer,
		)
		if err != nil {
			_ = controller.Shutdown()
			_ = db.Close()
			log.Fatalf("failed to create probe services: %v", err)
		}
		observeSvc = probeServices
		customizeSvc = probeServices
		shutdownFn = func() {
			if err := controller.Shutdown(); err != nil {
				log.Printf("failed to shutdown probes cleanly: %v", err)
			}
			_ = db.Close()
		}
	}
	defer shutdownFn()

	cfg := server.ServerConfig{
		Transport:        transport,
		HTTPPort:         port,
		AuthToken:        token,
		Debug:            debug,
		AllowProbeLoad:   allowLoad,
		LoaderSocketPath: loaderSocket,
	}

	s, err := server.New(cfg, server.Dependencies{
		Customize: customizeSvc,
		Observe:   observeSvc,
		Audit:     server.NoopAuditLogger{},
	})
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

	return db, nil
}
