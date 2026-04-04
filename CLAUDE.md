# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

eBPF-MCP is a Go-based middleware that bridges AI agents with eBPF kernel observability capabilities through the Model Context Protocol (MCP). It provides a standardized, secure interface for AI agents to interact with eBPF probes without directly manipulating kernel resources.

## Key Components

### 1. Probe Interface (`internal/probes/probe.go`)

All eBPF probes implement the `Probe` interface:

```go
type Probe interface {
    Name() string
    Start(ctx context.Context, dbConn *sql.DB) error
    Stop() error
    Update(config map[string]interface{}) error
    GetMetadata() ProbeMetadata
    GetStatus() ProbeStatus
    SetState(state ProbeState, errMsg ...string)
}
```

### 2. Controller (`internal/probes/controller.go`)

Central coordinator for probe lifecycle with thread-safe operations:
- `Load(ctx, name)` - Instantiate and start a probe
- `Unload(name)` - Stop a loaded probe
- `Update(name, config)` - Apply runtime parameter changes
- `Status(name)` - Get probe runtime state
- `Shutdown()` - Stop all probes

### 3. Registry (`internal/probes/registry.go`)

Two-phase registration architecture:

**Static Registration (at startup)**:
- `LoadProbesFromYAML(baseDir)` loads metadata from `probes/*.yaml`
- Stores probe metadata (type, title, params, outputs, etc.) in `metadataRegistry`
- No probe instantiation occurs at this stage

**Dynamic Registration (at load time)**:
- `GetProbe(type)` called when AI agent requests probe loading
- Dynamically loads probe implementation from `ebpf/<layer>/<endpoint>/`
- Instantiates and starts the probe via `Controller.Load()`

This design allows AI agents to query available probes without loading them, and defer actual eBPF program loading until explicitly requested.

### 4. MCP Server (`internal/server/server.go`)

Exposes three MCP tools:
- `probe_customize` - Modify probe runtime parameters
- `system_observe_control` - Load/unload/status operations
- `probe_resource_info` - Get probe metadata and status

## Common Commands

### Building and Running

```bash
# Build the project
go build -o exe/ebpf-mcp .

# Run with STDIO transport (default)
go run .

# Run with HTTP transport
sudo go run . -transport http -port 8080 -token <auth_token>

# Run with debug logging
go run . -debug
```

### Testing

```bash
# Run all tests
go test ./...

# Run tests with race detection
go test -race ./...

# Run independent probe test(require sudo)
sudo -E go test -count=1 ./test/probes -v

# Run specific test
go test -v ./internal/probes -run TestController

# Clean test cache 
make clean-testcache

# Clean log
make clean-log
```

### Code Quality

```bash
# Format code
gofmt -w .
goimports -w .

# Static analysis
go vet ./...

# Tidy dependencies
go mod tidy
```

## Environment Variables

- `MCP_AUTH_TOKEN` - HTTP transport authentication token
- `EBPF_MCP_DUCKDB_PATH` - DuckDB database path (default: `database/ebpf-mcp.duckdb`)
- `MCP_LOG_SCENARIO` - Custom logging scenario name

## Project Structure

```
.
├── main.go                    # Application entry point
├── go.mod                     # Go module definition
├── Makefile                   # Build automation
├── probes/                    # YAML probe configurations (static metadata)
│   ├── nfs-file-read.yaml
│   └── nfs-file-write.yaml
├── ebpf/                      # eBPF C programs and Go implementations
│   ├── headers/               # BPF helper definitions
│   └── <layer>/               # Layer-specific probes (e.g., NFS-client)
│       └── <endpoint>/        # Endpoint-specific probe directory
│           ├── *.c            # eBPF C code
│           ├── probe.go       # Go probe implementation
│           └── bpf_*.go       # Generated ebpf-go bindings
├── internal/
│   ├── probes/                # Probe controller, registry, interfaces
│   ├── server/                # MCP server implementation
│   ├── db/                    # DuckDB utilities
│   ├── logx/                  # Structured logging and error handling
│   └── audit/                 # Audit logging contracts
├── test/
│   ├── integration/          # Integration and E2E tests
│   └── probes/               # Probe-specific tests with reusable test framework
│       ├── helper_test.go    # Test helper utilities
│       ├── nfs_file_read_test.go
│       └── nfs_file_write_test.go
└── database/                  # DuckDB database files
```



## Probe Registration Architecture

The system uses a **two-phase registration** design to separate probe discovery from probe execution:

### Phase 1: Static Registration (Startup)

At server startup, `main.go` calls `probes.LoadProbesFromYAML()`:

1. Scans `probes/*.yaml` files
2. Parses probe metadata (type, title, layer, params, outputs, risks)
3. Stores metadata in `metadataRegistry` (in-memory map)
4. **No eBPF programs are loaded at this stage**

This allows AI agents to query available probes via `probe_resource_info` tool without any kernel operations.

### Phase 2: Dynamic Registration (Load Time)

When AI agent calls `system_observe_control` with `action=load`:

1. `Controller.Load(type)` is invoked
2. `GetProbe(type)` locates probe implementation in `ebpf/<layer>/<type>/`
3. Probe instance is created and `Start()` is called
4. eBPF programs are loaded into kernel
5. Probe state transitions: `unloaded` → `loaded`


### Benefits

- **Lazy loading**: eBPF programs only loaded when explicitly requested
- **Discovery without privileges**: AI agents can browse available probes without root
- **Decoupled metadata**: Probe descriptions and parameters defined in YAML, not code
- **Easy extension**: New probes only need YAML + implementation directory


