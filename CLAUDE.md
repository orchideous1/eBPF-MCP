# CLAUDE.md

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

eBPF-MCP is a Go-based middleware that bridges AI agents with eBPF kernel observability capabilities through the Model Context Protocol (MCP). It provides a standardized, secure interface for AI agents to interact with eBPF probes without directly manipulating kernel resources.

**Key Technologies:**
- Go 1.24.0
- MCP protocol (via mcp-go)
- eBPF (via cilium/ebpf)
- DuckDB for observability data storage

## Architecture

The system follows a four-layer architecture:

```
┌─────────────────────────────────────────────────────────────┐
│  Protocol Access Layer (internal/server)                    │
│  - MCP server with STDIO and HTTP transports                │
│  - Request validation, authentication, audit wrapping       │
├─────────────────────────────────────────────────────────────┤
│  Resource Semantic Layer (internal/probes)                  │
│  - Probe abstraction as standard resources                  │
│  - YAML-based probe metadata and runtime status             │
├─────────────────────────────────────────────────────────────┤
│  Policy Governance Layer (internal/audit, internal/logx)    │
│  - Error mapping and domain error handling                  │
│  - Structured logging with context                          │
├─────────────────────────────────────────────────────────────┤
│  Execution Engine Layer (ebpf/, internal/probes)            │
│  - eBPF program loading, attach, detach, map I/O            │
│  - Ring buffer event consumption to DuckDB                  │
└─────────────────────────────────────────────────────────────┘
```

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

# Run NFS E2E tests (requires sudo for eBPF)
sudo -E go test -count=1 ./test/integration -run TestNFSProbeLoadAndDuckDBIngestionE2E -v

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

## Probe Configuration (YAML)

Probe metadata is defined in YAML files under `probes/`:

```yaml
probes:
  - type: nfs_file_read          # Probe type identifier (used for dynamic loading)
    title: 读文件
    layer: nfs-client            # Layer classification (maps to ebpf/ directory)
    level: L2
    scene: 度量NFS-Client侧的文件单次读请求的延迟与大小
    entrypoints:
      - nfs_file_read
    params:
      - name: filter_pid
        type: u32
        description: 目标进程ID
        optional: true
    outputs:
      fields:
        - name: pid
          type: u32
          description: 进程ID
    risks: 高并发 I/O 场景下全量追踪可能有开销
```

**Key fields:**
- `type` - Unique probe identifier, used to locate implementation in `ebpf/<layer>/<type>/`
- `layer` - Logical layer classification (e.g., nfs-client, kernel, network)
- `params` - Runtime configurable parameters
- `outputs` - Event fields output to DuckDB

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

### Directory Structure Convention

```
ebpf/
└── <layer>/                    # e.g., nfs-client, kernel, network
    └── <type>/                 # e.g., nfs_file_read, tcp_connect
        ├── *.c                 # eBPF C source files
        ├── probe.go            # Go probe implementation
        └── bpf_*.go            # Generated ebpf-go bindings
```

The `layer` and `type` fields in YAML map directly to this directory structure, enabling automatic discovery.

### Benefits

- **Lazy loading**: eBPF programs only loaded when explicitly requested
- **Discovery without privileges**: AI agents can browse available probes without root
- **Decoupled metadata**: Probe descriptions and parameters defined in YAML, not code
- **Easy extension**: New probes only need YAML + implementation directory

## Error Handling

Domain errors are defined in `internal/logx/errors.go`:
- `INVALID_ARGUMENT` - Parameter validation failed
- `PERMISSION_DENIED` - Authentication/authorization failure
- `QUOTA_EXCEEDED` - Resource budget exceeded
- `PROBE_NOT_FOUND` - Probe doesn't exist
- `RUNTIME_FAILURE` - eBPF loading/execution failed
- `CONFLICT` - State conflict (e.g., loading already loaded probe)

Errors are mapped using `logx.MapDomainError(err)` for consistent protocol responses.

## Important Notes

- **Privileged Operations**: eBPF loading requires `CAP_BPF` capability (typically root). Tests that load eBPF programs must run with `sudo`.
- **DuckDB Permissions**: When running as root with sudo, the database file ownership is automatically adjusted to the original user.
- **Two-Phase Registration**: Probes are registered in two phases - static metadata at startup (from YAML), dynamic instantiation at load time.
- **Thread Safety**: The Controller uses mutex locks for concurrent access. Individual probes should handle their own synchronization.
- **State Machine**: Probes follow states: `unloaded` -> `loaded` -> `error` -> `unloaded`
- **Probe Discovery**: AI agents can query available probes via `probe_resource_info` tool without loading any eBPF programs

## Development Workflow

### Adding a New Probe

To add a new probe, you only need to:

1. **Create YAML configuration** in `probes/<probe-name>.yaml`:
   ```yaml
   probes:
     - type: my_probe
       title: My Probe
       layer: my-layer
       level: L2
       scene: Description of what this probe does
       entrypoints:
         - target_function
       params:
         - name: filter_pid
           type: u32
           description: Filter by PID
           optional: true
       outputs:
         fields:
           - name: pid
             type: u32
             description: Process ID
       risks: Potential performance impact
   ```

2. **Create probe implementation** in `ebpf/<layer>/<type>/`:
   ```
   ebpf/
   └── my-layer/
       └── my_probe/
           ├── my_probe.c       # eBPF C code
           ├── probe.go         # Go implementation
           └── bpf_bpfel.go     # Generated bindings (via bpf2go)
   ```

3. **Implement Probe interface** in `probe.go`:
   ```go
   type MyProbe struct {
       probes.BaseProbe
       // ... probe-specific fields
   }

   func (p *MyProbe) Start(ctx context.Context, db *sql.DB) error { ... }
   func (p *MyProbe) Stop() error { ... }
   func (p *MyProbe) Update(config map[string]interface{}) error { ... }
   ```

The probe will be automatically discovered at startup (static registration) and can be loaded dynamically via MCP tools.

### Testing a New Probe

When adding a new probe, you should also add corresponding tests. We provide a reusable test framework to simplify this process.

**1. Using the Test Helper Framework**

For standard NFS probes, use the `NFSProbeTestSuite`:

```go
// test/probes/my_probe_test.go
package probes

import (
    _ "ebpf-mcp/ebpf/my-layer/my_probe"  // Import for side effects (registration)
    "testing"
)

func TestMyProbe(t *testing.T) {
    suite := NewNFSProbeTestSuite(t, "my_probe", "my-layer")
    suite.RunAll()  // Runs all standard tests
}
```

**2. Using ProbeTestHelper for Custom Tests**

For more control, use the `ProbeTestHelper` directly:

```go
func TestCustomProbeBehavior(t *testing.T) {
    helper := NewProbeTestHelper(t)
    defer helper.Shutdown()

    tc := ProbeTestCase{
        Name:            "custom_probe",
        ProbeType:       "custom_probe",
        Layer:           "custom-layer",
        ExpectedParams:  []string{"param1", "param2"},
        ExpectedOutputs: []string{"field1", "field2"},
        TableName:       "custom_probe",
    }

    // Run specific tests
    helper.TestRegistration(tc)
    helper.TestMetadataIntegrity(tc)

    // Skip if not root for eBPF tests
    helper.SkipIfNotRoot()

    helper.TestLifecycle(tc)

    // Custom macro variable tests
    configs := []map[string]any{
        {"param1": uint32(1234)},
        {"param2": "test_value"},
    }
    helper.TestMacroVariables(tc, configs)
}
```

**3. Available Test Helper Methods**

| Method | Description |
|--------|-------------|
| `TestRegistration(tc)` | Verify probe is registered with correct metadata |
| `TestLifecycle(tc)` | Test Load/Unload/Status cycle |
| `TestMacroVariables(tc, configs)` | Test parameter updates |
| `TestMetadataIntegrity(tc)` | Verify metadata completeness |
| `TestDataCollection(tc, trigger)` | Test event collection to DuckDB |
| `TestErrorHandling(tc)` | Test error conditions |
| `SkipIfNotRoot()` | Skip test if not running as root |

**4. Test File Structure**

```
test/probes/
├── helper_test.go           # Reusable test framework
├── nfs_file_read_test.go    # NFS read probe tests
├── nfs_file_write_test.go   # NFS write probe tests
└── <your_probe>_test.go     # Your new probe tests
```

**5. Running Probe Tests**

```bash
# Run all probe tests (requires sudo for eBPF tests)
sudo -E go test -v ./test/probes/...

# Run specific probe test
sudo -E go test -v ./test/probes -run TestNFSFileReadProbe

# Run tests without eBPF (metadata tests only)
go test -v ./test/probes -run "Registration|Metadata"
```

- Unit tests: `go test ./internal/probes/...`
- Integration tests: `go test ./test/integration/...`
- E2E tests require sudo: `sudo -E go test ./test/integration -run <TestName> -v`

### Before Committing

- `go test ./...`
- `go vet ./...`
- `gofmt -w .`
- `go mod tidy`