# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

eBPF-MCP is a Go-based middleware that bridges AI agents with eBPF kernel observability capabilities through the Model Context Protocol (MCP). It provides a standardized, secure interface for AI agents to interact with eBPF probes without directly manipulating kernel resources.

### Key Components

1. **Probe Interface** (`internal/probes/probe.go`): All eBPF probes implement the `Probe` interface with lifecycle methods (Start, Stop, Update, GetStatus).

2. **Controller** (`internal/probes/controller.go`): Central coordinator for probe lifecycle with thread-safe operations.

3. **Registry** (`internal/probes/registry.go`): Two-phase registration architecture that separates probe discovery from execution.

4. **MCP Server** (`internal/server/server.go`): Exposes MCP tools for probe interaction.

### Project Structure

```
.
├── main.go                    # Application entry point
├── probes/                    # YAML probe configurations (static metadata)
├── ebpf/                      # eBPF C programs and Go implementations
│   ├── headers/               # BPF helper definitions
│   └── <layer>/               # Layer-specific probes, including: Disk\Network\NFS-client\nfsd\RPC\Sys-call
│       └── <endpoint>/        # Endpoint-specific probe directory
├── internal/
│   ├── probes/                # Probe controller, registry, interfaces
│   ├── server/                # MCP server implementation
│   ├── db/                    # DuckDB utilities
│   └── logx/                  # Structured logging
├── test/
│   ├── integration/          # Integration and E2E tests
│   └── probes/               # Probe-specific tests
└── database/                  # DuckDB database files
```

For detailed design information, see [docs/DESIGN.md](docs/DESIGN.md).

---

## Quick Start

### Building

```bash
# Build the project
go build -o exe/ebpf-mcp .

# Generate eBPF bindings (after modifying probes)
go generate ./...
```

### Running

```bash
# STDIO mode (default, for local MCP clients)
sudo -E ./exe/ebpf-mcp

# HTTP mode
sudo -E ./exe/ebpf-mcp -transport http -port 8080 -token <auth_token>

# Debug mode
sudo -E ./exe/ebpf-mcp -debug
```

For environment variables and MCP client configuration, see [docs/start.md](docs/start.md).

---

## Testing

### Non-Privileged Tests (No Root Required)

```bash
# Unit tests
go test ./internal/...

# E2E tests (using mock probes)
go test -v ./test/integration/...

# Race detection
go test -race ./...
```

### Privileged Tests (Root Required)

```bash
# Run all probe integration tests
sudo -E go test -count=1 ./test/probes -v

# Run specific probe test
sudo -E go test -count=1 ./test/probes -run TestNFSFileReadProbe -v

# Run with race detection
sudo -E go test -race -count=1 ./test/probes -v
```

For detailed test information and test matrix, see [docs/testbench.md](docs/testbench.md).

---


## Probe Overview

### Available Probes

| Probe | Layer | Description |
|-------|-------|-------------|
| `nfs_file_read` | nfs-client | NFS file read latency and size |
| `nfs_file_write` | nfs-client | NFS file write latency and size |
| `nfs_getattr` | nfs-client | NFS getattr operation tracing |
| `nfs_setattr` | nfs-client | NFS setattr operation tracing |
| `sys_call_trace` | Sys-call | System call tracing |

### Two-Phase Registration

1. **Static Registration (Startup)**: YAML metadata loaded from `probes/*.yaml`
2. **Dynamic Registration (Load Time)**: eBPF programs loaded when AI agent requests

### MCP Tools

- `probe_resource_info` - Get probe metadata and status
- `system_observe_control` - Load/unload/status operations
- `probe_customize` - Modify probe runtime parameters

For probe management, extension methods, and probe-creator skill usage, see [docs/probes.md](docs/probes.md).
