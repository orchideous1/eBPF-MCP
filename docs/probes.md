# Probes Management
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

### Registering the Probe in registry_gen.go

After creating the probe implementation, you must manually register it in `internal/probes/registry/registry_gen.go` to ensure the probe's `init()` function is called during program startup.

**Purpose of registry_gen.go:**
This file contains blank imports (`_ "package/path"`) for all eBPF probe packages. The blank import ensures that each probe's `init()` function is executed at program startup, which registers the probe with the global registry. Without this import, the probe will not be available for dynamic loading.

**How to add a new import:**

1. Open `internal/probes/registry/registry_gen.go`
2. Add a blank import line for your new probe package in the import block:

```go
import (
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_read"
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_write"
    _ "ebpf-mcp/ebpf/<layer>/<probe_name>"  // Add your new probe here
)
```

**Example:**
If you created a probe at `ebpf/network/tcp_connect/`, add:
```go
import (
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_read"
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_write"
    _ "ebpf-mcp/ebpf/network/tcp_connect"
)
```

**Note:** The `cmd/probe-registry-gen` tool mentioned in the file header is no longer available, so this file must be maintained manually when adding new probes.

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