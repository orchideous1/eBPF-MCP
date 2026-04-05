# Probes Management

本文档介绍 eBPF-MCP 探针的管理方法、扩展方式以及如何使用 probe-creator skill 创建新探针。

## 目录

- [探针概述](#探针概述)
- [探针管理](#探针管理)
- [创建新探针](#创建新探针)
- [探针注册](#探针注册)
- [测试探针](#测试探针)
- [开发工作流](#开发工作流)

---

## 探针概述

### 两阶段注册架构

系统使用**两阶段注册**设计来分离探针发现与探针执行：

**第一阶段：静态注册（启动时）**

服务器启动时，`main.go` 调用 `probes.LoadProbesFromYAML()`：
1. 扫描 `probes/*.yaml` 文件
2. 解析探针元数据（类型、标题、层、参数、输出、风险）
3. 将元数据存储在 `metadataRegistry`（内存映射）
4. **此阶段不加载 eBPF 程序**

这使得 AI 智能体可以通过 `probe_resource_info` 工具查询可用探针，无需 root 权限。

**第二阶段：动态注册（加载时）**

当 AI 智能体调用 `system_observe_control` 并设置 `action=load`：
1. `Controller.Load(type)` 被调用
2. `GetProbe(type)` 在 `ebpf/<layer>/<type>/` 中定位探针实现
3. 创建探针实例并调用 `Start()`
4. eBPF 程序被加载到内核
5. 探针状态转换：`unloaded` → `loaded`

**优势**：
- **延迟加载**：仅在显式请求时加载 eBPF 程序
- **无需特权发现**：AI 智能体无需 root 即可浏览可用探针
- **元数据解耦**：探针描述和参数在 YAML 中定义，而非代码
- **易于扩展**：新探针只需 YAML + 实现目录

### 探针状态机

```
unloaded → loading → loaded → unloading → unloaded
                ↓        ↓
               error ←──┘
```

---

## 探针管理

### 可用探针列表

| 探针名称 | 层级 | 描述 | 过滤参数 |
|---------|------|------|---------|
| `nfs_file_read` | nfs-client | NFS 文件读取延迟和大小 | `filter_pid` |
| `nfs_file_write` | nfs-client | NFS 文件写入延迟和大小 | `filter_pid` |
| `nfs_getattr` | nfs-client | NFS 获取属性操作追踪 | `filter_pid` |
| `nfs_setattr` | nfs-client | NFS 设置属性操作追踪 | `filter_pid` |
| `sys_call_trace` | Sys-call | 系统调用追踪 | `filter_pid`, `filter_syscall_id` |

### 探针元数据结构

每个探针通过 YAML 定义元数据：

```yaml
probes:
  - type: nfs_file_read
    title: 读文件
    layer: nfs-client
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
        - name: lat
          type: u64
          description: 延迟（纳秒）
        - name: size
          type: u64
          description: 数据大小（字节）
    risks: low
    risk-description: 可能对NFS性能产生轻微影响
```

### 探针接口

所有 eBPF 探针实现 `Probe` 接口：

```go
type Probe interface {
    Name() string
    Start(ctx context.Context, db *sql.DB) error
    Stop() error
    Update(config map[string]interface{}) error
    GetMetadata() ProbeMetadata
    GetStatus() ProbeStatus
    SetState(state ProbeState, errMsg ...string)
}
```

---

## 创建新探针

### 方法：使用 probe-creator Skill

**推荐方式**：使用 `probe-creator` skill 自动创建完整的探针实现。

#### 调用方式

在 Claude Code 中调用：

```
/probe-creator <probe-name> --layer <layer> --type <kprobe|tracepoint|uprobe> --target <kernel-function>
```

#### 交互式创建

直接描述需求：

> "创建一个追踪 TCP 连接的探针，监听 tcp_connect 内核函数，需要记录源IP、目标IP和端口"

Claude 将自动调用 `probe-creator` skill 并生成：
1. YAML 配置文件
2. eBPF C 程序
3. Go 探针实现
4. 测试文件

#### Skill 生成的文件结构

```
ebpf/
└── <layer>/
    └── <probe_name>/
        ├── <probe_name>.c       # eBPF C 代码
        ├── probe.go             # Go 探针实现
        └── bpf_<probe_name>.go  # 生成的 ebpf-go 绑定

probes/
└── <probe_name>.yaml            # 探针元数据

test/probes/
└── <probe_name>_test.go         # 探针测试
```

### 方法：手动创建

如需手动创建，参考以下步骤：

#### 1. 创建 YAML 配置

在 `probes/<probe-name>.yaml` 中创建：

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

#### 2. 创建探针目录结构

```bash
mkdir -p ebpf/<layer>/<probe_name>
```

#### 3. 实现 eBPF C 程序

创建 `ebpf/<layer>/<probe_name>/<probe_name>.c`：

```c
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

struct event {
    u32 pid;
    u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/target_function")
int BPF_KPROBE(trace_entry, struct file *file)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
```

#### 4. 实现 Go 探针

创建 `ebpf/<layer>/<probe_name>/probe.go`：

```go
package my_probe

import (
    "context"
    "database/sql"
    "ebpf-mcp/internal/probes"
)

type MyProbe struct {
    probes.BaseProbe
    // 探针特定字段
}

func (p *MyProbe) Start(ctx context.Context, db *sql.DB) error {
    // 实现 eBPF 加载和启动逻辑
    return nil
}

func (p *MyProbe) Stop() error {
    // 实现停止逻辑
    return nil
}

func (p *MyProbe) Update(config map[string]interface{}) error {
    // 实现参数更新逻辑
    return nil
}

func init() {
    probes.RegisterProbe("my_probe", func() probes.Probe {
        return &MyProbe{}
    })
}
```

#### 5. 生成 eBPF 绑定

```bash
go generate ./ebpf/<layer>/<probe_name>/...
```

---

## 探针注册

### 在 registry_gen.go 中注册

创建探针实现后，必须在 `internal/probes/registry/registry_gen.go` 中手动注册，确保探针的 `init()` 函数在程序启动时被调用。

**registry_gen.go 的作用**：
此文件包含所有 eBPF 探针包的空白导入（`_ "package/path"`）。空白导入确保每个探针的 `init()` 函数在程序启动时执行，从而向全局注册表注册探针。

**添加新导入**：

1. 打开 `internal/probes/registry/registry_gen.go`
2. 在导入块中添加新探针包的空白导入：

```go
import (
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_read"
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_write"
    _ "ebpf-mcp/ebpf/<layer>/<probe_name>"  // 在此添加新探针
)
```

**示例**：
如果你在 `ebpf/network/tcp_connect/` 创建了探针，添加：
```go
import (
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_read"
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_write"
    _ "ebpf-mcp/ebpf/network/tcp_connect"
)
```

**注意**：文件头提到的 `cmd/probe-registry-gen` 工具已不再可用，添加新探针时必须手动维护此文件。

---

## 测试探针

### 使用测试辅助框架

对于标准 NFS 探针，使用 `NFSProbeTestSuite`：

```go
// test/probes/my_probe_test.go
package probes

import (
    _ "ebpf-mcp/ebpf/my-layer/my_probe"  // 导入以触发注册
    "testing"
)

func TestMyProbe(t *testing.T) {
    suite := NewNFSProbeTestSuite(t, "my_probe", "my-layer")
    suite.RunAll()  // 运行所有标准测试
}
```

### 使用 ProbeTestHelper 自定义测试

如需更多控制，直接使用 `ProbeTestHelper`：

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

    // 运行特定测试
    helper.TestRegistration(tc)
    helper.TestMetadataIntegrity(tc)

    // 非 root 跳过 eBPF 测试
    helper.SkipIfNotRoot()

    helper.TestLifecycle(tc)

    // 自定义宏变量测试
    configs := []map[string]any{
        {"param1": uint32(1234)},
        {"param2": "test_value"},
    }
    helper.TestMacroVariables(tc, configs)
}
```

### 测试辅助方法

| 方法 | 描述 |
|------|------|
| `TestRegistration(tc)` | 验证探针注册和元数据 |
| `TestLifecycle(tc)` | 测试 Load/Unload/Status 周期 |
| `TestMacroVariables(tc, configs)` | 测试参数更新 |
| `TestMetadataIntegrity(tc)` | 验证元数据完整性 |
| `TestDataCollection(tc, trigger)` | 测试事件收集到 DuckDB |
| `TestErrorHandling(tc)` | 测试错误条件 |
| `SkipIfNotRoot()` | 非 root 时跳过测试 |

### 运行探针测试

```bash
# 运行所有探针测试（需要 sudo 进行 eBPF 测试）
sudo -E go test -v ./test/probes/...

# 运行特定探针测试
sudo -E go test -v ./test/probes -run TestNFSFileReadProbe

# 仅运行元数据测试（无需 root）
go test -v ./test/probes -run "Registration|Metadata"
```

---

## 开发工作流

### 提交前检查清单

- [ ] `go test ./...` 通过
- [ ] `go vet ./...` 无错误
- [ ] `gofmt -w .` 已执行
- [ ] `go mod tidy` 已执行
- [ ] YAML 元数据完整
- [ ] 探针已在 `registry_gen.go` 中注册
- [ ] 测试文件已创建

### 完整开发流程

1. **定义需求**：明确探针目标、监控的内核函数、需要采集的数据字段
2. **创建探针**：
   - 方式 A：使用 `/probe-creator` skill 自动生成
   - 方式 B：手动创建 YAML、C 代码、Go 实现
3. **注册探针**：在 `registry_gen.go` 中添加空白导入
4. **生成绑定**：运行 `go generate` 生成 ebpf-go 绑定
5. **编写测试**：创建 `test/probes/<probe>_test.go`
6. **验证测试**：
   ```bash
   # 非特权测试
   go test -v ./test/probes -run "Registration|Metadata"

   # 完整测试（需要 root）
   sudo -E go test -v ./test/probes -run Test<Your>Probe
   ```
7. **提交代码**

---

## 相关文档

- [项目概况](../CLAUDE.md) - 快速开始和基本命令
- [设计文档](DESIGN.md) - 系统架构设计
- [启动指南](start.md) - 环境变量和 MCP 配置
- [测试平台](testbench.md) - 详细测试矩阵
