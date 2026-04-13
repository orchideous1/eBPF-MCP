---
name: probe-creator
description: 在 eBPF-MCP 项目中创建完整的 eBPF 探针，聚焦用户确认核心逻辑，智能体负责实施。当用户需要"创建探针"、"添加监控"、"实现内核观测"时使用。必须遵循 ebpf-go 规范，生成符合项目结构的 YAML + C + Go + Test 文件。
---

# Probe Creator - eBPF 探针创建技能

## 核心理念

**用户负责**：确认探针函数、选择探针类型、定义采集逻辑
**智能体负责**：生成所有文件、确保 ebpf-go 规范、执行测试验证

## 快速开始

用户输入格式：
```
创建一个监控 <函数名> 的探针，用于 <场景>，采集 <数据>
```

示例：
- "创建 nfs_file_write 探针，分析 NFS 写入延迟"
- "监控 tcp_connect，采集连接信息"

## 完整工作流

首先进入计划模式，经过前三个阶段确定开发计划，然后执行开发任务

### 阶段 1：探针点确认（用户确认）

**步骤**：
1. 询问用户目标函数名
2. 要求用户确定探针类型：
   - `fentry/fexit` - 函数入口/出口（推荐，性能最好）
   - `kprobe/kretprobe` - 内核探针（兼容性更好）
   - `tracepoint` - 内核跟踪点
3. 确定所属层（layer）：nfs-client, nfsd, network, syscall, block 等

注意事项：
给用户提供便捷确定探针类型的命令：
```
./scripts/check_fentry_availability <end-point>
```

**输出**：确认的函数名、探针类型、所属层

---

### 阶段 2：探针类型与模板选择（用户确认）

根据场景选择合适的模板（references/ 目录）：

| 模板 | 适用场景 | 核心字段 | 可选扩展 |
|------|---------|---------|---------|
| `latency_fentry.md` | 函数延迟追踪 | pid, lat, time_stamp | ret, comm |
| `network_socket.md` | 网络连接/套接字 | pid, comm, saddr, daddr, sport, dport | family, protocol |
| `file_io.md` | 文件读写操作 | pid, file, offset, size | comm, flags |
| `syscall_entry.md` | 系统调用入口 | pid, comm, args[] | ret (exit时) |
| `generic_event.md` | 通用事件上报 | pid, time_stamp | 自定义字段 |

**步骤**：
1. 展示模板选项，说明适用场景
2. 用户选择模板
3. 确认可选字段（根据具体函数添加）

**输出**：选定的模板、确认的可选字段列表

---

### 阶段 3：逻辑确认（用户确认）

**步骤**：
1. 展示生成的代码框架（基于模板）
2. 解释关键逻辑：
   - fentry 做什么（记录开始时间/采集入口参数）
   - fexit 做什么（计算延迟/采集返回值）
3. 询问是否需要调整字段读取逻辑

**确认项**：
- [ ] 函数名正确
- [ ] 探针类型合适
- [ ] 核心字段满足需求
- [ ] 可选字段按需添加
- [ ] 字段读取逻辑正确

**技巧**
如果探针类型为fentry，提示用户通过以下脚本获取参数：
使用（./scripts/get_args_info.sh）获取结构体定义
使用（./scripts/get_func_args.sh）获取函数参数定义

如果探针类型为tracepoint, 提示用户通过以下命令获取具体参数：
```
sudo cat /sys/kernel/tracing/events/<kernel-sub-system>/<tracepoint>/format
```
**输出**：确认的逻辑设计

---

### 阶段 4：智能体实施（自动执行）

用户确认后，智能体自动执行以下操作：

#### 4.1 生成 YAML 配置

文件：`probes/<probe_name>.yaml`

包含：
- type, title, layer, level, scene
- entrypoints
- params（filter_pid, filter_file, filter_comm）
- outputs（fields 定义）
- risks
- risk-description

#### 4.2 生成 eBPF C 代码

文件：`ebpf/<layer>/<probe_name>/<probe_name>.c`

规范：
```c
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// 过滤参数
volatile __u64 filter_pid;

// 事件结构体
struct event {
    u64 pid;
    u64 lat;        // 仅延迟类探针
    u64 time_stamp;
    // ... 其他字段
};

// Map 定义
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __type(value, struct event);
} events SEC(".maps");

// 探针程序
SEC("fentry/<func_name>")
int BPF_PROG(<func_name>_entry, ...) { ... }

SEC("fexit/<func_name>")
int BPF_PROG(<func_name>_exit, ..., long ret) { ... }
```

#### 4.3 生成 Go 探针实现

文件：`ebpf/<layer>/<probe_name>/probe.go`

规范：
```go
//go:build linux
//go:generate go tool bpf2go -cflags "-O2" -tags linux bpf <probe_name>.c -- -I ../../headers

package <layer>

import (
    "context"
    "database/sql"
    "encoding/binary"
    "errors"
    "fmt"
    "log"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/duckdb/duckdb-go/v2"

    database "ebpf-mcp/internal/db"
    "ebpf-mcp/internal/probes"
)

func init() {
    probes.Register("<probe_name>", func() probes.Probe {
        return New<ProbeName>()
    })
}

type <ProbeName> struct {
    probes.BaseProbe
    objs   bpfObjects
    links  []link.Link
    reader *ringbuf.Reader
    cancel context.CancelFunc
    dbConn   *sql.Conn
    appender *duckdb.Appender
}

// 实现 Probe 接口的方法...
```

#### 4.4 生成测试文件

文件：`test/probes/<probe_name>_test.go`

包含：
- Test<Name>_Registration
- Test<Name>_Lifecycle
- Test<Name>_MacroVariables
- Test<Name>_MetadataIntegrity

#### 4.5 更新注册表（手动维护）
文件：`internal/probes/registry/registry_gen.go`

**作用说明：**
此文件通过 blank import (`_ "package/path"`) 确保所有 eBPF 探针包的 `init()` 函数在程序启动时被调用。每个探针的 `init()` 函数负责将自身注册到全局注册表中。缺少 import 将导致探针无法被动态加载。

**操作步骤：**
1. 打开 `internal/probes/registry/registry_gen.go`
2. 在 import 块中添加新探针的 blank import：

```go
import (
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_read"
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_write"
    _ "ebpf-mcp/ebpf/<layer>/<probe_name>"  // 添加新探针的 import
)
```

**完整示例：**
假设创建了 `ebpf/network/tcp_connect/` 探针，修改后的文件如下：
```go
package registry

import (
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_read"
    _ "ebpf-mcp/ebpf/NFS-client/nfs_file_write"
    _ "ebpf-mcp/ebpf/network/tcp_connect"
)

func init() {
    // 探针通过各自的 init() 函数自动注册到 probes.registry
}
```

**验证：**
添加 import 后，编译项目确保无错误：
```bash
go build ./...
```

#### 4.6 联动更新 nfs-layer-observer 参考文档（如适用）

如果本次创建的探针属于 **NFS-client** 层（`ebpf/NFS-client/`）或 **NFSD** 层（`ebpf/nfsd/`），**必须**同步更新 `nfs-layer-observer` 技能的参考文档，确保函数映射不会过时：

- 打开 `.claude/skills/nfs-layer-observer/references/probe_catalog_reference.md`
- 如果该函数此前在"未实现的探针"列表中，**将其移到对应的"已实现的探针"表格**，并补全探针名和采集字段
- 如果该函数此前不在文档中，直接在"已实现的探针"表格新增一行

> 这是 `nfs-layer-observer` 判断探针覆盖度的核心依据，遗漏更新会导致后续技能误判该探针为"未实现"。

#### 4.7 编译和测试

**编译 eBPF 代码**

执行以下命令编译 eBPF 程序：

```bash
cd ebpf/<layer>/<probe_name> && go generate
```

**重新编译mcp服务器**

执行以下命令编译项目：

```bash
cd ~/Myproject/SREgent2-ebpf-mcp && make build
```

**测试**

由于 eBPF 程序加载需要 root 权限，可以运行以下无需 sudo 的测试：

```bash
# 回到项目根目录
cd ~/MyProject/SREgent2-ebpf_mcp
```bash
# 注册和元数据测试（无需 root）
go test -v ./test/probes -run Test<ProbeName>_Registration
go test -v ./test/probes -run Test<ProbeName>_MetadataIntegrity
```

最后给出整体测试命令
```
sudo -E go test -v ./test/probes -run Test<ProbeName>
```

---

## 模板引用

根据探针类型读取对应模板：

- `references/latency_fentry.md` - 延迟追踪模板
- `references/network_socket.md` - 网络套接字模板
- `references/file_io.md` - 文件 I/O 模板
- `references/syscall_entry.md` - 系统调用模板
- `references/generic_event.md` - 通用事件模板

---

## 规范检查清单

实施完成后必须检查：

**eBPF C 代码**：
- [ ] 包含 `//go:build ignore`
- [ ] 包含许可证声明 `char __license[] SEC("license") = "Dual MIT/GPL";`
- [ ] 使用正确的 SEC 标记（fentry/fexit/kprobe/tracepoint）
- [ ] 使用 BPF_MAP_TYPE_RINGBUF 发送事件
- [ ] 使用 bpf_ringbuf_reserve / bpf_ringbuf_submit

**Go 代码**：
- [ ] 包含 `//go:build linux`
- [ ] 包含 `//go:generate` 指令
- [ ] 有 `init()` 函数注册探针
- [ ] 嵌入 `probes.BaseProbe`
- [ ] 实现所有 Probe 接口方法
- [ ] 正确处理资源清理（Stop 方法）
- [ ] 使用 `link.AttachTracing` 或 `link.Kprobe`
- [ ] 使用 `ringbuf.NewReader`

**项目结构**：
- [ ] YAML 文件在 `probes/` 目录
- [ ] C 和 Go 文件在 `ebpf/<layer>/<probe_name>/` 目录
- [ ] 测试文件在 `test/probes/` 目录
- [ ] **registry_gen.go 已手动更新**（添加 blank import）

---

## 输出示例

完成后的文件结构：
```
probes/
  └── nfs_file_write.yaml          # 元数据配置
ebpf/
  └── NFS-client/
      └── nfs_file_write/
          ├── nfs_file_write.c     # eBPF C 代码
          ├── probe.go             # Go 实现
          └── bpf_*.go             # bpf2go 生成
test/probes/
  └── nfs_file_write_test.go       # 测试文件
internal/probes/registry/
  └── registry_gen.go              # 更新导入
```

---

## 常见问题

**Q: 探针函数不支持 fentry 怎么办？**
A: 自动降级为 kprobe，或使用 tracepoint 备选方案。

**Q: 如何确定可选字段？**
A: 使用 `./scripts/get_func_args.sh <func>` 获取函数签名，建议可读取的参数字段。

**Q: 测试失败怎么办？**
A: 检查：1) 是否 root 权限 2) eBPF 代码是否编译成功 3) 函数名是否正确。
