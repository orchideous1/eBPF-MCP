# eBPF-MCP 设计文档

## 1. 文档目标

本文档定义 eBPF-MCP 服务端的核心设计，覆盖以下内容：
- 设计理念分析
- 代码架构详解
- 核心类/接口定义
- 具体工作流

目标是让智能体能够在可控、安全、可解释的前提下，调用 eBPF 探针能力完成系统观测任务。

---

## 2. 设计理念分析

### 2.1 MCP (Model Context Protocol) 架构设计理念

MCP 是由 Anthropic 提出的开放协议，旨在标准化 AI Agent 与外部工具、数据源的交互方式。eBPF-MCP 基于以下 MCP 核心设计理念：

**资源抽象（Resource Abstraction）**
- 每个 eBPF 探针被抽象为 MCP Resource，具有统一的元数据描述（名称、功能、参数、输出）
- 通过 `probe_resource_info` 工具暴露探针的完整信息，便于 AI Agent 按需发现和理解能力边界

**工具最小化（Minimal Tool Surface）**
- 仅暴露三个核心工具：`probe_resource_info`、`system_observe_control`、`probe_customize`
- 通过参数化配置而非增加工具数量来扩展功能，降低 AI Agent 的学习成本

**上下文感知（Context Awareness）**
- 探针运行时状态（loaded/unloaded/error）实时反馈给 AI Agent
- 通过 DuckDB 持久化观测数据，支持 AI Agent 进行历史数据查询和分析

### 2.2 eBPF 与 AI Agent 结合的架构思想

**内核可编程性的安全暴露**
- eBPF 程序直接运行在内核态，具有极高的执行权限。eBPF-MCP 作为中间层，将内核能力封装为受限的、可审计的接口
- AI Agent 不直接操作 eBPF 字节码，而是通过声明式参数（YAML 配置）间接控制观测行为

**事件驱动与数据流水线**
- 探针通过 Ring Buffer 将内核事件高效传输到用户态
- 用户态消费 goroutine 将事件结构化后写入 DuckDB，形成完整的观测数据流水线
- AI Agent 可通过 SQL 查询 DuckDB 中的数据，实现灵活的后续分析

**动态可配置性**
- 探针支持运行时参数更新（如 `filter_pid`、`filter_file`），无需重新加载 eBPF 程序
- 通过 eBPF Map 实现用户态与内核态的高效通信，参数变更即时生效

### 2.3 安全性和隔离性设计原则

**权限分离**
- MCP Server 运行在与 AI Agent 分离的进程中，通过 STDIO 或 HTTP 协议通信
- eBPF 程序加载需要 root 权限，但 AI Agent 通过 MCP 协议间接请求，不直接接触内核资源

**资源配额与准入控制**
- 探针加载前进行风险评估（`risks` 字段标识风险等级：low/medium/high）
- 支持通过 `filter_pid`、`filter_file` 等参数限制观测范围，避免全量追踪带来的性能开销

**状态机与错误隔离**
- 每个探针具有独立的状态机（unloaded -> loaded <-> error）
- 单个探针的错误不影响其他探针的运行，错误状态通过 `LastError` 字段反馈给 AI Agent

**优雅退出与资源回收**
- 探针停止时执行完整的资源清理：取消 context、关闭 Ring Buffer、Flush 数据、关闭数据库连接、Detach eBPF 程序
- 通过 `sync.RWMutex` 保证并发安全，避免资源竞争

---

## 3. 代码架构详解

### 3.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AI Agent (Client)                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ MCP Protocol (STDIO / HTTP)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MCP Server Layer                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  internal/server/server.go                                          │   │
│  │  - 协议接入与传输层管理（STDIO/HTTP）                                │   │
│  │  - 工具注册与请求路由                                                │   │
│  │  - 认证与中间件（Bearer Token）                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  MCP Tools                                                          │   │
│  │  - probe_resource_info: 探针元数据与状态查询                         │   │
│  │  - system_observe_control: 探针生命周期控制（load/unload/status）    │   │
│  │  - probe_customize: 探针参数动态更新                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ 方法调用
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Probe Controller Layer                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  internal/probes/controller.go                                      │   │
│  │  - 探针生命周期协调（线程安全）                                      │   │
│  │  - 数据库连接管理（懒加载模式）                                      │   │
│  │  - 状态聚合与查询                                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ 接口实现
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Probe Registry Layer                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  internal/probes/registry.go                                        │   │
│  │  - 两阶段注册架构：静态元数据（YAML）+ 动态实例（工厂函数）            │   │
│  │  - 探针发现与信息聚合                                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  internal/probes/probe.go                                           │   │
│  │  - Probe 接口定义                                                    │   │
│  │  - BaseProbe 基础实现                                                │   │
│  │  - 状态机与元数据模型                                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ 探针实现
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           eBPF Probe Implementations                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │ nfs_file_read   │  │ nfs_file_write  │  │ nfs_getattr     │  ...         │
│  │ (NFS-client)    │  │ (NFS-client)    │  │ (NFS-client)    │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │ nfsd4_read      │  │ nfsd4_write     │  │ sys_call_trace  │  ...         │
│  │ (nfsd)          │  │ (nfsd)          │  │ (Sys-call)      │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
                                       │ Ring Buffer / eBPF Maps
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Linux Kernel                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  eBPF Programs (kprobe/tracepoint/fentry/fexit)                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 分层设计

#### 第一层：协议接入层（MCP Server Layer）

**职责**：处理 MCP 协议通信，暴露标准化工具接口

**核心文件**：
- `internal/server/server.go`：服务启动、生命周期管理、工具注册
- `internal/server/config.go`：传输配置（STDIO/HTTP）、认证配置
- `internal/server/http_middleware.go`：HTTP 认证中间件

**设计要点**：
- 支持两种传输模式：STDIO（本地 MCP 客户端）和 HTTP（远程访问）
- 使用 `mcp-go` 库实现 MCP 协议
- HTTP 模式下启用 Bearer Token 认证

#### 第二层：探针控制层（Probe Controller Layer）

**职责**：协调探针生命周期，管理共享资源（数据库连接）

**核心文件**：
- `internal/probes/controller.go`：探针加载、卸载、更新、状态查询

**设计要点**：
- 使用 `sync.RWMutex` 保证线程安全
- 懒加载数据库连接：首个探针加载时打开，最后一个探针卸载时关闭
- 自动执行 CHECKPOINT 确保数据持久化

#### 第三层：探针注册层（Probe Registry Layer）

**职责**：探针发现、元数据管理、工厂模式实例化

**核心文件**：
- `internal/probes/registry.go`：两阶段注册机制实现
- `internal/probes/probe.go`：接口定义与基础实现

**设计要点**：
- 静态注册：从 YAML 加载探针元数据（名称、参数、输出、风险等级）
- 动态注册：通过 `init()` 函数注册探针工厂函数
- 运行时通过工厂函数创建探针实例

#### 第四层：探针实现层（eBPF Probe Layer）

**职责**：具体 eBPF 探针的实现，包括内核程序和用户态控制逻辑

**目录结构**：
```
ebpf/
├── NFS-client/           # NFS 客户端探针
│   ├── nfs_file_read/    # 文件读取追踪
│   ├── nfs_file_write/   # 文件写入追踪
│   ├── nfs_getattr/      # getattr 操作追踪
│   └── nfs_setattr/      # setattr 操作追踪
├── nfsd/                 # NFS 服务端探针
│   ├── nfsd4_read/       # NFSv4 读取追踪
│   └── nfsd4_write/      # NFSv4 写入追踪
└── Sys-call/             # 系统调用探针
    └── sys_call_trace/   # 系统调用追踪
```

### 3.3 数据流：从 YAML 配置到 eBPF 程序加载

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            数据流示意图                                      │
└─────────────────────────────────────────────────────────────────────────────┘

阶段 1: 服务启动（静态注册）
─────────────────────────────────────────────────────────────────────────────
  probes/*.yaml ──► registry.LoadProbesFromYAML() ──► metadataRegistry
       │                                                    │
       │  包含：type, title, layer, params, outputs, risks  │
       ▼                                                    ▼
  ┌─────────────┐                                    ┌─────────────┐
  │ 静态元数据   │                                    │ 内存元数据   │
  │ (YAML文件)  │                                    │ 存储结构     │
  └─────────────┘                                    └─────────────┘

阶段 2: 探针包导入（动态注册）
─────────────────────────────────────────────────────────────────────────────
  main.go import ──► probes.Register() ──► registry
       │                                        │
       │  init() 函数中注册工厂函数              │
       ▼                                        ▼
  ┌─────────────┐                        ┌─────────────┐
  │ 探针实现包   │                        │ 工厂函数     │
  │ 自动导入    │                        │ 注册表       │
  └─────────────┘                        └─────────────┘

阶段 3: AI Agent 请求加载（运行时实例化）
─────────────────────────────────────────────────────────────────────────────
  AI Agent ──► probe_resource_info ──► 返回元数据列表
       │
       ▼
  system_observe_control(load)
       │
       ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │ Controller.Load()                                                   │
  │  1. 检查探针是否已加载                                              │
  │  2. 调用 registry.GetProbe() 创建实例（工厂模式）                    │
  │  3. 调用 probe.Start()                                              │
  │     a. 创建 DuckDB 表                                               │
  │     b. loadBpfObjects() 加载 eBPF 程序                              │
  │     c. link.AttachTracing() 附加到内核探针点                        │
  │     d. ringbuf.NewReader() 创建事件读取器                           │
  │     e. 启动 consume goroutine 消费事件                              │
  │  4. 更新探针状态为 loaded                                           │
  └─────────────────────────────────────────────────────────────────────┘

阶段 4: 运行时事件处理
─────────────────────────────────────────────────────────────────────────────
  Kernel Event ──► Ring Buffer ──► consume() ──► DuckDB Appender
       │                                              │
       │  eBPF 程序生成事件                            │ 批量写入
       ▼                                              ▼
  ┌─────────────┐                              ┌─────────────┐
  │ 内核态事件   │                              │ DuckDB      │
  │ (bpfEvent)  │                              │ 持久化存储   │
  └─────────────┘                              └─────────────┘

阶段 5: 参数动态更新
─────────────────────────────────────────────────────────────────────────────
  AI Agent ──► probe_customize ──► Controller.Update()
                                          │
                                          ▼
                                    probe.Update()
                                          │
                                          ▼
                                    p.objs.FilterPid.Set()
                                          │
                                          ▼
                                    ┌─────────────┐
                                    │ eBPF Map    │
                                    │ 参数更新     │
                                    └─────────────┘
```

### 3.4 两层注册架构详解

#### 静态注册（Static Registration）

**时机**：服务启动时
**来源**：`probes/*.yaml` 配置文件
**存储**：`metadataRegistry`（map[string]ProbeMetadata）
**内容**：
- 探针类型标识（type）
- 标题和描述（title, scene）
- 所属层级（layer: nfs-client/nfsd/Sys-call）
- 可配置参数（params）：名称、类型、描述、是否可选、示例
- 输出字段（outputs）：名称、类型、描述
- 风险等级（risks）：low/medium/high

**代码路径**：
```go
// main.go
probes.LoadProbesFromYAML(repoRoot)  // 加载 YAML 配置

// internal/probes/registry.go
func LoadProbesFromYAML(baseDir string) error {
    // 遍历 probes/ 目录下的 .yaml 文件
    // 解析为 ProbeMetadata 结构体
    // 存入 metadataRegistry
}
```

#### 动态注册（Dynamic Registration）

**时机**：程序初始化时（`init()` 函数）
**来源**：各探针实现包的 `init()` 函数
**存储**：`registry`（map[string]func() Probe）
**内容**：探针工厂函数

**代码路径**：
```go
// ebpf/NFS-client/nfs_file_read/probe.go
func init() {
    probes.Register("nfs_file_read", func() probes.Probe {
        return NewNFSFileReadProbe()
    })
}

// internal/probes/registry.go
func Register(name string, factory func() Probe) {
    registry[name] = factory
}
```

#### 运行时实例化

当 AI Agent 请求加载探针时，Controller 通过工厂函数创建实例：

```go
// internal/probes/controller.go
func (c *Controller) Load(ctx context.Context, name string) (Status, error) {
    probe, ok := GetProbe(name)  // 调用工厂函数创建实例
    if err := probe.Start(ctx, c.db); err != nil {
        // 处理启动错误
    }
    c.probes[name] = probe  // 存入运行中探针映射
}

// internal/probes/registry.go
func GetProbe(name string) (Probe, bool) {
    factory := registry[name]
    return factory(), true  // 执行工厂函数创建新实例
}
```

---

## 4. 核心类/接口定义

### 4.1 Probe 接口定义和生命周期

**文件**：`internal/probes/probe.go`

```go
// Probe 定义了所有 eBPF 探针必须实现的接口
type Probe interface {
    // 基础标识
    Name() string

    // 生命周期方法
    Start(ctx context.Context, dbConn *sql.DB) error
    Stop() error
    Update(config map[string]interface{}) error

    // 状态与元数据
    GetMetadata() ProbeMetadata
    GetStatus() ProbeStatus
    SetState(state ProbeState, errMsg ...string)

    // 数据持久化
    Flush() error
}
```

**生命周期状态机**：

```
                    ┌─────────────┐
         ──────────│  unloaded   │◄──────────────┐
        │           │  (初始状态)  │               │
        │           └──────┬──────┘               │
        │                  │ Load                  │
        │                  ▼                       │
        │           ┌─────────────┐    Error      │
        │    ┌─────│   loaded    │───────────────┤
        │    │     │  (运行中)    │               │
        │    │     └──────┬──────┘               │
        │    │            │ Update/Error          │
        │    │            ▼                       │
        │    │     ┌─────────────┐    Stop       │
        │    └────►│    error    │───────────────┘
        │          │  (错误状态)  │
        │          └─────────────┘
        │                  │
        └──────────────────┘
```

**状态说明**：
- `unloaded`：探针未加载，初始状态
- `loaded`：探针正常运行中
- `error`：探针发生错误，可通过 `LastError` 获取错误信息

**BaseProbe 基础实现**：

```go
// BaseProbe 提供 Probe 接口的基础实现，可被具体探针嵌入
type BaseProbe struct {
    metadata ProbeMetadata
    status   ProbeStatus
}

// 提供默认实现的方法
func (b *BaseProbe) GetMetadata() ProbeMetadata
func (b *BaseProbe) GetStatus() ProbeStatus
func (b *BaseProbe) SetState(state ProbeState, errMsg ...string)
func (b *BaseProbe) Flush() error  // 默认空实现
```

### 4.2 Controller 的线程安全设计

**文件**：`internal/probes/controller.go`

**核心结构**：

```go
type Controller struct {
    mu       sync.RWMutex           // 读写锁，保护以下字段
    db       *sql.DB                // DuckDB 连接（懒加载）
    probes   map[string]Probe       // 已加载的探针实例
    statuses map[string]ProbeStatus // 探针状态缓存

    dbPath   string                 // 数据库路径
    dbOpener func(path string) (*sql.DB, error)  // 数据库打开函数
}
```

**线程安全策略**：

| 方法 | 锁类型 | 说明 |
|------|--------|------|
| `Load()` | `Lock()` | 写锁：修改 probes 和 statuses |
| `Unload()` | `Lock()` | 写锁：修改 probes 和 statuses |
| `Update()` | `Lock()` | 写锁：修改探针状态和 statuses |
| `Status()` | `RLock()` | 读锁：只读访问 |
| `ListStatus()` | `RLock()` | 读锁：只读访问 |
| `GetProbeInfo()` | `RLock()` | 读锁：只读访问 |
| `ListProbeInfos()` | `RLock()` | 读锁：只读访问 |

**懒加载模式**：

```go
func (c *Controller) EnableLazyDB(dbPath string, dbOpener func(path string) (*sql.DB, error)) {
    c.dbPath = dbPath
    c.dbOpener = dbOpener
}

func (c *Controller) openDBLocked() error {
    if c.dbOpener == nil {
        return ErrDBOpenerNotConfigured
    }
    db, err := c.dbOpener(c.dbPath)
    c.db = db
    return nil
}
```

数据库连接在首个探针加载时自动打开，最后一个探针卸载时自动关闭（CHECKPOINT + Close）。

### 4.3 Registry 的两阶段注册机制

**文件**：`internal/probes/registry.go`

**核心数据结构**：

```go
var (
    registryMu       sync.RWMutex
    registry         = make(map[string]func() Probe)      // 工厂函数注册表
    metadataRegistry = make(map[string]ProbeMetadata)     // 元数据注册表
)
```

**两阶段注册流程**：

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           两阶段注册架构                                     │
└─────────────────────────────────────────────────────────────────────────────┘

阶段 1: 静态元数据注册（服务启动时）
─────────────────────────────────────────────────────────────────────────────
  LoadProbesFromYAML(baseDir)
       │
       ├──► 遍历 probes/*.yaml
       │
       ├──► yaml.Unmarshal() ──► ProbeConfigFile
       │
       └──► metadataRegistry[probe.Type] = probe  // 存储元数据

阶段 2: 动态工厂注册（程序初始化时）
─────────────────────────────────────────────────────────────────────────────
  各探针包的 init()
       │
       └──► probes.Register(name, factory)
                │
                └──► registry[name] = factory  // 存储工厂函数

运行时：探针实例化
─────────────────────────────────────────────────────────────────────────────
  Controller.Load(name)
       │
       ├──► GetProbe(name)
       │         │
       │         └──► factory := registry[name]
       │         └──► return factory()  // 创建新实例
       │
       └──► probe.Start(ctx, db)  // 初始化并运行
```

**关键 API**：

```go
// 静态元数据管理
func LoadProbesFromYAML(baseDir string) error
func GetProbeMetadata(name string) (ProbeMetadata, bool)
func HasMetadata(name string) bool

// 动态工厂管理
func Register(name string, factory func() Probe)
func GetProbe(name string) (Probe, bool)
func HasProbe(name string) bool

// 信息聚合（合并静态+动态信息）
func GetProbeInfo(name string, status *ProbeStatus) (ProbeInfo, bool)
func ListProbeInfos(statusMap map[string]ProbeStatus) []ProbeInfo
```

### 4.4 MCP Server 的工具暴露机制

**文件**：`internal/server/server.go`

**Server 结构**：

```go
type Server struct {
    cfg        ServerConfig         // 配置（传输模式、端口、Token）
    controller *probes.Controller   // 探针控制器
    mcpServer  *server.MCPServer    // mcp-go 服务实例
    logger     *logx.Logger         // 结构化日志
}
```

**工具注册**：

```go
func (s *Server) registerTools() {
    // 工具 1：探针资源信息查询
    s.mcpServer.AddTool(buildProbeResourceInfoTool(), s.handleProbeResourceInfo)

    // 工具 2：系统观测控制（load/unload/status）
    s.mcpServer.AddTool(buildSystemObserveControlTool(), s.handleSystemObserveControl)

    // 工具 3：探针参数定制
    s.mcpServer.AddTool(buildProbeCustomizeTool(), s.handleProbeCustomize)
}
```

**工具定义**：

```go
// probe_resource_info：查询探针元数据和状态
func buildProbeResourceInfoTool() mcp.Tool {
    return mcp.NewTool(
        "probe_resource_info",
        mcp.WithDescription("Get probe resource information including metadata and runtime status."),
        mcp.WithString("probeName", mcp.Description("Specific probe ID to query. If empty, returns all probes.")),
    )
}

// system_observe_control：探针生命周期控制
func buildSystemObserveControlTool() mcp.Tool {
    return mcp.NewTool(
        "system_observe_control",
        mcp.WithDescription("Control probe lifecycle operations."),
        mcp.WithString("probeName", mcp.Required()),
        mcp.WithString("operation", mcp.Required(), mcp.Enum("load", "unload", "status")),
    )
}

// probe_customize：探针参数更新
func buildProbeCustomizeTool() mcp.Tool {
    return mcp.NewTool(
        "probe_customize",
        mcp.WithDescription("Customize probe runtime parameters."),
        mcp.WithString("name", mcp.Required()),
        mcp.WithObject("params", mcp.Required()),
        mcp.WithBoolean("dryRun"),
        mcp.WithString("reloadPolicy"),
    )
}
```

**传输模式**：

```go
func (s *Server) Start(ctx context.Context) error {
    switch s.cfg.Transport {
    case TransportStdio:
        // STDIO 模式：适用于本地 MCP 客户端（如 Claude Desktop）
        return server.ServeStdio(s.mcpServer)
    case TransportHTTP:
        // HTTP 模式：适用于远程访问，需配置 Bearer Token
        httpServer := &http.Server{Addr: ":" + s.cfg.HTTPPort, Handler: h}
        // ... 启动 HTTP 服务
    }
}
```

---

## 5. 具体工作流

### 5.1 探针启动流程

```
AI Agent 请求
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ handleSystemObserveControl(ctx, req)                                        │
│  operation = "load", probeName = "nfs_file_read"                            │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Controller.Load(ctx, "nfs_file_read")                                       │
│                                                                             │
│  1. 获取写锁：c.mu.Lock()                                                   │
│                                                                             │
│  2. 懒加载数据库（如果未打开）：                                            │
│     if c.db == nil { c.openDBLocked() }                                     │
│                                                                             │
│  3. 检查是否已加载：                                                        │
│     if _, loaded := c.probes[name]; loaded {                                │
│         return ErrProbeAlreadyLoaded                                        │
│     }                                                                       │
│                                                                             │
│  4. 获取探针工厂并创建实例：                                                │
│     probe, ok := GetProbe(name)  // 调用工厂函数                            │
│                                                                             │
│  5. 启动探针：                                                              │
│     if err := probe.Start(ctx, c.db); err != nil {                          │
│         probe.SetState(StateError, err.Error())                             │
│         return error                                                        │
│     }                                                                       │
│                                                                             │
│  6. 更新状态：                                                              │
│     probe.SetState(StateLoaded)                                             │
│     c.probes[name] = probe                                                  │
│     c.statuses[name] = probe.GetStatus()                                    │
│                                                                             │
│  7. 返回状态                                                                │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ NFSFileReadProbe.Start(ctx, db)                                             │
│                                                                             │
│  1. 创建 DuckDB 表（如果不存在）                                            │
│     db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS nfs_file_read (...)`)   │
│                                                                             │
│  2. 创建 DuckDB Appender（用于高效批量写入）                                │
│     p.appender, p.dbConn, err = database.NewDuckDBAppender(...)             │
│                                                                             │
│  3. 加载 eBPF 对象                                                          │
│     loadBpfObjects(&p.objs, nil)                                            │
│                                                                             │
│  4. 附加 eBPF 程序到内核探针点                                              │
│     entryLink, err := link.AttachTracing(link.TracingOptions{               │
│         Program: p.objs.NfsFileRead,                                        │
│     })                                                                      │
│     p.links = append(p.links, entryLink)                                    │
│                                                                             │
│     exitLink, err := link.AttachTracing(link.TracingOptions{                │
│         Program: p.objs.NfsFileReadExit,                                    │
│     })                                                                      │
│     p.links = append(p.links, exitLink)                                     │
│                                                                             │
│  5. 创建 Ring Buffer 读取器                                                 │
│     p.reader, err = ringbuf.NewReader(p.objs.Events)                        │
│                                                                             │
│  6. 启动事件消费 goroutine                                                  │
│     probeCtx, cancel := context.WithCancel(context.Background())            │
│     p.cancel = cancel                                                       │
│     p.done = make(chan struct{})                                            │
│     go p.consume(probeCtx)                                                  │
│                                                                             │
│  7. 返回成功                                                                │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
  返回 Status{Name: "nfs_file_read", State: "loaded", Loaded: true}
```

### 5.2 探针停止流程

```
AI Agent 请求
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ handleSystemObserveControl(ctx, req)                                        │
│  operation = "unload", probeName = "nfs_file_read"                          │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Controller.Unload("nfs_file_read")                                          │
│                                                                             │
│  1. 获取写锁：c.mu.Lock()                                                   │
│                                                                             │
│  2. 检查探针是否已加载：                                                    │
│     probe, loaded := c.probes[name]                                         │
│     if !loaded { return ErrProbeNotLoaded }                                 │
│                                                                             │
│  3. 停止探针：                                                              │
│     if err := probe.Stop(); err != nil {                                    │
│         probe.SetState(StateError, err.Error())                             │
│         return error                                                        │
│     }                                                                       │
│                                                                             │
│  4. 更新状态：                                                              │
│     probe.SetState(StateUnloaded)                                           │
│     delete(c.probes, name)                                                  │
│     c.statuses[name] = probe.GetStatus()                                    │
│                                                                             │
│  5. 检查是否需要关闭数据库（懒加载模式）：                                  │
│     if len(c.probes) == 0 && c.dbOpener != nil {                            │
│         c.checkpointAndCloseDBLocked()                                      │
│     }                                                                       │
│                                                                             │
│  6. 返回状态                                                                │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ NFSFileReadProbe.Stop()                                                     │
│                                                                             │
│  1. 取消 context，触发消费 goroutine 退出                                   │
│     if p.cancel != nil { p.cancel() }                                       │
│                                                                             │
│  2. 等待消费 goroutine 退出                                                 │
│     if p.done != nil { <-p.done }                                           │
│                                                                             │
│  3. Flush 剩余数据并关闭 Appender                                           │
│     if p.appender != nil {                                                  │
│         _ = p.appender.Flush()                                              │
│         _ = p.appender.Close()                                              │
│     }                                                                       │
│                                                                             │
│  4. 关闭数据库连接                                                          │
│     if p.dbConn != nil { _ = p.dbConn.Close() }                             │
│                                                                             │
│  5. 关闭所有 eBPF 链接                                                      │
│     for _, l := range p.links { _ = l.Close() }                             │
│     p.links = nil                                                           │
│                                                                             │
│  6. 关闭 eBPF 对象                                                          │
│     if p.objs != (bpfObjects{}) { _ = p.objs.Close() }                      │
│                                                                             │
│  7. 返回成功                                                                │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
  返回 Status{Name: "nfs_file_read", State: "unloaded", Loaded: false}
```

### 5.3 探针更新流程

```
AI Agent 请求
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ handleProbeCustomize(ctx, req)                                              │
│  name = "nfs_file_read", params = {"filter_pid": 1234}                      │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Controller.Update("nfs_file_read", {"filter_pid": 1234})                    │
│                                                                             │
│  1. 获取写锁：c.mu.Lock()                                                   │
│                                                                             │
│  2. 检查探针是否已加载：                                                    │
│     probe, loaded := c.probes[name]                                         │
│     if !loaded { return ErrProbeNotLoaded }                                 │
│                                                                             │
│  3. 更新探针参数：                                                          │
│     if err := probe.Update(config); err != nil {                            │
│         probe.SetState(StateError, err.Error())                             │
│         return error                                                        │
│     }                                                                       │
│                                                                             │
│  4. 更新状态：                                                              │
│     probe.SetState(StateLoaded)                                             │
│     c.statuses[name] = probe.GetStatus()                                    │
│                                                                             │
│  5. 返回状态                                                                │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ NFSFileReadProbe.Update({"filter_pid": 1234})                               │
│                                                                             │
│  1. 检查 eBPF 对象是否已初始化                                              │
│     if p.objs.FilterPid == nil { return ErrProbeNotStarted }                │
│                                                                             │
│  2. 处理 filter_pid 参数                                                    │
│     if raw, ok := config["filter_pid"]; ok {                                │
│         pid, err := toUint64(raw)                                           │
│         if err != nil { return error }                                      │
│         if err := p.objs.FilterPid.Set(pid); err != nil {                   │
│             return error                                                    │
│         }                                                                   │
│     }                                                                       │
│                                                                             │
│  3. 处理 filter_file 参数（字符串转字节数组）                               │
│     if raw, ok := config["filter_file"]; ok {                               │
│         var fileBytes [16]byte                                              │
│         copy(fileBytes[:], raw.(string))                                    │
│         p.objs.FilterFile.Set(fileBytes)                                    │
│     }                                                                       │
│                                                                             │
│  4. 处理 filter_comm 参数                                                   │
│     if raw, ok := config["filter_comm"]; ok {                               │
│         var commBytes [32]byte                                              │
│         copy(commBytes[:], raw.(string))                                    │
│         p.objs.FilterComm.Set(commBytes)                                    │
│     }                                                                       │
│                                                                             │
│  5. 返回成功                                                                │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
  参数通过 eBPF Map 同步到内核态，即时生效
```

### 5.4 状态查询流程

```
AI Agent 请求
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ handleProbeResourceInfo(ctx, req)                                           │
│  probeName = "" (查询所有) 或 probeName = "nfs_file_read" (查询单个)          │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 查询单个探针：Controller.GetProbeInfo(name)                                 │
│                                                                             │
│  1. 获取读锁：c.mu.RLock()                                                  │
│                                                                             │
│  2. 获取运行时状态（如果已加载）                                            │
│     if probe, loaded := c.probes[name]; loaded {                            │
│         status = probe.GetStatus()                                          │
│     }                                                                       │
│                                                                             │
│  3. 从 registry 获取完整信息（元数据 + 状态）                               │
│     info, exists := GetProbeInfo(name, &status)                             │
│                                                                             │
│  4. 返回 ProbeInfo{Metadata, Status}                                        │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 查询所有探针：Controller.ListProbeInfos()                                   │
│                                                                             │
│  1. 获取读锁：c.mu.RLock()                                                  │
│                                                                             │
│  2. 构建状态映射                                                            │
│     for name, probe := range c.probes {                                     │
│         statusMap[name] = probe.GetStatus()                                 │
│     }                                                                       │
│                                                                             │
│  3. 从 registry 获取所有探针信息                                            │
│     infos := ListProbeInfos(statusMap)                                      │
│                                                                             │
│  4. 按 Type 排序                                                            │
│     sort.Slice(infos, func(i, j int) bool {                                 │
│         return infos[i].Metadata.Type < infos[j].Metadata.Type              │
│     })                                                                      │
│                                                                             │
│  5. 返回 []ProbeInfo                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.5 错误处理和优雅退出机制

#### 错误处理体系

**分层错误定义**（`internal/logx/errors.go`）：

```go
// 错误码定义
type ErrorCode string
const (
    ErrorInvalidArgument      ErrorCode = "INVALID_ARGUMENT"
    ErrorPermissionDenied     ErrorCode = "PERMISSION_DENIED"
    ErrorQuotaExceeded        ErrorCode = "QUOTA_EXCEEDED"
    ErrorProbeNotFound        ErrorCode = "PROBE_NOT_FOUND"
    ErrorProbeNotLoaded       ErrorCode = "PROBE_NOT_LOADED"
    ErrorProbeAlreadyLoaded   ErrorCode = "PROBE_ALREADY_LOADED"
    ErrorProbeStartFailed     ErrorCode = "PROBE_START_FAILED"
    ErrorProbeStopFailed      ErrorCode = "PROBE_STOP_FAILED"
    ErrorProbeUpdateFailed    ErrorCode = "PROBE_UPDATE_FAILED"
    ErrorDBConnection         ErrorCode = "DB_CONNECTION_FAILED"
    ErrorDBOperation          ErrorCode = "DB_OPERATION_FAILED"
    ErrorRuntimeFailure       ErrorCode = "RUNTIME_FAILURE"
    ErrorConflict             ErrorCode = "CONFLICT"
)

// 全局错误变量
var (
    ErrProbeNotFound      = errors.New("probe not found")
    ErrProbeAlreadyLoaded = errors.New("probe already loaded")
    ErrProbeNotLoaded     = errors.New("probe not loaded")
    ErrProbeNotStarted    = errors.New("probe is not started")
    ErrDBIsNil            = errors.New("database is nil")
    // ...
)

// 领域错误（服务层）
type DomainError struct {
    Code    ErrorCode
    Level   Level
    Message string
    Cause   error
}

// 工具错误（协议层）
type ToolError struct {
    Code    ErrorCode
    Level   Level
    Message string
}
```

**错误映射流程**：

```
底层错误（ebpf-go, duckdb）
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 探针实现层                                                                  │
│  logx.NewDomainErrorWithCause(ErrorProbeStartFailed, "attaching tracing", err)
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Controller 层                                                               │
│  包装错误上下文，更新探针状态为 error                                       │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Server 层                                                                   │
│  mapped := logx.MapDomainError(err)                                         │
│  return mcp.NewToolResultError(mapped.String())                             │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
  返回给 AI Agent："PROBE_START_FAILED: attaching tracing: ..."
```

#### 优雅退出机制

**信号处理**（`main.go`）：

```go
ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer stop()

if err := s.Start(ctx); err != nil {
    log.Fatalf("server stopped with error: %v", err)
}
```

**Server 层退出处理**：

```go
func (s *Server) Start(ctx context.Context) error {
    // ...
    select {
    case <-ctx.Done():
        // 收到退出信号
        s.logger.Infof("shutdown signal received, stopping probes & server")

        // 1. 先停止所有探针
        if err := s.controller.Shutdown(); err != nil {
            s.logger.Errorf("controller shutdown error: %v", err)
        }

        // 2. 关闭 HTTP 服务器
        shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        httpServer.Shutdown(shutdownCtx)

        return nil
    }
}
```

**Controller 层退出处理**：

```go
func (c *Controller) Shutdown() error {
    c.mu.Lock()
    defer c.mu.Unlock()

    var shutdownErr error

    // 1. 停止所有已加载的探针
    for name, probe := range c.probes {
        if err := probe.Stop(); err != nil && shutdownErr == nil {
            shutdownErr = err
            probe.SetState(StateError, err.Error())
            continue
        }
        probe.SetState(StateUnloaded)
    }

    // 2. 清空探针映射
    c.probes = make(map[string]Probe)

    // 3. 关闭数据库（CHECKPOINT + Close）
    if c.db != nil && c.dbOpener != nil {
        _ = c.checkpointAndCloseDBLocked()
    }

    return shutdownErr
}
```

**探针层退出处理**：

```go
func (p *NFSFileReadProbe) Stop() error {
    // 1. 取消 context，通知消费 goroutine 退出
    if p.cancel != nil {
        p.cancel()
    }

    // 2. 等待消费 goroutine 退出（通过 done channel）
    if p.done != nil {
        <-p.done
    }

    // 3. Flush 数据并关闭 Appender
    if p.appender != nil {
        _ = p.appender.Flush()
        _ = p.appender.Close()
    }

    // 4. 关闭数据库连接
    if p.dbConn != nil {
        _ = p.dbConn.Close()
    }

    // 5. 关闭 eBPF 链接
    for _, l := range p.links {
        _ = l.Close()
    }

    // 6. 关闭 eBPF 对象
    if p.objs != (bpfObjects{}) {
        _ = p.objs.Close()
    }

    return nil
}
```

**消费 goroutine 退出机制**：

```go
func (p *NFSFileReadProbe) consume(ctx context.Context) {
    defer close(p.done)  // 通知 Stop() 已退出

    for {
        select {
        case <-ctx.Done():
            // 收到取消信号，退出
            return
        default:
        }

        // 阻塞读取，但会被 reader.Close() 打断
        record, err := p.reader.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) {
                // Ring Buffer 已关闭，退出
                return
            }
            continue
        }

        // 处理事件...
    }
}

// Stop() 中的桥接 goroutine
go func() {
    <-probeCtx.Done()
    if p.reader != nil {
        _ = p.reader.Close()  // 打断 Read() 阻塞
    }
}()
```

---

## 6. 附录

### 6.1 项目目录结构

```
.
├── main.go                          # 应用入口
├── go.mod                           # Go 模块定义
├── probes/                          # YAML 探针配置（静态元数据）
│   ├── nfs-file-read.yaml
│   ├── nfs-file-write.yaml
│   ├── nfs_getattr.yaml
│   ├── nfs_setattr.yaml
│   ├── nfsd4_read.yaml
│   ├── nfsd4_write.yaml
│   └── sys_call_trace.yaml
├── ebpf/                            # eBPF C 程序和 Go 实现
│   ├── headers/                     # BPF 辅助定义
│   ├── NFS-client/                  # NFS 客户端探针
│   │   ├── nfs_file_read/
│   │   │   ├── nfs_file_read.c      # eBPF C 程序
│   │   │   ├── bpf_bpfeb.go         # 大端字节序绑定
│   │   │   ├── bpf_bpfel.go         # 小端字节序绑定
│   │   │   └── probe.go             # Go 探针实现
│   │   ├── nfs_file_write/
│   │   ├── nfs_getattr/
│   │   └── nfs_setattr/
│   ├── nfsd/                        # NFS 服务端探针
│   │   ├── nfsd4_read/
│   │   └── nfsd4_write/
│   └── Sys-call/                    # 系统调用探针
│       └── sys_call_trace/
├── internal/
│   ├── probes/                      # 探针控制器、注册表、接口
│   │   ├── probe.go                 # Probe 接口定义
│   │   ├── controller.go            # Controller 实现
│   │   ├── registry.go              # Registry 实现
│   │   └── controller_test.go       # 控制器测试
│   ├── server/                      # MCP 服务器实现
│   │   ├── server.go                # Server 实现
│   │   ├── config.go                # 配置定义
│   │   ├── http_middleware.go       # HTTP 中间件
│   │   └── *_test.go                # 测试文件
│   ├── db/                          # DuckDB 工具
│   │   └── duckdb.go                # Appender 创建
│   └── logx/                        # 结构化日志和错误
│       ├── errors.go                # 错误定义和映射
│       └── logger.go                # 日志实现
├── test/                            # 测试目录
│   ├── integration/                 # 集成测试
│   └── probes/                      # 探针测试
└── database/                        # DuckDB 数据库文件
```

### 6.2 依赖说明

| 依赖 | 版本 | 用途 |
|------|------|------|
| github.com/mark3labs/mcp-go | v0.45.0 | MCP 协议实现 |
| github.com/cilium/ebpf | v0.21.0 | eBPF 程序加载和管理 |
| github.com/duckdb/duckdb-go/v2 | v2.10500.0 | DuckDB 数据库驱动 |
| github.com/joho/godotenv | v1.5.1 | 环境变量加载 |
| gopkg.in/yaml.v3 | v3.0.1 | YAML 配置解析 |

### 6.3 相关文档索引

- [启动文档](start.md) - 环境搭建、快速开始、配置指南
- [测试文档](testbench.md) - 测试策略、用例说明、质量门禁
- [探针文档](probes.md) - 探针管理、扩展方法、probe-creator skill 使用

---

*最后更新时间：2026-04-06*
