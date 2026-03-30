# MCP启动到探针注册全流程

本文档详细描述eBPF-MCP从启动到探针注册的完整流程，包括函数调用关系和关键组件交互。

## 一、整体流程概览

```mermaid
flowchart TB
    subgraph 程序启动阶段
        A[main.go:main] --> B[导入探针包]
        B --> C[probe.go:init]
        C --> D[registry.go:Register]
    end

    subgraph 核心组件初始化
        A --> E[probes.NewController]
        E --> F[server.New]
        F --> G[registerTools]
    end

    subgraph 服务运行阶段
        F --> H[s.Start]
        H --> I{Transport模式}
        I -->|STDIO| J[ServeStdio]
        I -->|HTTP| K[HTTP Server]
    end

    D --> L[registry<br/>探针工厂映射]
    E --> M[controller<br/>探针实例管理]
    G --> N[MCP Tools注册]
```

## 二、详细流程分析

### 2.1 程序入口与探针预注册

**入口文件**: `main.go`

```mermaid
sequenceDiagram
    participant main as main.go:main()
    participant import as import _ "ebpf/NFS-client"
    participant init as probe.go:init()
    participant reg as registry.go

    main->>import: 触发包初始化
    import->>init: 执行init函数
    init->>reg: Register("nfs_file_read", factory)
    reg->>reg: registry[name] = factory
    reg-->>init: 完成注册
    init-->>main: 继续执行
```

**关键代码** (`main.go:15`):
```go
import (
    _ "ebpf-mcp/ebpf/NFS-client"  // 触发init()执行
)
```

**探针自注册** (`ebpf/NFS-client/nfs_file_read/probe.go:22-26`):
```go
func init() {
    probes.Register("nfs_file_read", func() probes.Probe {
        return NewNFSFileReadProbe()
    })
}
```

### 2.2 Controller初始化

**文件**: `internal/probes/controller.go:36-45`

```mermaid
flowchart LR
    A[NewController] --> B{db == nil?}
    B -->|是| C[返回错误]
    B -->|否| D[创建Controller]
    D --> E[probes: map<br/>已加载探针实例]
    D --> F[statuses: map<br/>探针运行状态]
```

**关键代码**:
```go
func NewController(db *sql.DB) (*Controller, error) {
    if db == nil {
        return nil, fmt.Errorf("db is nil")
    }
    return &Controller{
        db:       db,
        probes:   make(map[string]Probe),      // 已加载的探针实例
        statuses: make(map[string]ProbeStatus), // 探针状态
    }, nil
}
```

### 2.3 Server初始化与Tools注册

**文件**: `internal/server/server.go:25-57`

```mermaid
sequenceDiagram
    participant main as main.go
    participant new as server.New
    participant val as config.Validate
    participant log as logx.NewRunLogger
    participant mcp as server.NewMCPServer
    participant reg as registerTools

    main->>new: 传入config和controller
    new->>val: 验证配置
    val-->>new: 返回
    new->>log: 创建Logger
    log-->>new: 返回logger
    new->>mcp: 创建MCPServer
    mcp-->>new: 返回mcpServer
    new->>reg: 注册Tools
    reg->>reg: AddTool(probe_customize)
    reg->>reg: AddTool(system_observe_control)
    reg->>reg: AddTool(probe_resource_info)
    reg-->>new: 完成
    new-->>main: 返回Server实例
```

### 2.4 服务启动

```mermaid
flowchart TB
    A[s.Start] --> B{Transport}
    B -->|stdio| C[server.ServeStdio]
    B -->|http| D[创建HTTPServer]
    D --> E[设置路由]
    E --> F[添加中间件]
    F --> G[httpServer.ListenAndServe]
```

## 三、核心数据结构关系

```mermaid
classDiagram
    class Registry {
        +registry map~string, func() Probe~
        +metadataRegistry map~string, ProbeMetadata~
        +Register(name, factory)
        +GetProbe(name) Probe
        +GetProbeMetadata(name) ProbeMetadata
        +LoadProbesFromYAML(baseDir)
    }

    class Controller {
        -db *sql.DB
        -probes map~string, Probe~
        -statuses map~string, ProbeStatus~
        +Load(ctx, name) error
        +Unload(name) error
        +Update(name, config) error
        +Status(name) ProbeStatus
        +Shutdown()
    }

    class Server {
        -cfg ServerConfig
        -controller *Controller
        -mcpServer *MCPServer
        -logger Logger
        +Start(ctx) error
        -registerTools()
    }

    class Probe {
        <<interface>>
        +Name() string
        +Start(ctx, dbConn) error
        +Stop() error
        +Update(config) error
        +GetMetadata() ProbeMetadata
        +GetStatus() ProbeStatus
        +SetState(state, errMsg...)
    }

    class NFSFileReadProbe {
        -metadata ProbeMetadata
        -status ProbeStatus
        -collection *ebpf.Collection
        -reader *perf.Reader
        +Start(ctx, dbConn) error
        +Stop() error
    }

    Registry --> Probe : 工厂创建
    Controller --> Probe : 管理实例
    Server --> Controller : 依赖调用
    Probe <|-- NFSFileReadProbe : 实现
```

## 四、关键问题与注意事项

### 4.1 YAML配置加载现状

**重要发现**: `LoadProbesFromYAML` 函数当前**未被main.go调用**，仅在测试中使用。

**影响**:
- 探针元数据只能从代码中的默认配置获取
- `probes/` 目录下的YAML配置文件**不会被自动加载**

**代码位置** (`internal/probes/registry.go:32-55`):
```go
func LoadProbesFromYAML(baseDir string) error {
    probesDir := filepath.Join(baseDir, "probes")
    // 遍历YAML文件并解析到metadataRegistry
}
```

**建议修复**: 在 `main.go` 的controller创建之前添加：
```go
// 加载YAML探针配置
if err := probes.LoadProbesFromYAML("."); err != nil {
    log.Printf("Warning: failed to load probe YAML configs: %v", err)
}
```

### 4.2 探针注册依赖

当前实现依赖Go的`init()`机制：

1. **必须显式导入探针包**，否则不会触发`init()`
2. **导入顺序**影响注册顺序（虽然通常不重要）
3. **未导入的探针**不会自动注册

**当前导入** (`main.go:15`):
```go
_ "ebpf-mcp/ebpf/NFS-client"  // 仅NFS-client探针被注册
```

## 五、函数调用关系汇总

### 5.1 启动阶段调用链

```
main()
├── 导入 _ "ebpf-mcp/ebpf/NFS-client"
│   └── probe.go:init()
│       └── probes.Register("nfs_file_read", factory)
│           └── registry[name] = factory
│
├── probes.NewController(db)
│   └── 创建Controller{probes: map, statuses: map}
│
├── server.New(cfg, controller)
│   ├── config.Validate()
│   ├── logx.NewRunLogger()
│   ├── server.NewMCPServer()
│   └── registerTools()
│       ├── AddTool("probe_customize")
│       ├── AddTool("system_observe_control")
│       └── AddTool("probe_resource_info")
│
└── s.Start(ctx)
    ├── STDIO: server.ServeStdio()
    └── HTTP: http.ListenAndServe()
```

### 5.2 探针加载调用链（运行时）

```
system_observe_control Tool
└── controller.Load(ctx, name)
    ├── GetProbe(name) -> factory()
    │   └── NewNFSFileReadProbe()
    │       └── GetProbeMetadata(name)
    └── probe.Start(ctx, db)
        ├── ebpf.LoadCollection()
        ├── ebpf.Attach()
        └── 启动事件消费goroutine
```

## 六、关键文件索引

| 组件 | 文件路径 | 关键函数/类型 |
|------|---------|--------------|
| 程序入口 | `main.go` | `main()` |
| Server | `internal/server/server.go` | `New()`, `Start()`, `registerTools()` |
| Server配置 | `internal/server/config.go` | `ServerConfig`, `Validate()` |
| Controller | `internal/probes/controller.go` | `Controller`, `NewController()`, `Load()`, `Unload()` |
| Registry | `internal/probes/registry.go` | `Register()`, `GetProbe()`, `LoadProbesFromYAML()` |
| Probe接口 | `internal/probes/probe.go` | `Probe`接口, `ProbeMetadata`, `ProbeStatus` |
| NFS探针 | `ebpf/NFS-client/nfs_file_read/probe.go` | `init()`, `NFSFileReadProbe` |
| YAML配置 | `probes/nfs-file-read.yaml` | 探针元数据配置 |

## 七、流程验证结论

经代码审查，当前流程为：

1. ✅ **启动协议层**: `server.New()` 创建MCPServer并注册Tools
2. ✅ **启动Controller**: `probes.NewController()` 创建控制器实例
3. ⚠️ **YAML元数据加载**: `LoadProbesFromYAML()` **未被调用**，YAML配置未自动加载
4. ✅ **探针工厂注册**: 通过`init()`机制在导入时完成

**待修复问题**: 需要在 `main.go` 中添加 `LoadProbesFromYAML` 调用来启用YAML配置加载。
