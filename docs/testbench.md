# 测试基准文档 (Testbench)

本文档汇总了 eBPF-MCP 项目的所有测试项目，识别测试盲区，并指导未来测试补充方向。

## 测试概览

### 当前测试矩阵

| 测试文件 | 类型 | 主要目的 | 权限要求 |
|---------|------|---------|---------|
| `internal/probes/controller_test.go` | 单元测试 | Probe Controller 生命周期管理 | 无 |
| `internal/logx/errors_test.go` | 单元测试 | 领域错误映射机制 | 无 |
| `internal/server/http_middleware_test.go` | 单元测试 | HTTP Bearer Token 认证中间件 | 无 |
| `internal/server/test_helpers_test.go` | 测试辅助 | 临时 DuckDB 和 Mock Server | 无 |
| `test/probes/helper_test.go` | 测试辅助 | 探针测试框架（`ProbeTestHelper`） | 无 |
| `test/probes/common_test.go` | 测试辅助 | 探针测试公共函数（`openTestDB`、YAML 加载） | 无 |
| `test/probes/nfs_file_read_test.go` | 集成测试 | `nfs_file_read` 探针完整功能 | root |
| `test/probes/nfs_file_write_test.go` | 集成测试 | `nfs_file_write` 探针完整功能 | root |
| `test/probes/dual_probe_test.go` | 集成测试 | 多探针并发加载与资源隔离 | root |
| `test/probes/sys_call_trace_test.go` | 集成测试 | `sys_call_trace` 探针完整功能 | root |
| `test/probes/nfs_getattr_test.go` | 集成测试 | `nfs_getattr` 探针完整功能 | root |
| `test/probes/nfs_setattr_test.go` | 集成测试 | `nfs_setattr` 探针完整功能 | root |
| `test/integration/mock_probe.go` | 测试辅助 | Mock 探针实现，用于无特权环境测试 | 无 |
| `test/integration/helper_test.go` | 测试辅助 | HTTP E2E 测试辅助函数和 MCP 响应解析 | 无 |
| `test/integration/mcp_http_e2e_test.go` | E2E 测试 | HTTP 传输模式下 MCP 工具全流程测试 | 无 |
| `test/integration/mcp_stdio_e2e_test.go` | E2E 测试 | STDIO 传输模式下服务器创建与工具注册测试 | 无 |

---

## 单元测试 (Unit Tests)

### 1. `internal/probes/controller_test.go`

**测试目标**: Probe Controller 的核心生命周期管理

**测试函数**:
- `TestControllerLifecycle` - 完整的 probe 生命周期：加载 → 更新 → 查询状态 → 卸载
- `TestControllerConflicts` - 状态冲突处理：重复加载、重复卸载
- `TestControllerNotFound` - 未注册 probe 的错误处理

**关键验证点**:
- Probe 状态机转换正确性 (`unloaded` → `loaded` → `unloaded`)
- 并发安全（通过 `stubProbe` 调用计数验证）
- 错误类型正确性 (`ErrProbeAlreadyLoaded`, `ErrProbeNotLoaded`, `ErrProbeNotFound`)

---

### 2. `internal/logx/errors_test.go`

**测试目标**: 领域错误码映射机制

**测试函数**:
- `TestMapDomainError` - 各种领域错误到标准错误码的映射

**覆盖的错误类型**:
- `ErrorInvalidArgument` - 参数无效
- `ErrorPermissionDenied` - 权限拒绝
- `ErrorQuotaExceeded` - 配额超限
- `ErrorProbeNotFound` - Probe 未找到
- `ErrorConflict` - 状态冲突
- `ErrorRuntimeFailure` - 运行时失败
- 未知错误回退处理

---

### 3. `internal/server/http_middleware_test.go`

**测试目标**: HTTP 认证中间件

**测试函数**:
- `TestBearerAuthMiddleware` - Bearer Token 认证逻辑

**测试场景**:
- Token 缺失时返回 401 Unauthorized
- Token 无效时返回 401 Unauthorized
- Token 有效时允许请求通过

---

### 4. `internal/server/test_helpers_test.go`

**测试目标**: 测试辅助工具

**提供的辅助函数**:
- `openTestDB()` - 创建临时 DuckDB 数据库
- `newTestServer(t)` - 创建带 controller 的测试服务器

---

## 集成测试 (Integration Tests)

### 5. `test/probes/nfs_file_read_test.go`

**测试目标**: `nfs_file_read` eBPF 探针的完整功能验证

**测试函数**:
- `TestNFSFileReadProbe_Registration` - 探针注册和元数据完整性
- `TestNFSFileReadProbe_ControllerLifecycle` - Controller 生命周期管理
- `TestNFSFileReadProbe_FilterByPID` - PID 过滤功能
- `TestNFSFileReadProbe_DataCollection` - 数据收集和 DuckDB 持久化
- `TestNFSFileReadProbe_MacroVariables` - 宏变量更新
- `TestNFSFileReadProbe_ConcurrentAccess` - 并发访问安全性
- `TestNFSFileReadProbe_ErrorHandling` - 错误处理
- `TestNFSFileReadProbe_FullWorkflow` - 完整工作流测试
- `TestNFSFileReadProbe_ListOperations` - 列表操作
- `TestNFSFileReadProbe_MetadataIntegrity` - 元数据完整性

**前置条件**: 需要 root 权限（加载 eBPF 程序需要 `CAP_BPF`）

---

### 6. `test/probes/nfs_file_write_test.go`

**测试目标**: `nfs_file_write` eBPF 探针的完整功能验证

**测试函数**: 与 `nfs_file_read_test.go` 结构类似，覆盖 `nfs_file_write` 探针的注册、生命周期、PID 过滤、数据收集、宏变量、并发访问、错误处理、完整工作流、列表操作和元数据完整性。

---

### 7. `test/probes/dual_probe_test.go`

**测试目标**: 多探针并发加载与资源隔离

**测试函数**:
- `TestDualProbeHandleConflict` - 验证 `nfs_file_read` 和 `nfs_file_write` 同时加载不冲突
- `TestNFSProbeWithFIOAndFilterValidation` - 使用 `fio` 和 `dd` 进行真实数据收集及过滤验证

**关键验证点**:
- 两个探针能同时加载运行
- 数据表独立创建
- 事件独立收集
- 参数独立更新
- 卸载互不影响

---

### 8. `test/probes/sys_call_trace_test.go`

**测试目标**: `sys_call_trace` 系统调用追踪探针的完整功能验证

**测试函数**:
- `TestSysCallTraceProbe_Registration` - 探针注册和元数据验证
- `TestSysCallTraceProbe_ControllerLifecycle` - Controller 生命周期管理
- `TestSysCallTraceProbe_MacroVariables` - 宏变量更新（`filter_pid`、`filter_syscall_id`）
- `TestSysCallTraceProbe_DataCollection` - 数据收集和 DuckDB 持久化
- `TestSysCallTraceProbe_MetadataIntegrity` - 元数据完整性

**关键验证点**:
- 探针属于 `Sys-call` 层
- 支持 `filter_pid` 和 `filter_syscall_id` 两个过滤参数
- 输出字段包含 `pid`、`comm`、`syscall_id`、`ret`、`duration`、`enter_time_stamp`

---

### 9. `test/probes/nfs_getattr_test.go`

**测试目标**: `nfs_getattr` NFS 属性获取探针的完整功能验证

**测试函数**:
- `TestNFSGetattrProbe_Registration` - 探针注册和元数据验证
- `TestNFSGetattrProbe_ControllerLifecycle` - Controller 生命周期管理
- `TestNFSGetattrProbe_FilterByPID` - PID 过滤功能
- `TestNFSGetattrProbe_MacroVariables` - 宏变量更新
- `TestNFSGetattrProbe_MetadataIntegrity` - 元数据完整性

**关键验证点**:
- 探针属于 `nfs-client` 层
- 支持 `filter_pid` 过滤参数
- 输出字段包含 `pid`、`comm`、`time_stamp`、`lat`、`ret`

---

### 10. `test/probes/nfs_setattr_test.go`

**测试目标**: `nfs_setattr` NFS 属性设置探针的完整功能验证

**测试函数**:
- `TestNFSSetattrProbe_Registration` - 探针注册和元数据验证
- `TestNFSSetattrProbe_ControllerLifecycle` - Controller 生命周期管理
- `TestNFSSetattrProbe_FilterByPID` - PID 过滤功能
- `TestNFSSetattrProbe_MacroVariables` - 宏变量更新
- `TestNFSSetattrProbe_MetadataIntegrity` - 元数据完整性

**关键验证点**:
- 探针属于 `nfs-client` 层
- 支持 `filter_pid` 过滤参数
- 输出字段包含 `pid`、`comm`、`time_stamp`、`lat`、`ret`

---

### 11. 探针测试辅助文件

#### `test/probes/helper_test.go`

**提供的核心类型和函数**:
- `ProbeTestHelper` - 探针测试通用辅助结构
- `ProbeTestCase` - 定义探针测试用例
- `NewProbeTestHelper(t)` - 创建测试辅助对象
- `TestRegistration(tc)` - 测试探针注册
- `TestLifecycle(tc)` - 测试 Controller 生命周期
- `TestMacroVariables(tc, configs)` - 测试宏变量更新
- `TestMetadataIntegrity(tc)` - 测试元数据完整性
- `TestDataCollection(tc, triggerFunc)` - 测试数据收集和持久化
- `TestErrorHandling(tc)` - 测试错误处理
- `NFSProbeTestSuite` - NFS 探针通用测试套件

#### `test/probes/common_test.go`

**提供的核心函数**:
- `openTestDB(t)` - 创建临时 DuckDB 数据库
- `init()` - 自动从项目根目录加载 YAML 配置文件

---

## E2E 测试 (End-to-End Tests)

### 12. `test/integration/mcp_http_e2e_test.go`

**测试目标**: HTTP 传输模式下 MCP 服务器的完整功能验证

**测试函数**:
- `TestMCPHTTPAuthentication` - HTTP Bearer Token 认证（缺失/无效/有效 Token）
- `TestMCPProbeResourceInfo` - `probe_resource_info` 工具测试（列出全部、查询指定、不存在探针）
- `TestMCPProbeLifecycle` - 探针加载 → 状态查询 → 卸载完整生命周期
- `TestMCPProbeCustomize` - `probe_customize` 工具测试（正常更新、dryRun、未加载探针）
- `TestMCPErrorScenarios` - 各类错误场景（无效 operation、缺少参数、重复加载、卸载未加载探针）
- `TestMCPEndToEndWorkflow` - 完整端到端工作流
- `TestMCPProbeNotFound` - 探针不存在时的错误处理

**关键特性**:
- 使用 `httptest.Server` 避免端口冲突
- 使用 Mock 探针，无需 root 权限
- 完整覆盖 MCP 会话初始化（`initialize` + `notifications/initialized`）

---

### 13. `test/integration/mcp_stdio_e2e_test.go`

**测试目标**: STDIO 传输模式下 MCP 服务器创建与基础功能验证

**测试函数**:
- `TestMCPStdioServerCreation` - STDIO 服务器创建和工具注册验证
- `TestMCPStdioToolsRegistration` - 三个 MCP 工具详情验证
- `TestMCPStdioServerConfig` - 默认/显式 STDIO 传输配置验证
- `TestMCPStdioBasicCommunication` - 底层 MCP 服务器可访问性验证
- `TestMCPStdioServerWithProbes` - 带 Mock 探针注册的服务器验证
- `TestMCPStdioServerStartTimeout` - 服务器启动超时退出场景

**关键特性**:
- 无需 root 权限
- 不依赖外部网络端口
- 验证 `MCPServer()` 返回非 nil 且 3 个工具均已注册

---

### 14. E2E 测试辅助文件

#### `test/integration/mock_probe.go`

**提供的核心类型和函数**:
- `MockProbe` - 内存探针实现，无 eBPF 依赖
- `NewMockProbe(name)` - 创建 Mock 探针
- `GetStartCalls()` / `GetStopCalls()` / `GetUpdateCalls()` - 获取调用次数
- `GetLastConfig()` - 获取最后一次配置
- `SetShouldError(bool)` / `Reset()` - 控制错误模拟和状态重置

#### `test/integration/helper_test.go`

**提供的核心类型和函数**:
- `testServer` - 封装测试服务器、控制器、DB、`httptest.Server`
- `setupTestServer(t)` / `setupTestServerWithConfig(t, cfg)` - 创建 HTTP 测试服务器
- `initMCPSession(t, baseURL, token)` - 初始化 MCP HTTP session
- `callTool(t, baseURL, token, sessionID, id, toolName, arguments)` - 调用 MCP 工具
- `mcpResponse` / `mcpError` / `callToolResult` - MCP 响应解析结构
- `parseMCPResponse(t, resp)` - 解析 HTTP 响应为 MCP 响应
- `registerMockProbe(t, name)` - 注册 Mock 探针

---

## 测试盲区分析

### 已覆盖（从盲区中移除）

以下区域在当前代码库中已有测试覆盖：

- **MCP 协议层测试**: `test/integration/mcp_http_e2e_test.go` 和 `mcp_stdio_e2e_test.go` 覆盖
- **probe_customize 工具**: `TestMCPProbeCustomize` 已覆盖参数更新和 dryRun 逻辑
- **probe_resource_info 工具**: `TestMCPProbeResourceInfo` 已覆盖元数据查询
- **HTTP 传输层**: `TestMCPHTTPAuthentication` 和 HTTP E2E 测试已覆盖
- **STDIO 传输层**: `mcp_stdio_e2e_test.go` 已覆盖基础启动和工具注册

###  remaining 盲区

#### 高优先级盲区

| 盲区 | 影响 | 建议补充测试 |
|------|------|-------------|
| **Registry 持久化/重载** | YAML 加载异常时的行为 | 模拟 YAML 解析失败、目录不存在场景 |
| **Controller.Shutdown 并发安全** | 多探针同时卸载的资源竞争 | 构造加载多个探针后并发调用 Shutdown |
| **探针启动失败状态回滚** | eBPF 加载失败后的残留状态 | Mock `Start` 返回错误，验证 Controller 不保留 loaded 状态 |

#### 中优先级盲区

| 盲区 | 影响 | 建议补充测试 |
|------|------|-------------|
| **DuckDB 连接失败** | 数据库异常处理 | 模拟数据库连接失败，验证错误处理 |
| **RingBuffer 消费异常** | 事件消费失败场景 | 模拟 RingBuffer 溢出、消费延迟等场景 |
| **大规模探针并发** | 多探针（3+）同时运行 | 扩展 `dual_probe_test` 到更多探针组合 |
| **配置热重载边界** | 运行时参数更新边界情况 | 测试空配置、超大值、并发更新等场景 |
| **MCP STDIO 实际 JSON-RPC 通信** | `mcp_stdio_e2e_test.go` 仅验证结构 | 添加子进程级测试，发送真实的 JSON-RPC 消息 |

#### 低优先级盲区

| 盲区 | 影响 | 建议补充测试 |
|------|------|-------------|
| **日志系统** | 日志输出格式和轮转 | 验证日志级别、字段完整性 |
| **审计系统** | 审计事件记录 | 目前使用 NoopLogger，如需启用需补充测试 |
| **性能基准** | 高并发下的性能表现 | 添加 Benchmark 测试 |
| **资源泄漏** | 长时间运行的资源管理 | 长时间运行测试，验证 goroutine 和 fd 泄漏 |

---

## 测试执行指南

### 单元测试（无需 root）

```bash
# 运行所有单元测试
go test ./internal/...

# 运行特定包测试
go test ./internal/probes -v
go test ./internal/logx -v
go test ./internal/server -v
```

### 探针集成测试

```bash
# 运行无需 root 的探针测试（注册和元数据相关）
go test -v ./test/probes -run "Test(NFS|SysCall).*(Registration|MetadataIntegrity)$"

# 运行所有探针集成测试（需要 root）
sudo -E go test -count=1 ./test/probes -v

# 运行指定探针测试
sudo -E go test -count=1 ./test/probes -run TestNFSFileReadProbe -v
sudo -E go test -count=1 ./test/probes -run TestSysCallTraceProbe -v
sudo -E go test -count=1 ./test/probes -run TestNFSGetattrProbe -v
sudo -E go test -count=1 ./test/probes -run TestNFSSetattrProbe -v

# 运行双探针冲突测试
sudo -E go test -count=1 ./test/probes -run TestDualProbe -v
```

### E2E 测试（无需 root）

```bash
# 运行所有 E2E 测试
go test -v ./test/integration/...

# 运行 HTTP E2E 测试
go test -v ./test/integration -run TestMCPHTTP
go test -v ./test/integration -run TestMCPProbeLifecycle
go test -v ./test/integration -run TestMCPEndToEndWorkflow

# 运行 STDIO E2E 测试
go test -v ./test/integration -run TestMCPStdio

# 带竞态检测运行
go test -race -v ./test/integration/...
```

### 全部测试

```bash
# 运行所有非 root 测试（自动跳过需要 root 的测试）
go test ./...

# 运行完整测试套件（包括探针测试，需要 root）
sudo -E go test -count=1 ./... -v

# 竞态检测
go test -race ./...

# 清理测试缓存
make clean-testcache
```

---

## 注意事项

1. **权限要求**: eBPF 探针集成测试需要 root 权限加载 eBPF 程序
2. **环境依赖**: NFS 相关测试需要 NFS 挂载点才能收集到实际事件；`TestNFSProbeWithFIOAndFilterValidation` 还需要 `fio` 工具
3. **测试缓存**: 使用 `sudo` 运行测试时添加 `-count=1` 避免 Go 测试缓存导致重复结果
4. **构建约束**: 所有 `test/probes/` 下的测试文件带有 `//go:build linux` 约束，在 non-Linux 平台上会自动跳过
5. **数据库权限**: 以 root 运行测试时，DuckDB 文件所有权会自动调整为原始用户
