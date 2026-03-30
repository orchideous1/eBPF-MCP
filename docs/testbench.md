# 测试基准文档 (Testbench)

本文档汇总了 eBPF-MCP 项目的所有测试项目，按测试类型分类，并说明每个测试的目的。

## 测试概览

| 测试文件 | 类型 | 主要目的 |
|---------|------|---------|
| `internal/probes/controller_test.go` | 单元测试 | 验证 Probe Controller 的生命周期管理 |
| `internal/logx/errors_test.go` | 单元测试 | 验证领域错误映射机制 |
| `internal/server/http_middleware_test.go` | 单元测试 | 验证 HTTP Bearer Token 认证中间件 |
| `internal/server/test_helpers_test.go` | 测试辅助 | 提供测试用的临时 DuckDB 和 Mock Server |
| `test/probes/nfs_file_read_test.go` | 集成测试 | 验证 nfs_file_read 探针完整功能 |
| `test/integration/mcp_observe_load_flow_test.go` | 集成测试 | 验证 MCP 协议下 probe 加载/卸载完整流程 |
| `test/integration/protocol_stdio_smoke_test.go` | 集成测试 | 验证 STDIO 传输层基础功能 |
| `test/integration/protocol_http_test.go` | 集成测试 | 验证 HTTP 传输层协议和认证流程 |
| `test/integration/nfs_probe_duckdb_e2e_test.go` | E2E 测试 | 验证 NFS probe 端到端数据采集和持久化 |

---

## 单元测试 (Unit Tests)

### 1. `internal/probes/controller_test.go`

**测试目标**: Probe Controller 的核心生命周期管理

**测试函数**:
- `TestControllerLifecycle` - 验证完整的 probe 生命周期：加载 → 更新 → 查询状态 → 卸载
- `TestControllerConflicts` - 验证状态冲突处理：重复加载、重复卸载
- `TestControllerNotFound` - 验证未注册 probe 的错误处理

**关键验证点**:
- Probe 状态机转换正确性 (unloaded → loaded → unloaded)
- 并发安全（通过 `stubProbe` 调用计数验证）
- 错误类型正确性 (`ErrProbeAlreadyLoaded`, `ErrProbeNotLoaded`, `ErrProbeNotFound`)

---

### 2. `internal/logx/errors_test.go`

**测试目标**: 领域错误码映射机制

**测试函数**:
- `TestMapDomainError` - 验证各种领域错误到标准错误码的映射

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
- `TestBearerAuthMiddleware` - 验证 Bearer Token 认证逻辑

**测试场景**:
- Token 缺失时返回 401 Unauthorized
- Token 无效时返回 401 Unauthorized
- Token 有效时允许请求通过

---

### 4. `internal/server/test_helpers_test.go`

**测试目标**: 测试辅助工具（非直接测试）

**提供的辅助函数**:
- `openTestDB()` - 创建临时 DuckDB 数据库
- `newTestServer(t)` - 创建带 mock controller 的测试服务器

**用途**: 为其他测试提供基础设施支持

---

## 集成测试 (Integration Tests)

### 5. `test/probes/nfs_file_read_test.go`

**测试目标**: nfs_file_read eBPF 探针的完整功能验证

**测试函数**:
- `TestNFSFileReadProbe_Registration` - 验证探针注册和元数据完整性
- `TestNFSFileReadProbe_ControllerLifecycle` - 验证 Controller 生命周期管理
- `TestNFSFileReadProbe_FilterByPID` - 验证 PID 过滤功能
- `TestNFSFileReadProbe_DataCollection` - 验证数据收集和 DuckDB 持久化
- `TestNFSFileReadProbe_MacroVariables` - 验证宏变量（filter_pid, is_get_name, is_get_size）更新
- `TestNFSFileReadProbe_ConcurrentAccess` - 验证并发访问安全性
- `TestNFSFileReadProbe_ErrorHandling` - 验证错误处理
- `TestNFSFileReadProbe_FullWorkflow` - 完整工作流测试
- `TestNFSFileReadProbe_ListOperations` - 验证列表操作
- `TestNFSFileReadProbe_MetadataIntegrity` - 验证元数据完整性

**前置条件**:
- 需要 root 权限（加载 eBPF 程序需要 `CAP_BPF`）

**关键验证点**:
- 探针正确注册到全局注册表
- Controller 能正确加载/卸载探针
- eBPF 宏变量能运行时更新
- Ring buffer 事件能正确消费并写入 DuckDB
- 并发操作线程安全

---

### 8. `test/integration/protocol_http_test.go`

**测试目标**: MCP 协议下 probe 控制流程的端到端验证

**测试函数**:
- `TestMCPObserveControlLoadFlow` - 完整的 probe 控制流程测试

**测试流程**:
1. 初始化 MCP 会话（initialize → notifications/initialized）
2. 验证无效操作返回错误（restart 操作不被支持）
3. 调用 `system_observe_control` 加载 probe
4. 验证 controller 状态和 probe Start 被调用
5. 调用 `system_observe_control` 查询状态
6. 调用 `system_observe_control` 卸载 probe
7. 验证 controller 状态和 probe Stop 被调用

**关键验证点**:
- MCP 协议握手流程
- HTTP 传输层 + 认证集成
- Controller 与 MCP Server 的集成
- Probe 生命周期回调正确性

---

### 6. `test/integration/protocol_stdio_smoke_test.go`

**测试目标**: STDIO 传输层基础功能验证

**测试函数**:
- `TestStdioServerSmoke` - 验证 STDIO 服务器能正常创建并注册工具

**验证内容**:
- Server 创建成功
- 2 个 MCP 工具正确注册（`probe_customize` 和 `system_observe_control`）

---

### 7. `test/integration/protocol_http_test.go`

**测试目标**: HTTP 传输层和认证集成

**测试函数**:
- `TestHTTPProtocolFlow` - 验证 HTTP 协议流程和认证

**测试场景**:
- Token 缺失时返回 401
- Token 有效时请求成功通过

**验证内容**:
- HTTP handler 创建
- Bearer Token 中间件集成
- MCP 工具调用流程

---

## E2E 测试 (End-to-End Tests)

### 9. `test/integration/nfs_probe_duckdb_e2e_test.go`

**测试目标**: NFS Probe 端到端数据采集和持久化验证

**测试函数**:
- `TestNFSProbeLoadAndDuckDBIngestionE2E` - 完整的 eBPF probe 数据采集流程

**前置条件**:
- 需要 root 权限（加载 eBPF 程序需要 `CAP_BPF`）
- 需要安装 `fio` 工具
- 需要存在 NFS 挂载点

**测试流程**:
1. 查找 NFS 挂载点
2. 创建临时 DuckDB 数据库
3. 初始化 Controller 并加载 `nfs_file_read` probe
4. 使用 fio 执行写工作负载（生成测试文件）
5. 使用 fio 执行读工作负载（触发 probe 事件）
6. 卸载 probe 并关闭数据库
7. 重新打开数据库验证数据持久化
8. 查询 `nfs_file_read` 表验证事件已记录

**关键验证点**:
- eBPF 程序能成功加载和附加
- Ring buffer 事件能正确消费
- 数据能正确写入 DuckDB
- 数据在数据库关闭后仍然持久化

---

## 测试执行指南

### 单元测试
```bash
# 运行所有单元测试
go test ./internal/...

# 运行特定包测试
go test ./internal/probes -v
go test ./internal/logx -v
go test ./internal/server -v
```

### 集成测试（探针）
```bash
# 运行探针集成测试（无需 root）
go test ./test/probes -v -run "TestNFSFileReadProbe_Registration|TestNFSFileReadProbe_ErrorHandling|TestNFSFileReadProbe_MetadataIntegrity"

# 运行探针集成测试（需要 root）
sudo -E go test -count=1 ./test/probes -v

# 运行完整工作流测试
sudo -E go test -count=1 ./test/probes -run TestNFSFileReadProbe_FullWorkflow -v
```

### 集成测试（协议）
```bash
# 运行集成测试（无需 root）
go test ./test/integration -v -run "TestMCPObserveControlLoadFlow|TestStdioServerSmoke|TestHTTPProtocolFlow"
```

### E2E 测试
```bash
# 运行 E2E 测试（需要 root、NFS 挂载和 fio）
sudo -E go test -count=1 ./test/integration -run TestNFSProbeLoadAndDuckDBIngestionE2E -v
```

### 全部测试
```bash
# 运行所有测试（自动跳过需要 root 的测试）
go test ./...

# 竞态检测
go test -race ./...
```

---

## 注意事项

1. **权限要求**: E2E 测试需要 root 权限加载 eBPF 程序
2. **环境依赖**: NFS E2E 测试需要 NFS 挂载点和 fio 工具
3. **测试缓存**: 使用 sudo 运行测试时添加 `-count=1` 避免缓存问题
4. **数据库权限**: 以 root 运行测试时，DuckDB 文件所有权会自动调整为原始用户
