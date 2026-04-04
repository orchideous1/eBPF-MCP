# eBPF-MCP 启动指南

本文档介绍如何编译、配置和启动 eBPF-MCP 服务器，以及 AI 智能体如何通过 MCP 协议与 eBPF 探针交互。

## 目录

- [编译项目](#编译项目)
- [配置 MCP 服务器](#配置-mcp-服务器)
- [启动命令](#启动命令)
- [环境变量](#环境变量)
- [MCP 工具使用](#mcp-工具使用)
- [端到端测试](#端到端测试)

---

## 编译项目

### 前置要求

- Go 1.24.0+
- Linux 内核 5.8+（支持 eBPF）
- root 权限（eBPF 加载需要）
- bpftool（用于生成 eBPF 绑定代码）

### 编译命令

```bash
# 编译项目到 exe/ebpf-mcp
make build

# 或者直接使用 go build
go build -o exe/ebpf-mcp .
```

### 生成 eBPF 绑定代码（首次编译或修改探针后需要）

```bash
# 为所有探针生成 eBPF 代码
make generate

# 为指定探针生成代码
make generate endpoint=nfs_file_read
```

---

## 配置 MCP 服务器

### 1. STDIO 模式（推荐，用于本地 MCP 客户端）

STDIO 模式适用于 Claude Desktop、Cursor 等本地 MCP 客户端。

编辑项目根目录的 `mcp.json`：

```json
{
  "mcpServers": {
    "ebpf-mcp": {
      "command": "sudo",
      "args": ["-E", "./exe/ebpf-mcp"],
      "env": {
        "MCP_AUTH_TOKEN": "your-secret-token-here",
        "EBPF_MCP_DUCKDB_PATH": "database/ebpf-mcp.duckdb"
      }
    }
  }
}
```

配置说明：
- `command`: 必须使用 `sudo`，因为 eBPF 程序加载需要 root 权限
- `-E`: 保留当前用户的环境变量
- `./exe/ebpf-mcp`: 编译后的可执行文件路径

### 2. Claude Desktop 配置

将 `mcp.json` 的内容合并到 Claude Desktop 的配置文件中：

**Linux**: `~/.config/claude/config.json`
**macOS**: `~/Library/Application Support/Claude/config.json`

```json
{
  "mcpServers": {
    "ebpf-mcp": {
      "command": "sudo",
      "args": ["-E", "/path/to/ebpf-mcp/exe/ebpf-mcp"],
      "env": {
        "MCP_AUTH_TOKEN": "your-secret-token-here",
        "EBPF_MCP_DUCKDB_PATH": "/path/to/ebpf-mcp/database/ebpf-mcp.duckdb"
      }
    }
  }
}
```

### 3. HTTP 模式（用于远程访问）

HTTP 模式允许通过网络远程访问 MCP 服务器。

编辑 `.env` 文件配置参数：

```bash
# MCP 服务器认证令牌（HTTP模式需要）
MCP_AUTH_TOKEN=your-secret-token-here

# DuckDB 数据库路径
EBPF_MCP_DUCKDB_PATH=database/ebpf-mcp.duckdb
```

---

## 启动命令

### STDIO 模式（默认）

```bash
# 使用 make 命令（自动编译并运行）
make run

# 或者手动运行
sudo -E ./exe/ebpf-mcp

# 调试模式
sudo -E ./exe/ebpf-mcp -debug
```

### HTTP 模式

```bash
# 使用 make 命令（自动编译并以 HTTP 模式运行）
make run-http

# 或者手动运行（指定端口和令牌）
sudo -E ./exe/ebpf-mcp -transport http -port 8080 -token "your-secret-token"

# 使用 .env 中的令牌
sudo -E ./exe/ebpf-mcp -transport http -port 8080
```

### 启动参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-transport` | 传输模式：`stdio` 或 `http` | `stdio` |
| `-port` | HTTP 模式端口 | `8080` |
| `-token` | HTTP 模式认证令牌 | 从环境变量读取 |
| `-debug` | 启用调试日志 | `false` |

---

## 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `MCP_AUTH_TOKEN` | HTTP 传输认证令牌 | "" |
| `EBPF_MCP_DUCKDB_PATH` | DuckDB 数据库路径 | `database/ebpf-mcp.duckdb` |
| `MCP_LOG_SCENARIO` | 日志场景名称 | 自动生成 |

使用 `-E` 参数保留环境变量：

```bash
# 导出环境变量
export MCP_AUTH_TOKEN="my-token"
export EBPF_MCP_DUCKDB_PATH="/custom/path/db.duckdb"

# 使用 sudo -E 保留环境变量启动
sudo -E ./exe/ebpf-mcp
```

---

## MCP 工具使用

eBPF-MCP 服务器暴露 3 个 MCP 工具，AI 智能体可以通过这些工具与 eBPF 探针交互。

### 工具列表

1. **probe_resource_info** - 获取探针资源信息
2. **system_observe_control** - 控制系统观测探针生命周期
3. **probe_customize** - 自定义探针运行时参数

### 1. probe_resource_info - 获取探针信息

列出所有可用的 eBPF 探针及其元数据。

**参数**：
- `probeName` (可选): 指定探针名称，不指定则返回所有探针

**示例**：

```json
{
  "probeName": "nfs_file_read"
}
```

**返回值示例**：

```json
{
  "probes": [
    {
      "type": "nfs_file_read",
      "title": "读文件",
      "layer": "nfs-client",
      "level": "L2",
      "scene": "度量NFS-Client侧的文件单次读请求的延迟与大小",
      "params": [
        {
          "name": "filter_pid",
          "type": "u32",
          "description": "目标进程ID",
          "optional": true
        }
      ],
      "outputs": {
        "fields": [
          {"name": "pid", "type": "u32", "description": "进程ID"},
          {"name": "lat", "type": "u64", "description": "延迟（纳秒）"},
          {"name": "size", "type": "u64", "description": "数据大小（字节）"}
        ]
      },
      "state": "unloaded"
    }
  ]
}
```

### 2. system_observe_control - 控制探针生命周期

加载、卸载或查询探针状态。

**参数**：
- `probeName`: 探针名称
- `operation`: 操作类型 - `load` / `unload` / `status`

**加载探针示例**：

```json
{
  "probeName": "nfs_file_read",
  "operation": "load"
}
```

**卸载探针示例**：

```json
{
  "probeName": "nfs_file_read",
  "operation": "unload"
}
```

**查询状态示例**：

```json
{
  "probeName": "nfs_file_read",
  "operation": "status"
}
```

**返回值**：

```json
{
  "success": true,
  "state": "loaded",
  "message": "Probe loaded successfully"
}
```

### 3. probe_customize - 配置探针参数

更新已加载探针的运行时参数。

**参数**：
- `name`: 探针名称
- `params`: 参数对象
- `dryRun` (可选): 是否为 dry run 模式

**示例**：

```json
{
  "name": "nfs_file_read",
  "params": {
    "filter_pid": 1234,
    "filter_comm": "nginx"
  },
  "dryRun": false
}
```

**返回值**：

```json
{
  "success": true,
  "message": "Probe parameters updated"
}
```

---

## 完整使用流程示例

### 场景：观测 NFS 文件读取性能

1. **AI 智能体查询可用探针**：

```json
// 调用 probe_resource_info
{
  "probeName": "nfs_file_read"
}
```

2. **AI 智能体加载探针**：

```json
// 调用 system_observe_control
{
  "probeName": "nfs_file_read",
  "operation": "load"
}
```

3. **AI 智能体配置过滤参数**（可选）：

```json
// 调用 probe_customize
{
  "name": "nfs_file_read",
  "params": {
    "filter_pid": 1234
  }
}
```

4. **探针开始采集数据**到 DuckDB

5. **AI 智能体查询探针状态**：

```json
// 调用 system_observe_control
{
  "probeName": "nfs_file_read",
  "operation": "status"
}
```

6. **AI 智能体卸载探针**：

```json
// 调用 system_observe_control
{
  "probeName": "nfs_file_read",
  "operation": "unload"
}
```

---

## 故障排查

### 权限问题

如果启动时遇到权限错误，确保使用 `sudo` 运行：

```bash
# 错误：无法加载 eBPF 程序
# 正确：使用 sudo
sudo -E ./exe/ebpf-mcp
```

### 环境变量未传递

使用 `sudo -E` 保留环境变量，或在 `/etc/sudoers` 中配置：

```bash
# 检查环境变量
sudo -E env | grep MCP
```

### 端口被占用

HTTP 模式下如果端口被占用，更换端口：

```bash
sudo -E ./exe/ebpf-mcp -transport http -port 8081
```

---

## 端到端测试

项目提供端到端（E2E）测试套件，用于验证 MCP 服务器的核心功能，无需 root 权限即可运行。

### 测试覆盖范围

E2E 测试位于 `test/integration/` 目录，包含以下测试模块：

| 测试文件 | 测试内容 |
|---------|---------|
| `mcp_http_e2e_test.go` | HTTP 传输模式的完整流程测试 |
| `mcp_stdio_e2e_test.go` | STDIO 传输模式的完整流程测试 |
| `mock_probe.go` | Mock 探针实现，用于无特权环境测试 |
| `helper_test.go` | 测试辅助函数和通用工具 |

### 测试特点

- **无需 root 权限**：使用 Mock 探针替代真实 eBPF 程序，可在普通用户环境运行
- **覆盖双传输模式**：同时验证 HTTP 和 STDIO 两种 MCP 传输协议
- **完整生命周期**：测试探针加载、配置、状态查询、卸载全流程
- **独立运行**：每个测试用例自包含，不依赖外部服务

### 运行 E2E 测试

```bash
# 运行所有 E2E 测试
go test -v ./test/integration/...

# 运行指定测试文件
go test -v ./test/integration/ -run TestHTTPMCPServer
go test -v ./test/integration/ -run TestSTDIOMCPServer

# 带竞态检测运行
go test -race -v ./test/integration/...

# 查看测试覆盖率
go test -cover -v ./test/integration/...
```

### 测试输出示例

```
=== RUN   TestHTTPMCPServer
=== RUN   TestHTTPMCPServer/ProbeLifecycle
    mcp_http_e2e_test.go:123: 探针 nfs_file_read 加载成功
    mcp_http_e2e_test.go:145: 探针状态: loaded
    mcp_http_e2e_test.go:167: 探针卸载成功
--- PASS: TestHTTPMCPServer (2.34s)
=== RUN   TestSTDIOMCPServer
=== RUN   TestSTDIOMCPServer/ProbeLifecycle
    mcp_stdio_e2e_test.go:89: STDIO 服务器启动成功
    mcp_stdio_e2e_test.go:112: 探针查询成功，返回 2 个可用探针
--- PASS: TestSTDIOMCPServer (1.56s)
PASS
ok      github.com/shaojianqing/eBPF-MCP/test/integration       3.91s
```

### 测试前置条件

- Go 1.24.0+
- 已编译项目（`make build` 或 `go build`）
- 无需 root 权限
- 无需 Linux 内核 eBPF 支持（使用 Mock 探针）

### 故障排查

**测试找不到可执行文件**：
```bash
# 确保已编译
make build

# 或手动编译
go build -o exe/ebpf-mcp .
```

**端口冲突（HTTP 测试）**：
- 测试会自动选择可用端口，但如果系统资源紧张可能失败
- 关闭占用 8080-8090 范围端口的其他服务

---

## 相关文档

- [设计文档](DESIGN.md) - 系统架构设计
- [开发路线图](DEVELOP_ROADMAP.md) - 开发计划
- [测试平台](testbench.md) - 测试环境搭建
