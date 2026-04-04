# eBPF-MCP 启动指南

本文档介绍环境变量配置、MCP 客户端配置以及完整的启动流程。

## 目录

- [环境变量](#环境变量)
- [MCP 客户端配置](#mcp-客户端配置)
- [启动命令](#启动命令)
- [MCP 工具使用](#mcp-工具使用)
- [故障排查](#故障排查)

---

## 环境变量

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `MCP_AUTH_TOKEN` | HTTP 传输认证令牌 | "" |
| `EBPF_MCP_DUCKDB_PATH` | DuckDB 数据库路径 | `database/ebpf-mcp.duckdb` |
| `MCP_LOG_SCENARIO` | 日志场景名称 | 自动生成 |

### 使用环境变量

```bash
# 导出环境变量
export MCP_AUTH_TOKEN="my-token"
export EBPF_MCP_DUCKDB_PATH="/custom/path/db.duckdb"
export MCP_LOG_SCENARIO="production"

# 使用 sudo -E 保留环境变量启动
sudo -E ./exe/ebpf-mcp
```

验证环境变量传递：
```bash
sudo -E env | grep MCP
```

---

## MCP 客户端配置

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

## 相关文档

- [项目概况](../CLAUDE.md) - 快速开始和基本命令
- [设计文档](DESIGN.md) - 系统架构设计
- [测试平台](testbench.md) - 详细测试矩阵和执行指南
- [探针管理](probes.md) - 探针扩展和管理方法
