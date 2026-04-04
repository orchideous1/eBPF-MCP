---
name: syscall-analyzer
description: |
  系统调用分析专家技能。当用户需要分析进程的系统调用行为、性能瓶颈或系统调用模式时触发此技能。
  适用于：系统调用追踪、性能分析、延迟分析、系统调用频率统计、异常检测、进程行为分析。
  无论用户提到"系统调用"、"syscall"、"trace系统调用"、"分析进程性能"、"查看进程在做什么"，都应使用此技能。
  支持通过 eBPF-MCP 探针采集数据，并进行可视化分析。
---

# 系统调用分析技能

本技能通过 eBPF-MCP 系统调用探针采集数据，并对 DuckDB 数据库中的系统调用记录进行深度分析和可视化展示。

## 数据库表结构

系统调用数据存储在 `sys_call_trace` 表中，字段定义如下：

| 字段名 | 类型 | 说明 |
|--------|------|------|
| pid | UBIGINT | 进程ID (TGID << 32 \| PID) |
| syscall_id | UINTEGER | 系统调用号 |
| ret | BIGINT | 系统调用返回值 |
| duration | UBIGINT | 调用延迟（纳秒）|
| enter_time_stamp | UBIGINT | 进入时间戳（纳秒，自系统启动）|
| comm | VARCHAR | 进程名称（最多16字符）|

## 前置准备：确认 NFS 挂载点

在使用 NFS 相关探针前，建议先确认系统中存在的 NFS 挂载点。

### 查看 NFS 挂载目录

```bash
# 查看系统中所有 NFS 挂载点
mount | grep nfs

# 仅显示挂载点路径
mount | grep nfs | awk '{print $3}'

# 显示 NFS 服务器地址和挂载点
mount | grep nfs | awk '{print $1, $3}'

# 过滤特定 NFS 服务器的挂载
mount | grep nfs | grep "server-ip"
```

### 常用过滤组合

| 命令 | 用途 |
|------|------|
| `mount \| grep nfs` | 查看所有 NFS 挂载 |
| `mount \| grep nfs \| grep -v nfsd` | 排除 nfsd 守护进程 |
| `df -h \| grep nfs` | 查看 NFS 磁盘使用情况 |
| `cat /proc/mounts \| grep nfs` | 从 proc 文件系统读取 |

---

## 工作流程

### 1. 启动系统调用探针

首先，获取探针信息确认可用性：

```json
{
  "tool": "probe_resource_info",
  "arguments": {
    "probeName": "sys_call_trace"
  }
}
```

然后加载探针：

```json
{
  "tool": "system_observe_control",
  "arguments": {
    "probeName": "sys_call_trace",
    "operation": "load"
  }
}
```

如需过滤特定进程或系统调用，在加载后使用 probe_customize：

```json
{
  "tool": "probe_customize",
  "arguments": {
    "name": "sys_call_trace",
    "params": {
      "filter_pid": 1234,
      "filter_syscall_id": 0
    }
  }
}
```

### 2. 数据采集

探针加载后，让进程运行一段时间以采集足够的数据。建议采集时间：
- 简单分析：10-30秒
- 性能分析：1-5分钟
- 异常排查：直到问题复现

### 3. 停止探针并确保数据落盘

```json
{
  "tool": "system_observe_control",
  "arguments": {
    "probeName": "sys_call_trace",
    "operation": "unload"
  }
}
```

### 4. 数据库分析

使用 DuckDB SQL 查询分析数据。SQL 脚本位于 `.claude/skills/syscall-analyzer/scripts/` 目录，可按需读取执行。

#### 可用分析脚本

| 脚本 | 用途 | 说明 |
|------|------|------|
| [syscall_frequency.sql](./scripts/syscall_frequency.sql) | 频率统计 | Top 20 系统调用及其占比 |
| [process_stats.sql](./scripts/process_stats.sql) | 进程统计 | 各进程调用数、延迟统计 |
| [high_latency_calls.sql](./scripts/high_latency_calls.sql) | 高延迟分析 | 超过10ms的慢调用 |
| [latency_distribution.sql](./scripts/latency_distribution.sql) | 延迟分布 | P50/P95/P99 延迟统计 |
| [time_series.sql](./scripts/time_series.sql) | 时间序列 | 每秒调用数趋势 |
| [error_analysis.sql](./scripts/error_analysis.sql) | 错误分析 | 负返回值错误统计 |
| [process_syscall_matrix.sql](./scripts/process_syscall_matrix.sql) | 热力矩阵 | 进程-系统调用交叉统计 |
| [top_slow_processes.sql](./scripts/top_slow_processes.sql) | 慢进程 | P99延迟最高的进程 |

#### 使用示例

```bash
# 执行 SQL 脚本分析
duckdb database/ebpf-mcp.duckdb < .claude/skills/syscall-analyzer/scripts/syscall_frequency.sql

# 或使用 Python
python -c "
import duckdb
conn = duckdb.connect('database/ebpf-mcp.duckdb')
with open('.claude/skills/syscall-analyzer/scripts/syscall_frequency.sql') as f:
    result = conn.execute(f.read()).fetchdf()
    print(result)
"
```

#### 常用即席查询模板

快速查询模板（无需读取脚本文件）：

```sql
-- 最近的高延迟调用
SELECT syscall_id, comm, duration/1e6 as ms
FROM sys_call_trace
WHERE duration > 10000000
ORDER BY duration DESC LIMIT 20;

-- 进程调用统计
SELECT comm, COUNT(*) as calls, AVG(duration)/1e6 as avg_ms
FROM sys_call_trace
GROUP BY comm ORDER BY calls DESC;

-- 每秒调用趋势
SELECT (enter_time_stamp/1e9)::INT as sec, COUNT(*)
FROM sys_call_trace
GROUP BY sec ORDER BY sec;
```

### 5. 可视化分析

可视化脚本 [visualize.py](./scripts/visualize.py) 提供全自动的数据分析和图表生成能力。

#### 脚本功能

| 功能 | 输出文件 | 说明 |
|------|----------|------|
| 频率分析 | `syscall_frequency.png` | Top 20 系统调用频率柱状图 |
| 延迟分布 | `syscall_latency_distribution.png` | 延迟直方图（线性与对数刻度） |
| 热力图 | `syscall_heatmap.png` | 进程 vs 系统调用热力矩阵 |
| 时间线 | `syscall_timeline.png` | 每秒调用数与平均延迟趋势 |
| 延迟箱线 | `syscall_latency_by_type.png` | 各类型系统调用延迟分布 |
| 慢调用散点 | `top_slow_calls.png` | Top 100 最慢调用时间分布 |
| 数据摘要 | `syscall_summary.json` | JSON 格式统计摘要 |

#### 使用方法

```bash
# 基础用法 - 分析全部数据
python .claude/skills/syscall-analyzer/scripts/visualize.py \
    --db-path database/ebpf-mcp.duckdb \
    --output-dir ./syscall_analysis

# 分析特定进程
python .claude/skills/syscall-analyzer/scripts/visualize.py \
    --db-path database/ebpf-mcp.duckdb \
    --output-dir ./syscall_analysis \
    --pid 1234

# 分析最近5分钟的数据
python .claude/skills/syscall-analyzer/scripts/visualize.py \
    --db-path database/ebpf-mcp.duckdb \
    --output-dir ./syscall_analysis \
    --time-range 5m
```

#### 依赖安装

```bash
pip install duckdb pandas matplotlib seaborn numpy
```

#### 脚本参数说明

- `--db-path`: DuckDB 数据库文件路径（必需）
- `--output-dir`: 输出目录路径（必需）
- `--pid`: 仅分析指定进程ID（可选）
- `--time-range`: 时间范围，支持 `30s`, `5m`, `1h` 格式（可选）

## 分析维度

### 性能分析
- **延迟分布**：识别长尾延迟、P99延迟
- **热点系统调用**：找出调用频率最高的系统调用
- **进程视角**：哪些进程产生最多系统调用
- **时间模式**：系统调用随时间的分布

### 异常检测
- **高延迟调用**：超过阈值的慢调用
- **错误返回**：负返回值（错误码）分析
- **突发流量**：短时间内大量系统调用
- **异常进程**：系统调用模式异常的进程

### 行为分析
- **系统调用模式**：进程的系统调用指纹
- **依赖关系**：通过系统调用推断的IO/网络模式
- **资源使用**：读/写/打开等操作频率

## 系统调用号对照

系统调用号定义参见 [resource/unistd.h](./resource/unistd.h)。该文件包含完整的 Linux x86_64 系统调用号定义。

### 常用系统调用速查

| 编号 | 名称 | 功能 |
|------|------|------|
| 63 | read | 从文件描述符读取 |
| 64 | write | 向文件描述符写入 |
| 56 | openat | 相对于目录打开文件 |
| 57 | close | 关闭文件描述符 |
| 222 | mmap | 内存映射 |
| 226 | mprotect | 设置内存保护 |
| 29 | ioctl | 设备控制 |
| 172 | getpid | 获取进程ID |
| 221 | execve | 执行程序 |
| 129 | kill | 发送信号 |

> 注：可视化脚本会自动将 syscall_id 映射为可读名称。

## 输出报告结构

分析报告应包含以下章节：

1. **执行摘要** - 关键发现和结论
2. **采集概况** - 数据量、时间范围、进程覆盖
3. **频率分析** - 热点系统调用、分布统计
4. **延迟分析** - 延迟分布、长尾分析、瓶颈识别
5. **进程分析** - 各进程系统调用行为
6. **异常发现** - 错误返回、高延迟、异常模式
7. **优化建议** - 基于分析的具体优化建议
8. **附录** - 可视化图表、原始数据查询

## 注意事项

1. **权限要求**：加载 eBPF 探针需要 root 权限
2. **性能开销**：高频系统调用场景下，全量追踪会带来较大开销
3. **过滤建议**：生产环境建议通过 filter_pid 或 filter_syscall_id 进行过滤
4. **数据量控制**：长时间采集可能产生大量数据，注意磁盘空间
5. **时间戳解释**：enter_time_stamp 是自系统启动以来的纳秒数
