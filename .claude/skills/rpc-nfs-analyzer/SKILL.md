---
name: rpc-nfs-analyzer
description: |
  RPC-NFS 事务分析专家技能。当用户需要分析 NFS 相关的 RPC 事务、追踪 RPC/SVC 层的延迟和失败、关联 rpc_task_latency 与 svc_rqst_latency 数据时必须触发此技能。
  适用于：NFS 性能分析、RPC 事务追踪、SVC 请求延迟拆解、失败事务根因定位、高延迟事务排查。
  无论用户提到 "RPC"、"SVC"、"NFS 事务"、"xid"、"rpc_task_latency"、"svc_rqst_latency"、"分析 NFS 延迟"、"追踪失败 RPC"，都应使用此技能。
---

# RPC-NFS 事务分析技能

本技能通过关联 `rpc_task_latency` 和 `svc_rqst_latency` 两层探针的数据，对 NFS 相关的 RPC 事务进行端到端追踪和深度分析。

## 核心分析能力

| 能力 | 说明 |
|------|------|
| **事务关联** | 通过 `xid`（RPC 事务 ID）将 RPC 层和 SVC 层的数据精确对齐 |
| **失败追踪** | 监控 `rpc_task_latency.status`，识别失败的 RPC 事务并关联 SVC 层表现 |
| **延迟拆解** | 对比 RPC 任务总延迟与 SVC 请求处理延迟，定位瓶颈所在层级 |
| **高延迟追踪** | 提取并分析两端延迟都很高的事务，辅助根因排查 |

## 数据库表结构

### `rpc_task_latency` 表（RPC 层）

| 字段名 | 类型 | 说明 |
|--------|------|------|
| pid | UBIGINT | 执行 RPC 任务的进程 ID |
| xid | UINTEGER | RPC 事务 ID，关联键 |
| proc_name | VARCHAR | RPC 过程名称（如 READ、WRITE、GETATTR） |
| latency | UBIGINT | RPC 任务执行延迟（纳秒） |
| start_timestamp | UBIGINT | RPC 任务开始时间戳（纳秒，自系统启动） |
| status | INTEGER | 任务完成状态码（0 表示成功，负值表示错误） |

### `svc_rqst_latency` 表（SVC 层）

| 字段名 | 类型 | 说明 |
|--------|------|------|
| xid | UINTEGER | RPC 事务 ID，关联键 |
| latency | UBIGINT | SVC 请求处理延迟（纳秒），从 svc_process 到 svc_send 的时间 |
| start_timestamp | UBIGINT | SVC 请求开始时间戳（纳秒，自系统启动） |

---

## 工作流程

### 步骤1: 加载探针

**加载 `rpc_task_latency` 探针：**

```json
{
  "tool": "system_observe_control",
  "arguments": {
    "probeName": "rpc_task_latency",
    "operation": "load"
  }
}
```

**加载 `svc_rqst_latency` 探针：**

```json
{
  "tool": "system_observe_control",
  "arguments": {
    "probeName": "svc_rqst_latency",
    "operation": "load"
  }
}
```

**可选：按进程过滤**

如需聚焦特定 NFS 客户端进程，可在加载后对 `rpc_task_latency` 使用 `probe_customize`：

```json
{
  "tool": "probe_customize",
  "arguments": {
    "name": "rpc_task_latency",
    "params": {
      "filter_comm": "nfs"
    }
  }
}
```

---

### 步骤2: 数据采集

**时间建议**

| 分析类型 | 建议采集时间 | 说明 |
|----------|-------------|------|
| 快速排查 | 30-60 秒 | 获取足够样本进行初步关联 |
| 深度分析 | 2-5 分钟 | 捕获稳定的事务模式和长尾延迟 |
| 失败追踪 | 直到问题复现 | 需要捕获失败事件发生的完整上下文 |

**检查项**
- [ ] 两个探针均已成功加载（状态为 `loaded`）
- [ ] 目标 NFS 操作在采集期间被执行
- [ ] 数据库文件大小在增长

---

### 步骤3: 停止探针并获取最新数据库

```json
{
  "tool": "system_observe_control",
  "arguments": {
    "probeName": "rpc_task_latency",
    "operation": "unload"
  }
}
```

```json
{
  "tool": "system_observe_control",
  "arguments": {
    "probeName": "svc_rqst_latency",
    "operation": "unload"
  }
}
```

获取最新数据库文件路径：

```bash
# 默认存储在 /tmp/database（可通过环境变量调整）
export LATEST_DB=$(ls -t /tmp/database/ebpf-mcp-*.duckdb 2>/dev/null | head -1)

# 如果 /tmp/database 下没有，尝试当前目录的 database/
if [ -z "$LATEST_DB" ]; then
    export LATEST_DB=$(ls -t database/ebpf-mcp-*.duckdb 2>/dev/null | head -1)
fi

echo "Using database: $LATEST_DB"
```

验证数据：

```bash
duckdb $LATEST_DB -c "SELECT COUNT(*) FROM rpc_task_latency;"
duckdb $LATEST_DB -c "SELECT COUNT(*) FROM svc_rqst_latency;"
```

---

### 步骤4: 执行 SQL 分析脚本

SQL 脚本位于 `.claude/skills/rpc-nfs-analyzer/scripts/`：

| 脚本 | 用途 | 适用场景 |
|------|------|----------|
| [transaction_summary.sql](./scripts/transaction_summary.sql) | 整体摘要 | **任何分析都建议先执行**，快速了解样本量、成功率、匹配率 |
| [latency_breakdown.sql](./scripts/latency_breakdown.sql) | 延迟拆解 | 性能分析核心脚本，按 `proc_name` 对比两层延迟 |
| [high_latency_transactions.sql](./scripts/high_latency_transactions.sql) | 高延迟事务追踪 | 排查高延迟根因，输出 `latency_pattern` 分类 |
| [failed_transactions.sql](./scripts/failed_transactions.sql) | 失败事务追踪 | 失败根因定位，输出 `error_label` 和 `svc_hint` |
| [rpc_svc_correlation.sql](./scripts/rpc_svc_correlation.sql) | 基础关联 | 查看按 `xid` 关联后的完整事务列表，适合下钻具体事务 |

**场景驱动的分析路径速查**

| 用户问题 | 推荐执行顺序 |
|----------|-------------|
| "延迟高，定位瓶颈" | `transaction_summary.sql` → `latency_breakdown.sql` → `high_latency_transactions.sql` |
| "大量 RPC 失败" | `transaction_summary.sql` → `failed_transactions.sql` → `rpc_svc_correlation.sql` |
| "概览 NFS RPC 健康状况" | `transaction_summary.sql` → `latency_breakdown.sql` |
| "排查具体 xid" | `rpc_svc_correlation.sql` → 即席查询 |

**执行示例：**

```bash
# 1. 先看整体摘要（必需）
duckdb $LATEST_DB < .claude/skills/rpc-nfs-analyzer/scripts/transaction_summary.sql

# 2. 性能瓶颈：延迟拆解
duckdb $LATEST_DB < .claude/skills/rpc-nfs-analyzer/scripts/latency_breakdown.sql

# 3. 失败追踪
duckdb $LATEST_DB < .claude/skills/rpc-nfs-analyzer/scripts/failed_transactions.sql

# 4. 高延迟追踪
duckdb $LATEST_DB < .claude/skills/rpc-nfs-analyzer/scripts/high_latency_transactions.sql
```

---

### 步骤5: 生成分析报告

报告应包含以下章节：

1. **执行摘要** - 关键发现（3-5 条要点）
2. **数据采集概况** - 样本量、时间范围、探针覆盖
3. **事务成功率统计** - 成功/失败事务数量及占比
4. **延迟拆解分析** - RPC 层 vs SVC 层的延迟分布对比
5. **高延迟事务追踪** - Top N 高延迟事务详情及根因推断
6. **失败事务追踪** - 失败事务列表、状态码分布、关联的 SVC 层延迟
7. **优化建议** - 基于数据的具体建议（如是否需要优化 SVC 处理、网络延迟排查等）

**快速结论示例模板（可直接填充）**

```
【快速结论】
- 采集周期：XX 秒 | RPC 事务总数：XX | xid 匹配率：XX%
- 失败率：XX% | 主要错误：XX（如 ETIMEDOUT / ECONNRESET）
- 核心瓶颈：
  □ RPC 独占开销高（网络/客户端队列问题）
  □ SVC 处理延迟高（服务端/存储问题）
  □ 两者均高（服务端过载）
- 下一步行动：XX
```

---

## 关键分析指标解读

### `xid` 关联原理

- `xid` 是贯穿 RPC 层和 SVC 层的唯一事务标识符。
- 理想情况下，每个 `xid` 在两张表中都应有记录。
- 如果 `rpc_task_latency` 中有记录但 `svc_rqst_latency` 中缺失，可能说明 RPC 事务在到达 SVC 层前失败或被丢弃。
- **注意 `xid = 0` 的记录**：当 RPC 任务在某些内核路径中 `tk_rqstp` 为 NULL 时，`rpc_task_latency` 探针会记录 `xid = 0`，这类记录无法与 SVC 层关联。分析时建议在 SQL 中过滤 `xid != 0`。

### 延迟对比

| 场景 | RPC latency ≈ SVC latency | 推断 |
|------|---------------------------|------|
| RPC 延迟明显 > SVC 延迟 | 否 | 瓶颈在 RPC 层之外（网络、客户端队列、重传） |
| RPC 延迟 ≈ SVC 延迟 | 是 | 瓶颈主要在 SVC 处理或下层存储 |
| SVC 延迟高但 RPC 正常 | 否 | 可能是服务端异步处理或采样偏差 |

### 状态码解读

- `status = 0`：RPC 任务成功完成
- `status < 0`：RPC 任务失败，常见负值需结合内核源码解读
  - `-5` (`-EIO`)：I/O 错误
  - `-11` (`-EAGAIN`)：资源暂时不可用
  - `-103` (`-ECONNABORTED`)：连接被中止
  - `-104` (`-ECONNRESET`)：连接被重置
  - `-110` (`-ETIMEDOUT`)：连接超时
  - `-111` (`-ECONNREFUSED`)：连接被拒绝

### 现实能力与边界

- `svc_rqst_latency` 当前不采集 `status` 字段，无法直接判断 SVC 层是否返回错误；失败分析主要通过 RPC 层的 `status` 结合 SVC 层是否存在记录来推断。
- `nfs-client` 层探针（如 `nfs_file_read`）当前未采集 `xid`，无法与 RPC 层做精确的 SQL 级事务关联；如需关联，只能通过 `pid` + 时间窗口做近似匹配。
- `rpc_task_latency` 与 `svc_rqst_latency` 的时间戳均来自 `bpf_ktime_get_ns()`。若客户端与服务端是**不同物理机**，时间戳不能直接相减，只能分别比较延迟值。

---

## 常用即席查询模板

```sql
-- 查看某个 xid 的完整链路（排除 xid=0 的无效记录）
SELECT
    r.xid,
    r.proc_name,
    r.pid,
    r.latency / 1e6 AS rpc_ms,
    s.latency / 1e6 AS svc_ms,
    (r.latency - COALESCE(s.latency, 0)) / 1e6 AS rpc_only_ms,
    r.status
FROM rpc_task_latency r
LEFT JOIN svc_rqst_latency s ON r.xid = s.xid
WHERE r.xid = <目标xid> AND r.xid != 0;

-- 按 proc_name 统计失败率（排除 xid=0）
SELECT
    proc_name,
    COUNT(*) AS total,
    COUNT_IF(status != 0) AS failed,
    ROUND(COUNT_IF(status != 0) * 100.0 / COUNT(*), 2) AS fail_rate_pct
FROM rpc_task_latency
WHERE xid != 0
GROUP BY proc_name
ORDER BY fail_rate_pct DESC;

-- RPC-SVC 时间差分布（识别网络/队列延迟）
SELECT
    quantile_cont(0.5)((r.latency - s.latency) / 1e6) AS p50_diff_ms,
    quantile_cont(0.95)((r.latency - s.latency) / 1e6) AS p95_diff_ms,
    quantile_cont(0.99)((r.latency - s.latency) / 1e6) AS p99_diff_ms
FROM rpc_task_latency r
JOIN svc_rqst_latency s ON r.xid = s.xid
WHERE r.xid != 0;
```
