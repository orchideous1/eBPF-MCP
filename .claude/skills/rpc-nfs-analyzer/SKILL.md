---
name: rpc-nfs-analyzer
description: |
  RPC-NFS 事务分析专家技能。当用户需要分析 NFS 相关的 RPC 事务、追踪 RPC/SVC 层的延迟和失败、关联 rpc_task_latency 与 svc_rqst_latency 数据时必须触发此技能。
  适用于：NFS 性能分析、RPC 事务追踪、SVC 请求延迟拆解、失败事务根因定位、高延迟事务排查。
  无论用户提到 "RPC"、"SVC"、"NFS 事务"、"xid"、"rpc_task_latency"、"svc_rqst_latency"、"分析 NFS 延迟"、"追踪失败 RPC"，都应使用此技能。
---

# RPC-NFS 事务分析技能

## 与 nfs-sre-expert 的关系

- **被委托时**：`nfs-sre-expert` 已制定跨层观测计划，你负责 **RPC 层与 SVC 层**的关联分析、延迟拆解和失败定位。
- **独立调用时**：你需自行决定采集时长、加载/卸载探针、执行分析并输出报告。

---

## 核心分析能力

| 能力 | 说明 |
|------|------|
| **事务关联** | 通过 `xid`（RPC 事务 ID）将 RPC 层和 SVC 层的数据对齐 |
| **失败追踪** | 监控 `rpc_task_latency.status`，识别失败 RPC 事务并推断 SVC 层表现 |
| **延迟拆解** | 对比 RPC 任务总延迟与 SVC 请求处理延迟，定位瓶颈所在层级 |
| **高延迟追踪** | 提取并分析两端延迟都很高的事务，辅助根因排查 |

---

## 独立观测闭环

### 1. 加载探针
加载 `rpc_task_latency` 和 `svc_rqst_latency` 两个探针。如需聚焦特定进程，加载后使用 `probe_customize` 设置 `filter_comm` 或 `filter_pid`。

### 2. 采集与卸载
| 分析类型 | 建议采集时间 |
|----------|-------------|
| 快速排查 | 30-60 秒 |
| 深度分析 | 2-5 分钟 |
| 失败追踪 | 直到问题复现 |

采集完成后**必须卸载所有探针**，获取最新 DuckDB 文件并验证两张表均有数据。

### 3. 分析路径

SQL 脚本位于 `.claude/skills/rpc-nfs-analyzer/scripts/`：

| 脚本 | 用途 | 推荐场景 |
|------|------|----------|
| `transaction_summary.sql` | 整体摘要 | **任何分析都建议先执行** |
| `latency_breakdown.sql` | 延迟拆解 | 性能分析核心脚本 |
| `high_latency_transactions.sql` | 高延迟事务追踪 | 排查长尾根因 |
| `failed_transactions.sql` | 失败事务追踪 | 失败根因定位 |
| `rpc_svc_correlation.sql` | 基础关联 | 查看按 `xid` 关联后的完整事务列表 |

**场景驱动的执行顺序**：
- **延迟高，定位瓶颈**：`transaction_summary.sql` → `latency_breakdown.sql` → `high_latency_transactions.sql`
- **大量 RPC 失败**：`transaction_summary.sql` → `failed_transactions.sql` → `rpc_svc_correlation.sql`
- **排查具体 xid**：`rpc_svc_correlation.sql` → 即席查询

---

## 关键领域语义解读

### `xid` 关联原理

- `xid` 是贯穿 RPC 层和 SVC 层的唯一事务标识符。
- 理想情况下，每个 `xid` 在两张表中都应有记录。
- 如果 `rpc_task_latency` 中有记录但 `svc_rqst_latency` 中缺失，可能说明 RPC 事务在到达 SVC 层前失败或被丢弃。
- **注意 `xid = 0` 的记录**：当 `tk_rqstp` 为 NULL 时，探针会记录 `xid = 0`，这类记录无法与 SVC 层关联。分析时建议过滤 `xid != 0`。

### 延迟对比的语义

| 场景 | RPC latency vs SVC latency | 推断 |
|------|---------------------------|------|
| RPC 延迟明显 > SVC 延迟 | 否 | 瓶颈在 RPC 层之外（网络、客户端队列、重传） |
| RPC 延迟 ≈ SVC 延迟 | 是 | 瓶颈主要在 SVC 处理或下层存储 |
| SVC 延迟高但 RPC 正常 | 否 | 可能是服务端异步处理或采样偏差 |

### 状态码解读

- `status = 0`：RPC 任务成功完成
- `status < 0`：RPC 任务失败，常见负值：
  - `-5` (`-EIO`)：I/O 错误
  - `-11` (`-EAGAIN`)：资源暂时不可用
  - `-103` (`-ECONNABORTED`)：连接被中止
  - `-104` (`-ECONNRESET`)：连接被重置
  - `-110` (`-ETIMEDOUT`)：连接超时
  - `-111` (`-ECONNREFUSED`)：连接被拒绝

### 现实边界

- `svc_rqst_latency` 当前不采集 `status` 字段，失败分析主要通过 RPC 层的 `status` 结合 SVC 层是否存在记录来推断。
- `nfs-client` 层探针当前未采集 `xid`，无法与 RPC 层做精确 SQL 级关联；如需关联，只能通过 `pid` + 时间窗口做近似匹配。
- 若客户端与服务端是**不同物理机**，两张表的时间戳不能直接相减（均来自各自机器的 `bpf_ktime_get_ns()`），只能分别比较延迟值。

---

## 报告结构

1. **执行摘要** - 关键发现（3-5 条要点）
2. **数据采集概况** - 样本量、时间范围、探针覆盖
3. **事务成功率统计** - 成功/失败数量及占比
4. **延迟拆解分析** - RPC 层 vs SVC 层的延迟分布对比
5. **高延迟事务追踪** - Top N 高延迟事务详情及根因推断
6. **失败事务追踪** - 失败事务列表、状态码分布、SVC 层关联情况
7. **优化建议** - 基于数据的具体建议
