---
name: nfs-layer-observer
description: |
  NFS 客户端与服务端（NFSD）层的 eBPF 观测专家技能。
  当用户提到 "NFS"、"NFSD"、"nfsd"、"nfs-client"、"分析 NFS 请求"、"NFS 服务端"、"NFS 读写延迟"、"NFS 操作慢"、"nfsd4_*" 等时，**必须**使用此技能。
  本技能负责执行 NFS-client / nfsd 层的观测闭环（加载→采集→卸载→分析数据），以及被 `nfs-sre-analyzer` 委托时的深度分析。
  本技能**不**负责判断探针覆盖度或调用 probe-creator；探针可用性应由 `nfs-sre-probe-decision` 提前确认。
---

# NFS Layer Observer - NFS 层观测技能

## 与 nfs-sre 系列的关系

- **被 `nfs-sre-analyzer` 委托时**：负责 **NFS-client / nfsd 层**的深入数据分析。
- **独立调用时**：执行 NFS 层的完整观测闭环（加载→采集→卸载→分析）。**假设所需探针已存在**（已由 `nfs-sre-probe-decision` 或用户确认）。

---

## 核心职责

1. **判断目标层**：根据用户问题确定关注 `nfs-client`、`nfsd` 或两者。
2. **执行观测闭环**：加载探针 → 采集数据 → 卸载探针 → 分析并输出报告。
3. **被委托时做深度分析**：运行 SQL、识别延迟分布、Top N 慢操作、时序趋势、异常点。

---

## 步骤 1：判断目标层

| 关键词 | 推断层 |
|--------|--------|
| "客户端"、"client"、`nfs_file_*`、`nfs_lookup`、`nfs4_*`（非 nfsd4_*） | **nfs-client** |
| "服务端"、"server"、"nfsd"、`nfsd4_*`、`NFSD` | **nfsd** |
| 未明确说明 client/server | **两者都检查** |

---

## 步骤 2：执行观测闭环

### 2.1 加载探针
通过 `system_observe_control` 加载所需探针。按需使用 `probe_customize` 设置 `filter_pid`、`filter_comm` 等过滤参数。

### 2.2 数据采集与卸载
| 分析类型 | 建议时长 |
|----------|----------|
| 快速排查 | 30–60 秒 |
| 深度分析 | 2–5 分钟 |
| 问题复现 | 直到复现为止 |

采集完成后**必须卸载所有探针**，获取最新 DuckDB 文件路径并验证数据存在。

### 2.3 数据分析思路

**延迟分析**：关注 P50/P95/P99 延迟分布，识别长尾。
**Top 慢操作**：按 `pid`、`comm` 聚合，找出延迟最高的进程或操作。
**时序趋势**：按秒统计 QPS 与平均延迟，观察波动模式。
**异常点**：高延迟 Top N、错误返回（如有 `error` 字段）。

### 2.4 报告结构
1. **执行摘要** - 关键发现（3-5 条）
2. **探针覆盖** - 本次用到的探针列表
3. **数据概况** - 样本量、时间范围
4. **延迟/性能分析** - 按数据结果解读
5. **异常点识别** - 高延迟、错误/失败
6. **结论与建议** - 是否需要更多探针或调整过滤条件

---

## 3. 证据不足时的补救策略

| 不足场景 | 补救动作 |
|----------|----------|
| 数据为空或样本太少 | 检查过滤条件是否过严，调用 `probe_customize` 放宽 |
| 捕获不到目标操作 | 说明该操作可能未被当前探针覆盖，建议先由 `nfs-sre-probe-decision` 分析缺口 |
| 缺少关键上下文字段 | 建议由 `nfs-sre-probe-decision` 评估是否需要增强探针 |
| 需关联 RPC/SVC 层 | 额外加载 `rpc_task_latency`、`svc_rqst_latency`，调用 `rpc-nfs-analyzer` |

---

## 4. 快速参考：常见运维问题与推荐探针

| 运维问题 | 关注层 | 推荐探针 |
|----------|--------|----------|
| "NFS 客户端读慢" | nfs-client | `nfs_file_read` |
| "NFS 客户端写慢" | nfs-client | `nfs_file_write` |
| "NFS getattr 慢" | nfs-client | `nfs_getattr` |
| "NFS setattr 慢" | nfs-client | `nfs_setattr` |
| "NFSD 服务端读慢" | nfsd | `nfsd4_read` |
| "NFSD 服务端写慢" | nfsd | `nfsd4_write` |
| "NFSD 访问权限检查慢" | nfsd | `nfsd4_access` |

---

## 5. Anti-Patterns (Never Do)

❌ **推断操作类型清单或盘点覆盖度** → ✅ 这是 `nfs-sre-probe-decision` 的职责
❌ **直接调用 probe-creator** → ✅ 必须通过 `nfs-sre-probe-decision` 统一决策
❌ **未卸载探针就结束** → ✅ 必须显式卸载并验证
❌ **忽略样本量不足** → ✅ 必须报告数据质量并给出补救建议
