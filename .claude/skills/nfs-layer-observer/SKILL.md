---
name: nfs-layer-observer
description: |
  NFS 客户端与服务端（NFSD）层的 eBPF 观测专家技能。
  当用户提到 "NFS"、"NFSD"、"nfsd"、"nfs-client"、"分析 NFS 请求"、"NFS 服务端"、"NFS 读写延迟"、"NFS 操作慢"、"nfsd4_*" 等时，**必须**使用此技能。
  本技能负责判断当前探针集合是否覆盖用户的运维需求；若不能覆盖，则与用户确认后调用 probe-creator 开发新探针；若能覆盖，则执行加载→观测→卸载→分析数据。
---

# NFS Layer Observer - NFS 层观测技能

## 与 nfs-sre-expert 的关系

- **被委托时**：`nfs-sre-expert` 已确定观测目标和跨层计划，你负责 **NFS-client / nfsd 层**的深入分析。
- **独立调用时**：你需自行完成覆盖度盘点、探针选择、观测闭环和报告输出。

---

## 核心职责

1. **判断目标层**：根据用户问题确定关注 `nfs-client`、`nfsd` 或两者。
2. **盘点探针覆盖度**：对照 `references/probe_catalog_reference.md` 和本地 `probes/`、`ebpf/NFS-client/`、`ebpf/nfsd/` 目录，判断需求是否被已有探针覆盖。
3. **补全缺口**：若覆盖不足，与用户确认后调用 `probe-creator`。
4. **执行观测闭环**：加载探针 → 采集数据 → 卸载探针 → 分析并输出报告。

---

## 步骤 1：判断目标层

| 关键词 | 推断层 |
|--------|--------|
| "客户端"、"client"、`nfs_file_*`、`nfs_lookup`、`nfs4_*`（非 nfsd4_*） | **nfs-client** |
| "服务端"、"server"、"nfsd"、`nfsd4_*`、`NFSD` | **nfsd** |
| 未明确说明 client/server | **两者都检查** |

---

## 步骤 2：盘点探针覆盖度

**判定优先级**：
1. **已满足**：已有探针可直接回答用户问题 → 直接观测。
2. **可扩展满足**：`references/probe_catalog_reference.md` 中的未实现函数可补缺口 → 与用户确认后调用 `probe-creator`。
3. **不可满足**：目标函数不在 catalog 中 → 说明能力边界，询问替代方案。

**快速盘点命令**：
```bash
ls -1 ebpf/NFS-client/
ls -1 ebpf/nfsd/
ls -1 probes/*.yaml | grep -E 'nfs-|nfsd4'
```

**风险约束**：
- `nfs-client` 的 `nfs_op` 层事件量高，不建议全量采集，优先使用更聚焦的 `vfs` 层探针（如 `nfs_file_read`）。
- `nfsd` 层 op 种类多，负载高时易事件洪泛，建议按需分批加载。

---

## 步骤 3：启动 probe-creator（按需）

若覆盖不足，向用户展示缺口并征得同意后调用 `probe-creator`：
```
创建一个监控 <函数名> 的探针，用于 <场景>，采集 <延迟/返回值/错误状态等>
```

探针创建完成后：
1. 重新盘点目录确认新探针已落地。
2. **必须**更新 `references/probe_catalog_reference.md`，将新探针从"未实现"移到"已实现"表格。

---

## 步骤 4：执行观测闭环

### 4.1 加载探针
通过 `system_observe_control` 加载所需探针。按需使用 `probe_customize` 设置 `filter_pid`、`filter_comm` 等过滤参数。

### 4.2 数据采集与卸载
| 分析类型 | 建议时长 |
|----------|----------|
| 快速排查 | 30–60 秒 |
| 深度分析 | 2–5 分钟 |
| 问题复现 | 直到复现为止 |

采集完成后**必须卸载所有探针**，获取最新 DuckDB 文件路径并验证数据存在。

### 4.3 数据分析思路

**延迟分析**：关注 P50/P95/P99 延迟分布，识别长尾。
**Top 慢操作**：按 `pid`、`comm` 聚合，找出延迟最高的进程或操作。
**时序趋势**：按秒统计 QPS 与平均延迟，观察波动模式。
**异常点**：高延迟 Top N、错误返回（如有 `error` 字段）。

### 4.4 报告结构
1. **执行摘要** - 关键发现（3-5 条）
2. **探针覆盖** - 本次用到的探针列表
3. **数据概况** - 样本量、时间范围
4. **延迟/性能分析** - 按数据结果解读
5. **异常点识别** - 高延迟、错误/失败
6. **结论与建议** - 是否需要更多探针或调整过滤条件

---

## 证据不足时的补救策略

| 不足场景 | 补救动作 |
|----------|----------|
| 数据为空或样本太少 | 检查过滤条件是否过严，调用 `probe_customize` 放宽 |
| 捕获不到目标操作 | 列出缺失函数，征得同意后调用 `probe-creator` |
| 缺少关键上下文字段 | 调用 `probe-creator` 增强该探针的字段采集 |
| 需关联 RPC/SVC 层 | 额外加载 `rpc_task_latency`、`svc_rqst_latency`，调用 `rpc-nfs-analyzer` |

---

## 快速参考：常见运维问题与推荐探针

| 运维问题 | 关注层 | 推荐探针 |
|----------|--------|----------|
| "NFS 客户端读慢" | nfs-client | `nfs_file_read` |
| "NFS 客户端写慢" | nfs-client | `nfs_file_write` |
| "NFS getattr 慢" | nfs-client | `nfs_getattr` |
| "NFS setattr 慢" | nfs-client | `nfs_setattr` |
| "NFSD 服务端读慢" | nfsd | `nfsd4_read` |
| "NFSD 服务端写慢" | nfsd | `nfsd4_write` |
| "NFSD create_session 慢" | nfsd | 需新建 `nfsd4_create_session` |
| "NFS lookup 慢" | nfs-client | 需新建 `nfs_lookup` |
