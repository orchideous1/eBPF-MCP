---
name: nfs-layer-observer
description: |
  NFS 客户端与服务端（NFSD）层的 eBPF 观测专家技能。
  当用户提到 "NFS"、"NFSD"、"nfsd"、"nfs-client"、"分析 NFS 请求"、"NFS 服务端"、"NFS 读写延迟"、"NFS 操作慢"、"nfsd4_*" 等时，**必须**使用此技能。
  本技能负责判断当前探针集合是否覆盖用户的运维需求；若不能覆盖，则与用户确认后调用 probe-creator 开发新探针；若能覆盖，则执行加载→观测→卸载→分析数据。
---

# NFS Layer Observer - NFS 层观测技能

## 核心理念

**用户负责**：描述具体的 NFS/NFSD 问题场景、目标操作（如 read/write/getattr/create_session）
**智能体负责**：
1. 判断用户关注的是 NFS-client 层、nfsd 层还是两者
2. 检查现有探针集合是否覆盖需求
3. 若覆盖不足，联络用户确认开发计划并调用 `probe-creator`
4. 若覆盖足够，执行标准 eBPF-MCP 探针生命周期并输出分析报告
5. 若分析证据不充分，主动调用 `probe_customize` 或再次调用 `probe-creator` 增强探针

---

## 步骤 1：判断目标层（Layer）

根据用户请求中的关键词推断：

| 关键词 | 推断层 |
|--------|--------|
| "客户端"、"client"、"nfs_file_read"、"nfs_lookup"、"nfs_create"、"nfs4_*"（除 nfsd4_* 外） | **nfs-client** |
| "服务端"、"server"、"nfsd"、"nfsd4_*"、"NFSD" | **nfsd** |
| "NFS 慢"、"读写延迟高"、未明确说明 client/server | **两者都要检查**（先 nfs-client，再 nfsd） |

**输出**：确定需要关注的 layer 列表（`[nfs-client]`、`[nfsd]` 或 `[nfs-client, nfsd]`）

---

## 步骤 2：盘点现有探针覆盖度

### 2.1 读取探针目录

检查以下路径的 YAML 文件与 eBPF 目录：

- `probes/` 目录 — 已有静态注册的探针 YAML
- `ebpf/NFS-client/` 目录 — 已实现的 nfs-client 探针
- `ebpf/nfsd/` 目录 — 已实现的 nfsd 探针
- `references/probe_catalog_reference.md` — 本技能附带的精简速查表，包含函数分层分类、已存在探针、运维问题映射


### 2.2 构建覆盖矩阵

覆盖矩阵的判定优先级（由快到慢）：

1. **已满足**：用户的运维需求能否用**已存在的探针**直接回答？
   - 能 → 直接进入步骤 4 执行观测。
2. **可扩展满足**：已存在的探针不够，但 `references/probe_catalog_reference.md` 中的**未实现函数**可以补上缺口？
   - 能 → 进入步骤 3，与用户确认后调用 `probe-creator`。
3. **不可满足**：用户的请求函数既不在已存在探针中，也不在 catalog 中。
   - 告知用户该操作超出当前 eBPF-MCP 的 NFS 观测范围，并询问是否有替代函数可以满足需求。

**盘点方法**：

对于 **nfs-client** 层：
1. 读取 `references/probe_catalog_reference.md` 和本地 `probes/`、`ebpf/NFS-client/` 目录
2. 将用户目标函数归类到以下三类：
   - **已覆盖**：`probes/` 和 `ebpf/NFS-client/` 均已存在实现
   - **可覆盖**：reference 的 `nfs-client` 章节中有定义，但本地尚未实现
   - **不在 catalog**：reference 中未收录，可能涉及自定义/第三方内核模块

对于 **nfsd** 层：
1. 同理读取 reference 和本地 `probes/`、`ebpf/nfsd/` 目录
2. 将目标 `nfsd4_*` 函数归类到 **已覆盖 / 可覆盖 / 不在 catalog**

**快速覆盖查询示例**（智能体内部执行）：
```bash
# 查看已实现的 nfs-client 探针
ls -1 ebpf/NFS-client/
# 查看已实现的 nfsd 探针
ls -1 ebpf/nfsd/
# 查看已注册的 YAML
ls -1 probes/*.yaml | grep -E 'nfs-|nfsd4'
```

### 2.3 风险与建议

在盘点覆盖度和决策是否新建探针时，注意以下约束：

- **nfs-client `nfs_op` 层**：事件量很高（`event_rate: high`），不建议全量采集。优先用更聚焦的已存在 `vfs` 探针（如 `nfs_file_read`、`nfs_file_write`）；只有当 vfs 层无法解释问题时，才考虑扩展 nfs_op 层的探针。
- **nfsd 层**：op 种类多，负载高时 queue 可能反压。已存在的 `nfsd4_read`、`nfsd4_write` 可直接覆盖高频读写问题；低频/管理类操作（如 `nfsd4_create_session`）按需新建。
- **新建探针优先级**：高频操作（read/write/getattr/lookup/create_session）优先实现；低频/管理类操作按需求补充。全量启用 nfsd 所有 op 易导致事件洪泛，建议分批次按需加载。

---

## 步骤 3：启动 probe-creator 的决策逻辑

### 3.1 判断是否需要新探针

根据步骤 2.2 的覆盖矩阵结果，按以下优先级决策：

1. **需求已被已存在探针覆盖**
   - 用户的运维问题可以通过**已加载/已实现的探针**直接回答。
   - **动作**：直接跳到步骤 4，执行标准观测流程。

2. **需求未被已存在探针覆盖，但在 catalog 中可扩展**
   - 已有探针无法满足，但 `references/probe_catalog_reference.md`中**有对应的未实现函数**可以补上缺口。
   - **动作**：执行 3.2，与用户确认开发计划。

3. **需求完全不可覆盖**
   - 目标函数既不在已存在探针中，也不在 reference/catalog 中。
   - **动作**：向用户说明该操作/函数超出当前 eBPF-MCP NFS 层观测能力，并询问是否存在可替代的观测目标。

### 3.2 与用户确认开发计划

**必须**向用户说明缺口，并获得明确同意后，才启动 `probe-creator`。

沟通模板：
```
当前探针集合无法完全覆盖你的需求：
- 目标层：<nfs-client | nfsd>
- 目标操作：<函数列表>
- 已覆盖：<已有探针列表>
- 缺失：<需要新建的函数列表>

我建议调用 probe-creator 为以下函数创建探针：
1. <func_1>
2. <func_2>
...

是否继续？（是/否 / 修改列表）
```

用户确认后，**调用 `probe-creator` 技能**为每个缺失的函数开发探针。

调用方式：对缺失的每个函数，构造类似
```
创建一个监控 <函数名> 的探针，用于 <场景>，采集 <延迟/返回值/错误状态等>
```
的 prompt，进入 `probe-creator` 工作流。

### 3.3 probe-creator 返回后的验证

探针创建完成后，执行以下动作：

1. **确认新探针已落地**
   - 重新执行步骤 2 的盘点，读取 `probes/*.yaml` 和 `ebpf/<layer>/` 目录，确认新探针文件已生成。
2. **更新参考文档**
   - **必须**同步修改 `references/probe_catalog_reference.md`：将该新探针从"未实现的探针"区域移到对应的"已实现的探针"表格中，补全探针名和采集字段。
   - 如果该函数此前不在 reference 中，直接新增到"已实现的探针"表格。

---

## 步骤 4：执行标准观测流程

所有需要的探针均已存在时，执行 **Load → Observe → Unload → Analyze**。

### 4.1 加载探针（Load）

对所需探针分别调用 `system_observe_control`：
```json
{
  "tool": "system_observe_control",
  "arguments": {
    "probeName": "<probe_name>",
    "operation": "load"
  }
}
```

**加载优先级**：
- 若用户关注读延迟 → 先加载 `nfs_file_read`（client）或 `nfsd4_read`（server）
- 若用户关注写延迟 → 先加载 `nfs_file_write`（client）或 `nfsd4_write`（server）
- 若用户提到具体函数（如 `nfs_getattr`、`nfsd4_create_session`）→ 加载对应探针（如果已实现）

**可选：设置过滤/采样参数**

加载后可用 `probe_customize` 按需定制：
```json
{
  "tool": "probe_customize",
  "arguments": {
    "name": "nfs_file_read",
    "params": {
      "filter_pid": 1234
    }
  }
}
```

### 4.2 数据采集（Observe）

**建议采集时间**：

| 分析类型 | 建议时长 | 说明 |
|----------|----------|------|
| 快速排查 | 30–60 秒 | 获取初步样本 |
| 深度分析 | 2–5 分钟 | 捕获长尾延迟与异常模式 |
| 问题复现 | 直到复现为止 | 确保命中异常事件 |

期间确认：
- 探针状态为 `loaded`
- 数据库文件在增长

### 4.3 停止探针（Unload）

```json
{
  "tool": "system_observe_control",
  "arguments": {
    "probeName": "<probe_name>",
    "operation": "unload"
  }
}
```

**获取数据库路径**：
```bash
export LATEST_DB=$(ls -t /tmp/database/ebpf-mcp-*.duckdb 2>/dev/null | head -1)
if [ -z "$LATEST_DB" ]; then
    export LATEST_DB=$(ls -t database/ebpf-mcp-*.duckdb 2>/dev/null | head -1)
fi
echo "$LATEST_DB"
```

验证数据存在：
```bash
duckdb "$LATEST_DB" -c "SELECT COUNT(*) FROM <probe_name>;"
```

（表名通常为探针名，也可能为 `nfs_file_read`、`nfsd4_read` 等，可通过 `SHOW TABLES;` 确认）

### 4.4 分析数据（Analyze）

根据用户原始问题选择分析模板：

#### A. 延迟分析（通用）

```sql
-- P50/P95/P99 延迟分布
SELECT
    quantile_cont(0.50)(lat_ns) / 1e6 AS p50_ms,
    quantile_cont(0.95)(lat_ns) / 1e6 AS p95_ms,
    quantile_cont(0.99)(lat_ns) / 1e6 AS p99_ms,
    COUNT(*) AS total_events
FROM <probe_table>
WHERE time_stamp_ns > 0;
```

#### B. Top 慢操作（按 pid/comm 聚合）

```sql
SELECT
    pid,
    comm,
    COUNT(*) AS cnt,
    AVG(lat_ns) / 1e6 AS avg_ms,
    MAX(lat_ns) / 1e6 AS max_ms
FROM <probe_table>
GROUP BY pid, comm
ORDER BY max_ms DESC
LIMIT 20;
```

#### C. 时序趋势（简化）

```sql
SELECT
    round(time_stamp_ns / 1e9, 0) AS second,
    COUNT(*) AS qps,
    AVG(lat_ns) / 1e6 AS avg_ms
FROM <probe_table>
GROUP BY second
ORDER BY second;
```

### 4.5 报告结构

分析报告必须包含以下章节：
1. **执行摘要** - 关键发现（3-5 条）
2. **探针覆盖** - 本次用到的探针列表
3. **数据概况** - 样本量、时间范围
4. **延迟/性能分析** - 按 SQL 结果解读
5. **异常点识别** - 高延迟 Top N、错误/失败（如有 error 字段）
6. **结论与建议** - 是否需要更多探针、是否需调整过滤条件

---

## 步骤 5：证据不足时的补救策略

在分析过程中，若出现以下情况，应主动采取措施而非直接结束：

| 不足场景 | 补救动作 |
|----------|----------|
| 数据为空或样本太少 | 检查过滤条件是否过严 → 调用 `probe_customize` 放宽/移除 filter_pid/filter_comm |
| 捕获不到目标操作 | 目标操作对应的探针未实现 → 列出缺失函数，征得用户同意后调用 `probe-creator` |
| 只有延迟但无上下文（缺少 pid/comm/file） | 确认当前探针 YAML 的 `outputs.fields` 是否包含所需字段；若不支持，调用 `probe-creator` 增强该探针（修改字段采集逻辑） |
| 需要关联其他层（如RPC层） | 若用户同意，额外加载 `rpc_task_latency`、`svc_rqst_latency` 等探针，调用 `rpc-nfs-analyzer` 进行跨层关联分析 |

---

## 快速参考：常见 NFS 请求与对应探针

| 运维问题 | 关注层 | 推荐探针 |
|----------|--------|----------|
| "NFS 客户端读慢" | nfs-client | `nfs_file_read` |
| "NFS 客户端写慢" | nfs-client | `nfs_file_write` |
| "NFS getattr 慢" | nfs-client | `nfs_getattr` |
| "NFS setattr 慢" | nfs-client | `nfs_setattr` |
| "NFSD 服务端读慢" | nfsd | `nfsd4_read` |
| "NFSD 服务端写慢" | nfsd | `nfsd4_write` |
| "NFSD create_session 慢" | nfsd | 需新建 `nfsd4_create_session` 探针（调用 probe-creator） |
| "NFS lookup 慢" | nfs-client | 需新建 `nfs_lookup` 探针（调用 probe-creator） |

> **提示**：建覆盖矩阵或不确定用户提到的函数归属时，直接读取 `references/probe_catalog_reference.md`，里面有更完整的函数列表和运维问题映射速查。

---

## 引用资源

- `references/probe_catalog_reference.md` - NFS 探针精简速查表（函数分类、已存在探针、运维问题映射）
- `.claude/skills/probe-creator/SKILL.md` - 新探针自动创建技能
- `.claude/skills/rpc-nfs-analyzer/SKILL.md` - RPC/SVC 层关联分析（可选进阶）
- `scripts/latency_summary.sql` - P50/P95/P99 延迟汇总脚本
- `scripts/top_slow_ops.sql` - Top 慢操作聚合脚本
- `scripts/time_series_trend.sql` - 秒级 QPS 与延迟趋势脚本
