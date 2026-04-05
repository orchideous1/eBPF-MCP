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
| syscall_id | UINTEGER | 系统调用号（数字形式）|
| ret | BIGINT | 系统调用返回值 |
| duration | UBIGINT | 调用延迟（纳秒）|
| enter_time_stamp | UBIGINT | 进入时间戳（纳秒，自系统启动）|
| comm | VARCHAR | 进程名称（最多16字符）|

---

## 工作流程

### 步骤1: 启动系统调用探针

**步骤目标**
加载 `sys_call_trace` 探针，开始采集系统调用数据。

**具体操作命令**

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

如需过滤特定进程或系统调用，在加载后使用 `probe_customize`：

```json
{
  "tool": "probe_customize",
  "arguments": {
    "name": "sys_call_trace",
    "params": {
      "filter_pid": 1234,
      "filter_syscall_id": 0,
      "filter_comm": "git"
    }
  }
}
```

**思维链（思考要点）**
   探针加载：
   - 在加载之前可以调用probe_resource_info查看详细信息，包括探针在内核中是否加载（load/unload）
   探针定制：
   - 全量采集：适用于未知问题排查，但性能开销大；按 PID 或者 comm 过滤：适用于已知目标进程的分析；按 syscall_id 过滤：适用于关注特定系统调用（如只关注文件操作）
   - 

---

### 步骤3: 数据采集

**步骤目标**
让探针运行足够时间，采集具有统计意义的系统调用样本。

**时间建议**

| 分析类型 | 建议采集时间 | 说明 |
|----------|-------------|------|
| 简单分析 | 10-30秒 | 快速了解系统调用概况 |
| 性能分析 | 1-5分钟 | 获取稳定的延迟分布统计 |
| 异常排查 | 直到问题复现 | 需要捕获异常事件发生时的数据 |

**思维链（思考要点）**

1. **采集时长决策**：
   - 目标进程的系统调用频率如何？高频进程（如数据库）10秒即可获取大量样本
   - 问题是否间歇性出现？如果是，需要延长采集时间或多次采集
   - 是否有特定的操作序列需要覆盖？确保采集期间执行了目标操作

2. **样本量评估**：
   - 延迟百分位统计（P95/P99）至少需要数百个样本
   - 频率分布分析需要覆盖完整的业务周期
   - 异常检测需要包含正常和异常两种状态的数据

3. **实时监控**：
   - 采集期间可通过数据库查询实时确认数据写入
   - 检查数据库文件大小是否在增长

**检查项**
- [ ] 目标进程在采集期间处于运行状态
- [ ] 执行了需要分析的业务操作
- [ ] 数据库文件大小在增长（确认数据写入）
- [ ] 采集时间达到预期目标

**注意事项和限制**
- **数据量控制**：长时间采集可能产生大量数据，注意磁盘空间
- **时间戳解释**：`enter_time_stamp` 是自系统启动以来的纳秒数，不是 Unix 时间戳
- **进程生命周期**：如果目标进程在采集期间退出，其数据仍然保留在数据库中

---

### 步骤4: 停止探针并确保数据落盘

**步骤目标**
安全卸载探针，确保所有缓冲数据已写入数据库文件。
> 在数据库目录(database/)中查找带时间戳的最新数据库文件(通常带有时间戳后缀，如 `ebpf-mcp-20250405-143022.duckdb`)
> 确保分析的是最新采集的数据。
> 数据库文件记为$LATEST_DB

**具体操作命令**
```
export LATEST_DB = $(ls -t database/ebpf-mcp-*.duckdb | head -1) //修改环境变量为最新数据库文件，便于调用分析脚本
```

```json
{
  "tool": "system_observe_control",
  "arguments": {
    "probeName": "sys_call_trace",
    "operation": "unload"
  }
}
```

验证数据落盘：

```bash
# 检查数据库文件大小
ls -lh $LATEST_DB

# 验证数据已写入（使用 DuckDB 命令行）
duckdb $LATEST_DB -c "SELECT COUNT(*) FROM sys_call_trace;"

# 查看数据时间范围
duckdb $LATEST_DB -c "SELECT MIN(enter_time_stamp)/1e9 as start_sec, MAX(enter_time_stamp)/1e9 as end_sec FROM sys_call_trace;"
```

**思维链（思考要点）**

1. **数据完整性验证**：
   - 查询记录数确认有数据写入
   - 检查时间戳范围是否与采集时段匹配

2. **异常处理**：
   - 如果数据为空，检查过滤条件是否过于严格

**检查项**
- [ ] 探针状态变为 `registered`（unload 成功）
- [ ] 数据库查询返回非零记录数
- [ ] 时间戳范围符合预期
- [ ] 关键字段无大量 NULL 值

**注意事项和限制**
- 探针 unload 后，数据库文件句柄释放，可以进行完整分析
- 如果探针异常退出，可能存在数据丢失（缓冲区未刷新）
- 建议 unload 后等待几秒再进行数据库操作

---

### 步骤5: 数据库分析（原始数据处理）

**步骤目标**
对原始系统调用数据进行统计分析，专注于数据聚合和指标计算。

**SQL 脚本使用**

SQL 脚本位于 `.claude/skills/syscall-analyzer/scripts/` 目录：

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

**使用示例**

```bash
# 使用最新数据库执行分析
LATEST_DB=$(ls -t database/ebpf-mcp-*.duckdb 2>/dev/null | head -1)

# 执行频率统计
duckdb $LATEST_DB < .claude/skills/syscall-analyzer/scripts/syscall_frequency.sql

# 执行进程统计
duckdb $LATEST_DB < .claude/skills/syscall-analyzer/scripts/process_stats.sql

# 执行高延迟分析
duckdb $LATEST_DB < .claude/skills/syscall-analyzer/scripts/high_latency_calls.sql
```

**常用即席查询模板**

```sql
-- 最近的高延迟调用（syscall_id 保持数字）
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

-- 各系统调用延迟统计（原始ID）
SELECT
    syscall_id,
    COUNT(*) as count,
    MIN(duration)/1e6 as min_ms,
    AVG(duration)/1e6 as avg_ms,
    MAX(duration)/1e6 as max_ms,
    quantile_cont(0.95)(duration)/1e6 as p95_ms,
    quantile_cont(0.99)(duration)/1e6 as p99_ms
FROM sys_call_trace
GROUP BY syscall_id
ORDER BY count DESC;
```

**思维链（思考要点）**

1. **分析目标明确**：
   - 性能问题：优先执行 `high_latency_calls.sql` 和 `latency_distribution.sql`
   - 行为分析：优先执行 `process_stats.sql` 和 `syscall_frequency.sql`
   - 异常排查：优先执行 `error_analysis.sql`

2. **数据质量检查**：
   - 记录数是否合理？（过少可能采样不足，过多可能包含无关数据）
   - 时间范围是否覆盖目标时段？
   - 是否有明显的数据异常（如 duration 为 0 或极大值）？

3. **指标解读**：
   - 延迟单位转换：数据库中存储的是纳秒，报表通常使用毫秒（除以 1e6）
   - 时间戳转换：`enter_time_stamp` 是自启动纳秒数，转换为秒需除以 1e9
   - 错误识别：`ret < 0` 表示系统调用返回错误

4. **迭代分析**：
   - 根据初步结果调整分析方向
   - 发现热点 syscall_id 后，可针对性深入分析
   - 发现热点进程后，可使用 `filter_pid` 重新采集更精确的数据

**检查项**
- [ ] 各脚本执行无报错
- [ ] 查询结果记录数合理
- [ ] 延迟数值在合理范围（纳秒级到秒级）
- [ ] 识别出需要关注的 syscall_id 数字

**注意事项和限制**
- **此阶段不涉及系统调用名称映射**：syscall_id 保持数字形式，便于精确统计和交叉验证
- **大数据集处理**：如果记录数超过百万，部分查询可能较慢，可考虑添加时间范围过滤
- **NULL 值处理**：某些字段可能为 NULL，使用 `COALESCE` 进行默认值处理

---

### 步骤6: 总结报告（系统调用号映射）

**步骤目标**
将分析结果转换为可读报告，在此阶段引入系统调用号到名称的映射，生成最终交付物。

**映射方法**

系统调用号定义参考 [resource/unistd.h](./resource/unistd.h)，该文件包含完整的 Linux x86_64 系统调用号定义。

**常用系统调用速查表**

| 编号 | 名称 | 功能 |
|------|------|------|
| 0 | io_setup | 异步 I/O 初始化 |
| 1 | io_destroy | 异步 I/O 销毁 |
| 17 | getcwd | 获取当前工作目录 |
| 29 | ioctl | 设备控制 |
| 56 | openat | 相对于目录打开文件 |
| 57 | close | 关闭文件描述符 |
| 63 | read | 从文件描述符读取 |
| 64 | write | 向文件描述符写入 |
| 172 | getpid | 获取进程ID |
| 221 | execve | 执行程序 |

**手动映射示例**

```bash
# 在 SQL 查询中手动映射常用系统调用
# 注意：实际报告中应使用脚本自动映射

duckdb $LATEST_DB -c "
SELECT
    CASE syscall_id
        WHEN 0 THEN 'io_setup'
        WHEN 1 THEN 'io_destroy'
        WHEN 56 THEN 'openat'
        WHEN 57 THEN 'close'
        WHEN 63 THEN 'read'
        WHEN 64 THEN 'write'
        ELSE 'syscall_' || syscall_id
    END as syscall_name,
    COUNT(*) as calls,
    AVG(duration)/1e6 as avg_ms
FROM sys_call_trace
GROUP BY syscall_id
ORDER BY calls DESC
LIMIT 10;
"
```

**使用可视化脚本自动生成报告**

可视化脚本 [visualize.py](./scripts/visualize.py) 会自动完成系统调用号到名称的映射：

```bash
# 基础用法 - 分析全部数据
python .claude/skills/syscall-analyzer/scripts/visualize.py \
    --db-path $LATEST_DB \
    --output-dir ./syscall_analysis

# 分析特定进程
python .claude/skills/syscall-analyzer/scripts/visualize.py \
    --db-path $LATEST_DB \
    --output-dir ./syscall_analysis \
    --pid 1234

# 分析最近5分钟的数据
python .claude/skills/syscall-analyzer/scripts/visualize.py \
    --db-path $LATEST_DB \
    --output-dir ./syscall_analysis \
    --time-range 5m
```

**依赖安装**

```bash
pip install duckdb pandas matplotlib seaborn numpy
```

**可视化脚本输出**

| 文件名 | 说明 |
|--------|------|
| `syscall_frequency.png` | 系统调用频率分布（Top 20，已映射名称） |
| `syscall_latency_distribution.png` | 延迟分布直方图 |
| `syscall_heatmap.png` | 进程-系统调用热力图 |
| `syscall_timeline.png` | 调用数与延迟时间线 |
| `syscall_latency_by_type.png` | 各类型延迟箱线图（已映射名称） |
| `top_slow_calls.png` | 最慢100次调用散点图 |
| `syscall_summary.json` | 完整统计摘要（包含 syscall_name） |

**思维链（思考要点）**

1. **报告结构规划**：
   - 执行摘要：关键发现（Top 3）
   - 数据概况：样本量、时间范围、进程覆盖
   - 频率分析：哪些系统调用最频繁
   - 延迟分析：瓶颈在哪里
   - 异常发现：错误、高延迟、异常模式
   - 优化建议：基于数据的具体建议

2. **受众适配**：
   - 技术报告：包含详细 SQL 查询和原始数据
   - 管理报告：突出关键指标和业务影响
   - 故障报告：聚焦异常点和根因分析

---

## 输出报告结构

分析报告应包含以下章节：

1. **执行摘要** - 关键发现和结论（3-5 条要点）
2. **采集概况** - 数据量、时间范围、进程覆盖、采样时长
3. **频率分析** - 热点系统调用、分布统计、调用模式
4. **延迟分析** - 延迟分布、P95/P99 长尾、瓶颈识别
5. **进程分析** - 各进程系统调用行为、资源消耗排行
6. **异常发现** - 错误返回、高延迟事件、异常模式
7. **优化建议** - 基于分析数据的具体优化建议
8. **附录** - 可视化图表、原始数据查询、方法论说明

---
