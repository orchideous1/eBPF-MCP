# 系统调用分析脚本集

本目录包含用于系统调用数据分析的 SQL 脚本和 Python 可视化脚本。

## SQL 分析脚本

### 基础统计脚本

| 脚本 | 用途 | 典型输出 |
|------|------|----------|
| `syscall_frequency.sql` | 系统调用频率统计 | 各 syscall 的调用次数和占比 |
| `process_stats.sql` | 进程维度的统计 | 各进程的总调用数、平均延迟、最大延迟 |

### 性能分析脚本

| 脚本 | 用途 | 典型输出 |
|------|------|----------|
| `high_latency_calls.sql` | 高延迟调用筛选 | 超过10ms的系统调用详情 |
| `latency_distribution.sql` | 延迟分布统计 | P50/P95/P99 延迟分位数 |
| `top_slow_processes.sql` | 慢进程识别 | P99延迟最高的进程排行 |

### 模式分析脚本

| 脚本 | 用途 | 典型输出 |
|------|------|----------|
| `time_series.sql` | 时间序列分析 | 每秒调用数趋势 |
| `error_analysis.sql` | 错误返回值分析 | 负返回值的错误统计 |
| `process_syscall_matrix.sql` | 交叉矩阵统计 | 进程-系统调用热力图数据 |

### 使用方式

```bash
# 命令行执行（使用 $LATEST_DB 环境变量指向最新的数据库文件）
duckdb $LATEST_DB < syscall_frequency.sql

# 或直接在 duckdb shell 中执行
duckdb $LATEST_DB
D select * from sys_call_trace limit 5;
D .read syscall_frequency.sql
```

## Python 可视化脚本

### visualize.py

全自动可视化分析工具，从数据库读取数据并生成多种分析图表。

#### 功能特性

- **7种可视化图表**：频率、延迟、热力图、时间线、箱线图、散点图
- **灵活的过滤**：支持按进程ID、时间范围过滤
- **统计摘要**：生成 JSON 格式的完整统计报告
- **系统调用名称映射**：自动将 syscall_id 转换为可读名称

#### 命令行参数

```
--db-path      DuckDB 数据库路径（必需）
--output-dir   输出目录（必需）
--pid          过滤特定进程ID（可选）
--time-range   时间范围，如 5m, 1h（可选）
```

#### 使用示例

```bash
# 首先设置最新数据库环境变量
export LATEST_DB=$(ls -t database/ebpf-mcp-*.duckdb | head -1)

# 分析全部数据
python visualize.py --db-path $LATEST_DB --output-dir ./analysis

# 分析特定进程
python visualize.py --db-path $LATEST_DB --output-dir ./analysis --pid 1234

# 分析最近10分钟
python visualize.py --db-path $LATEST_DB --output-dir ./analysis --time-range 10m
```

#### 输出文件

| 文件名 | 说明 |
|--------|------|
| `syscall_frequency.png` | 系统调用频率分布（Top 20） |
| `syscall_latency_distribution.png` | 延迟分布直方图（线性与对数） |
| `syscall_heatmap.png` | 进程-系统调用热力图 |
| `syscall_timeline.png` | 调用数与延迟时间线 |
| `syscall_latency_by_type.png` | 各类型延迟箱线图 |
| `top_slow_calls.png` | 最慢100次调用散点图 |
| `syscall_summary.json` | 完整统计摘要 |

## 典型分析工作流

### 快速排查高延迟问题

```bash
# 0. 设置最新数据库环境变量
export LATEST_DB=$(ls -t database/ebpf-mcp-*.duckdb | head -1)

# 1. 查看高延迟调用
duckdb $LATEST_DB < high_latency_calls.sql

# 2. 生成可视化图表
python visualize.py --db-path $LATEST_DB --output-dir ./latency_analysis

# 3. 重点查看 syscall_latency_by_type.png 和 top_slow_calls.png
```

### 进程行为分析

```bash
# 0. 设置最新数据库环境变量
export LATEST_DB=$(ls -t database/ebpf-mcp-*.duckdb | head -1)

# 1. 查看各进程调用统计
duckdb $LATEST_DB < process_stats.sql

# 2. 查看进程-系统调用矩阵
duckdb $LATEST_DB < process_syscall_matrix.sql

# 3. 查看最慢进程排行
duckdb $LATEST_DB < top_slow_processes.sql
```

### 全量可视化分析

```bash
# 设置最新数据库环境变量并执行分析
export LATEST_DB=$(ls -t database/ebpf-mcp-*.duckdb | head -1)
python visualize.py --db-path $LATEST_DB --output-dir ./full_analysis
# 然后查看生成的所有图表和 summary.json
```

## 依赖安装

```bash
# SQL 分析需要
duckdb --version  # 或 apt install duckdb

# Python 可视化需要
pip install duckdb pandas matplotlib seaborn numpy
```

## 数据库表结构

所有脚本操作 `sys_call_trace` 表，字段如下：

| 字段 | 类型 | 说明 |
|------|------|------|
| pid | UBIGINT | 进程ID（TGID << 32 \| PID） |
| syscall_id | UINTEGER | 系统调用号 |
| ret | BIGINT | 返回值 |
| duration | UBIGINT | 延迟（纳秒） |
| enter_time_stamp | UBIGINT | 进入时间戳（纳秒） |
| comm | VARCHAR | 进程名 |
