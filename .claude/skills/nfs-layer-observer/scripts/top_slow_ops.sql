-- top_slow_ops.sql
-- 用途：按 pid/comm 聚合 Top 慢操作
-- 使用方式：替换 __TABLE__ 为实际探针表名后执行

SELECT
    pid,
    comm,
    COUNT(*) AS cnt,
    AVG(lat_ns) / 1e6 AS avg_ms,
    MAX(lat_ns) / 1e6 AS max_ms,
    quantile_cont(0.95)(lat_ns) / 1e6 AS p95_ms
FROM __TABLE__
WHERE lat_ns IS NOT NULL
GROUP BY pid, comm
ORDER BY max_ms DESC
LIMIT 20;
