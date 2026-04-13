-- latency_summary.sql
-- 用途：计算 NFS/NFSD 探针表的 P50/P95/P99 延迟及事件总数
-- 使用方式：duckdb <db_file> -c "$(cat latency_summary.sql | sed 's/__TABLE__/probe_table_name/')"

SELECT
    quantile_cont(0.50)(lat_ns) / 1e6 AS p50_ms,
    quantile_cont(0.95)(lat_ns) / 1e6 AS p95_ms,
    quantile_cont(0.99)(lat_ns) / 1e6 AS p99_ms,
    MIN(lat_ns) / 1e6 AS min_ms,
    MAX(lat_ns) / 1e6 AS max_ms,
    AVG(lat_ns) / 1e6 AS avg_ms,
    COUNT(*) AS total_events
FROM __TABLE__
WHERE lat_ns IS NOT NULL;
