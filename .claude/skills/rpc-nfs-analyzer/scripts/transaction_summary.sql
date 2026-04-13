-- 事务整体摘要统计
-- 汇总 RPC 事务数量、成功率、延迟分位数、关联匹配率

WITH rpc_stats AS (
    SELECT
        COUNT(*) AS total_transactions,
        COUNT_IF(status = 0) AS success_count,
        COUNT_IF(status != 0) AS failed_count,
        ROUND(COUNT_IF(status != 0) * 100.0 / COUNT(*), 2) AS fail_rate_pct,
        ROUND(AVG(latency) / 1e6, 3) AS rpc_avg_ms,
        ROUND(quantile_cont(0.50)(latency) / 1e6, 3) AS rpc_p50_ms,
        ROUND(quantile_cont(0.95)(latency) / 1e6, 3) AS rpc_p95_ms,
        ROUND(quantile_cont(0.99)(latency) / 1e6, 3) AS rpc_p99_ms,
        ROUND(MAX(latency) / 1e6, 3) AS rpc_max_ms
    FROM rpc_task_latency
),
svc_stats AS (
    SELECT
        COUNT(*) AS svc_records,
        ROUND(AVG(latency) / 1e6, 3) AS svc_avg_ms,
        ROUND(quantile_cont(0.95)(latency) / 1e6, 3) AS svc_p95_ms,
        ROUND(quantile_cont(0.99)(latency) / 1e6, 3) AS svc_p99_ms
    FROM svc_rqst_latency
),
match_stats AS (
    SELECT
        COUNT(*) AS matched_count,
        ROUND(COUNT(*) * 100.0 / (SELECT total_transactions FROM rpc_stats), 2) AS match_rate_pct
    FROM rpc_task_latency r
    JOIN svc_rqst_latency s ON r.xid = s.xid
)
SELECT
    r.total_transactions,
    r.success_count,
    r.failed_count,
    r.fail_rate_pct,
    m.matched_count,
    m.match_rate_pct,
    r.rpc_avg_ms,
    r.rpc_p50_ms,
    r.rpc_p95_ms,
    r.rpc_p99_ms,
    r.rpc_max_ms,
    s.svc_avg_ms,
    s.svc_p95_ms,
    s.svc_p99_ms
FROM rpc_stats r
CROSS JOIN svc_stats s
CROSS JOIN match_stats m;
