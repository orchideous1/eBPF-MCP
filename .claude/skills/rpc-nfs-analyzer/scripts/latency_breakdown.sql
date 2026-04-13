-- 延迟拆解分析
-- 按 proc_name 统计 RPC 层和 SVC 层的延迟分布对比

WITH joined AS (
    SELECT
        r.proc_name,
        r.latency AS rpc_latency,
        s.latency AS svc_latency,
        (r.latency - COALESCE(s.latency, 0)) AS rpc_overhead
    FROM rpc_task_latency r
    LEFT JOIN svc_rqst_latency s ON r.xid = s.xid
)
SELECT
    proc_name,
    COUNT(*) AS total_count,
    COUNT_IF(svc_latency IS NOT NULL) AS matched_count,
    ROUND(COUNT_IF(svc_latency IS NOT NULL) * 100.0 / COUNT(*), 2) AS match_rate_pct,
    -- RPC 层延迟统计 (ms)
    ROUND(MIN(rpc_latency) / 1e6, 3) AS rpc_min_ms,
    ROUND(AVG(rpc_latency) / 1e6, 3) AS rpc_avg_ms,
    ROUND(quantile_cont(0.95)(rpc_latency) / 1e6, 3) AS rpc_p95_ms,
    ROUND(quantile_cont(0.99)(rpc_latency) / 1e6, 3) AS rpc_p99_ms,
    ROUND(MAX(rpc_latency) / 1e6, 3) AS rpc_max_ms,
    -- SVC 层延迟统计 (ms)
    ROUND(MIN(svc_latency) / 1e6, 3) AS svc_min_ms,
    ROUND(AVG(svc_latency) / 1e6, 3) AS svc_avg_ms,
    ROUND(quantile_cont(0.95)(svc_latency) / 1e6, 3) AS svc_p95_ms,
    ROUND(quantile_cont(0.99)(svc_latency) / 1e6, 3) AS svc_p99_ms,
    ROUND(MAX(svc_latency) / 1e6, 3) AS svc_max_ms,
    -- RPC 独占延迟 (网络/队列等)
    ROUND(AVG(rpc_overhead) / 1e6, 3) AS avg_overhead_ms,
    ROUND(quantile_cont(0.95)(rpc_overhead) / 1e6, 3) AS p95_overhead_ms
FROM joined
GROUP BY proc_name
ORDER BY total_count DESC;
