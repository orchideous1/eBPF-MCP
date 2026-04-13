-- 高延迟事务追踪分析
-- 定义阈值：RPC 延迟 > 10ms 或 SVC 延迟 > 10ms
-- 重点关注两端延迟均较高的热点事务

SELECT
    r.xid,
    r.proc_name,
    r.pid,
    r.latency / 1e6 AS rpc_latency_ms,
    s.latency / 1e6 AS svc_latency_ms,
    (r.latency - COALESCE(s.latency, 0)) / 1e6 AS rpc_overhead_ms,
    r.status,
    CASE
        WHEN r.status = 0 THEN 'SUCCESS'
        ELSE 'FAILED'
    END AS status_str,
    CASE
        WHEN r.latency > 10000000 AND s.latency > 10000000 THEN 'BOTH_HIGH'
        WHEN r.latency > 10000000 AND (s.latency IS NULL OR s.latency <= 10000000) THEN 'RPC_HIGH_ONLY'
        WHEN r.latency <= 10000000 AND s.latency > 10000000 THEN 'SVC_HIGH_ONLY'
    END AS latency_pattern,
    r.start_timestamp / 1e9 AS start_sec
FROM rpc_task_latency r
LEFT JOIN svc_rqst_latency s ON r.xid = s.xid
WHERE r.latency > 10000000
   OR s.latency > 10000000
ORDER BY GREATEST(r.latency, COALESCE(s.latency, 0)) DESC
LIMIT 100;
