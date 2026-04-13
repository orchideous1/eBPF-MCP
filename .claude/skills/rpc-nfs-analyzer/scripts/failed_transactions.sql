-- 失败事务追踪分析
-- 提取 status != 0 的 RPC 事务，并关联 SVC 层表现

WITH failed_rpc AS (
    SELECT *
    FROM rpc_task_latency
    WHERE status != 0
)
SELECT
    f.xid,
    f.proc_name,
    f.pid,
    f.latency / 1e6 AS rpc_latency_ms,
    COALESCE(s.latency, 0) / 1e6 AS svc_latency_ms,
    f.status,
    CASE f.status
        WHEN -5 THEN 'EIO(-5)'
        WHEN -11 THEN 'EAGAIN(-11)'
        WHEN -103 THEN 'ECONNABORTED(-103)'
        WHEN -104 THEN 'ECONNRESET(-104)'
        WHEN -110 THEN 'ETIMEDOUT(-110)'
        WHEN -111 THEN 'ECONNREFUSED(-111)'
        ELSE 'UNKNOWN(' || f.status || ')'
    END AS error_label,
    CASE
        WHEN s.xid IS NULL THEN 'NO_SVC_RECORD'
        WHEN s.latency > 1000000 THEN 'SVC_SLOW'
        ELSE 'SVC_NORMAL'
    END AS svc_hint,
    f.start_timestamp / 1e9 AS start_sec
FROM failed_rpc f
LEFT JOIN svc_rqst_latency s ON f.xid = s.xid
ORDER BY f.start_timestamp DESC
LIMIT 100;
