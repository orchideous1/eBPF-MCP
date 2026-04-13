-- RPC-SVC 基础关联查询
-- 按 xid 将 RPC 层和 SVC 层数据关联，展示完整事务链路

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
    r.start_timestamp / 1e9 AS rpc_start_sec,
    s.start_timestamp / 1e9 AS svc_start_sec
FROM rpc_task_latency r
LEFT JOIN svc_rqst_latency s ON r.xid = s.xid
ORDER BY r.start_timestamp DESC
LIMIT 200;
