-- 系统调用延迟分布统计
-- 用途：分析各类系统调用的延迟分布，识别长尾问题
-- 输出：各系统调用的 P50/P95/P99 延迟

SELECT
    syscall_id,
    COUNT(*) as count,
    MIN(duration) as min_ns,
    ROUND(AVG(duration), 2) as avg_ns,
    ROUND(quantile_cont(0.50) WITHIN GROUP (ORDER BY duration), 2) as p50_ns,
    ROUND(quantile_cont(0.95) WITHIN GROUP (ORDER BY duration), 2) as p95_ns,
    ROUND(quantile_cont(0.99) WITHIN GROUP (ORDER BY duration), 2) as p99_ns,
    MAX(duration) as max_ns,
    ROUND(STDDEV(duration), 2) as stddev_ns
FROM sys_call_trace
GROUP BY syscall_id
HAVING COUNT(*) > 10
ORDER BY p99_ns DESC;
