-- 系统调用时间序列分析
-- 用途：分析系统调用随时间的分布，识别流量峰值
-- 输出：每秒调用数、平均延迟

SELECT
    (enter_time_stamp / 1000000000)::UBIGINT as second_bucket,
    COUNT(*) as calls_per_second,
    ROUND(AVG(duration), 2) as avg_latency_ns,
    COUNT(DISTINCT (pid & 0xFFFFFFFF)::UINTEGER) as unique_processes
FROM sys_call_trace
GROUP BY second_bucket
ORDER BY second_bucket;
