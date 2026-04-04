-- 最慢进程分析
-- 用途：识别产生高延迟系统调用的进程
-- 输出：进程名、总调用数、平均延迟、最大延迟、P99延迟

SELECT
    comm as process_name,
    COUNT(*) as total_calls,
    ROUND(AVG(duration), 2) as avg_duration_ns,
    MAX(duration) as max_duration_ns,
    ROUND(quantile_cont(0.99) WITHIN GROUP (ORDER BY duration), 2) as p99_ns,
    COUNT(CASE WHEN duration > 10000000 THEN 1 END) as slow_calls
FROM sys_call_trace
GROUP BY comm
HAVING COUNT(*) > 50
ORDER BY p99_ns DESC
LIMIT 15;
