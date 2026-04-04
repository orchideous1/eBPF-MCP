-- 进程系统调用统计
-- 用途：分析各进程的系统调用行为
-- 输出：进程ID、进程名、总调用数、唯一系统调用数、平均/最大延迟

SELECT
    (pid & 0xFFFFFFFF)::UINTEGER as process_id,
    comm,
    COUNT(*) as total_calls,
    COUNT(DISTINCT syscall_id) as unique_syscalls,
    ROUND(AVG(duration), 2) as avg_duration_ns,
    MAX(duration) as max_duration_ns,
    ROUND(SUM(duration) / 1000000.0, 2) as total_time_ms
FROM sys_call_trace
GROUP BY pid, comm
ORDER BY total_calls DESC;
