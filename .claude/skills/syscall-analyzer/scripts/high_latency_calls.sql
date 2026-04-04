-- 高延迟系统调用分析
-- 用途：识别性能瓶颈，找出慢系统调用
-- 参数：可调整 duration 阈值（默认10ms = 10000000ns）

SELECT
    syscall_id,
    (pid & 0xFFFFFFFF)::UINTEGER as process_id,
    comm,
    ROUND(duration / 1000000.0, 3) as duration_ms,
    enter_time_stamp,
    ret
FROM sys_call_trace
WHERE duration > 10000000  -- 超过10ms
ORDER BY duration DESC
LIMIT 50;
