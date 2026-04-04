-- 错误返回值分析
-- 用途：识别系统调用错误，分析错误模式
-- 输出：错误系统调用、错误码、错误次数、涉及进程

SELECT
    syscall_id,
    ret as error_code,
    COUNT(*) as error_count,
    comm,
    (pid & 0xFFFFFFFF)::UINTEGER as process_id
FROM sys_call_trace
WHERE ret < 0
GROUP BY syscall_id, ret, comm, pid
ORDER BY error_count DESC;
