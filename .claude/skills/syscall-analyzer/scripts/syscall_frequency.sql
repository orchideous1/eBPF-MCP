-- 系统调用频率统计
-- 用途：识别最频繁使用的系统调用
-- 参数：可通过 LIMIT 调整返回数量

SELECT
    syscall_id,
    COUNT(*) as call_count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM sys_call_trace
GROUP BY syscall_id
ORDER BY call_count DESC
LIMIT 20;
