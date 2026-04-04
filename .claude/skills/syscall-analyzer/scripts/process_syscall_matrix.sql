-- 进程-系统调用热力矩阵
-- 用途：生成进程与系统调用的交叉统计，用于热力图可视化
-- 输出：进程名、各系统调用计数

SELECT
    comm as process_name,
    SUM(CASE WHEN syscall_id = 0 THEN 1 ELSE 0 END) as read_count,
    SUM(CASE WHEN syscall_id = 1 THEN 1 ELSE 0 END) as write_count,
    SUM(CASE WHEN syscall_id = 2 THEN 1 ELSE 0 END) as open_count,
    SUM(CASE WHEN syscall_id = 3 THEN 1 ELSE 0 END) as close_count,
    SUM(CASE WHEN syscall_id = 9 THEN 1 ELSE 0 END) as mmap_count,
    SUM(CASE WHEN syscall_id = 16 THEN 1 ELSE 0 END) as ioctl_count,
    SUM(CASE WHEN syscall_id = 257 THEN 1 ELSE 0 END) as openat_count,
    COUNT(*) as total_calls
FROM sys_call_trace
GROUP BY comm
HAVING COUNT(*) > 100
ORDER BY total_calls DESC
LIMIT 20;
