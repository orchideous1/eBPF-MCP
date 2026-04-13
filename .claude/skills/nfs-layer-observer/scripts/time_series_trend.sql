-- time_series_trend.sql
-- 用途：按秒级聚合 QPS 和平均延迟趋势
-- 使用方式：替换 __TABLE__ 为实际探针表名后执行

SELECT
    ROUND(time_stamp_ns / 1e9, 0) AS second,
    COUNT(*) AS qps,
    AVG(lat_ns) / 1e6 AS avg_ms,
    MAX(lat_ns) / 1e6 AS max_ms
FROM __TABLE__
WHERE time_stamp_ns IS NOT NULL AND lat_ns IS NOT NULL
GROUP BY second
ORDER BY second;
