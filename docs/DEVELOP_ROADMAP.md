# 开发日志
## 3/24：
完成数据库后端DuckDB的搭建，跑通nfs_file_read向数据库推送的测试
下一步：
1. 把 observe/control 服务层与 probes 注册表打通，实现在 MCP 工具里真正调用 Start/Stop/Update
2. 增加一个小型集成测试：启动探针后触发 nfs_file_read，查询 DuckDB 表验证落盘条数与字段内容。

## 3/25

## Finish-4/5