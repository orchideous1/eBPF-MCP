# 开发日志
## 3/24：
完成数据库后端DuckDB的搭建，跑通nfs_file_read向数据库推送的测试
下一步：
1. 把 observe/control 服务层与 probes 注册表打通，实现在 MCP 工具里真正调用 Start/Stop/Update
2. 增加一个小型集成测试：启动探针后触发 nfs_file_read，查询 DuckDB 表验证落盘条数与字段内容。

## 3/25
把 observe/control 服务层与 probes 注册表打通，实现在 MCP 工具里真正调用 Start/Stop/Update
验证了数据库写入和分析
下一步：
1. 重构server
2. 复制探针数量
3. 完成审计模块

## 3/26
+ 重构server模块，确立server + controller架构，controller再独立执行审计功能。
+ 实现探针声明式资源加载。
下一步计划：复制探针数量

## 3/27-3/29
+ 增加探针测试系统，建立全链路测试

## Finish-4/5