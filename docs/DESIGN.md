# eBPF-MCP 设计文档

## 1. 文档目标
本文档定义 eBPF-MCP 服务端的核心设计，覆盖以下内容：
- 架构逻辑设计
- 框架代码设计
- 模块划分
- MCP 工具定义

目标是让智能体能够在可控、安全、可解释的前提下，调用 eBPF 探针能力完成系统观测任务。

## 2. 背景与设计原则
在运维场景中，eBPF 探针通常存在以下问题：
- 探针能力描述不统一，智能体难以理解功能边界
- 探针加载/卸载流程分散，缺乏统一治理
- 参数可定制性强，但安全边界不清晰
- 资源开销不可预期，可能影响业务稳定性

本项目基于 MCP 协议，使用 mcp-go 和 ebpf-go 构建服务端，遵循以下原则：
- 资源标准化：所有探针必须被抽象为 MCP Resource
- 工具最小化：对智能体暴露最少但足够的工具能力
- 生命周期可控：加载、更新、卸载全流程可审计
- 安全优先：默认拒绝高风险请求（default deny）
- 成本可预估：引入配额与准入检查，避免资源失控

## 3. 架构逻辑设计
### 3.1 总体架构
系统分为四层：
1. 协议接入层（MCP Server Layer）
2. 资源语义层（Resource Catalog Layer）
3. 策略治理层（Policy and Quota Layer）
4. 执行引擎层（eBPF Runtime Layer）

### 3.2 分层职责
1. 协议接入层
- 基于 mcp-go 实现 MCP Server
- 注册资源和工具
- 对请求进行入参校验、鉴权、审计封装

2. 资源语义层
- 将每个探针抽象为标准资源实例
- 维护探针元信息：功能说明、语义标签、运行状态、可配置参数
- 提供资源检索能力，便于智能体按语义发现探针

3. 策略治理层
- 执行策略校验（谁可以做什么）
- 执行资源配额准入（CPU/内存/事件吞吐预算）
- 管理探针生命周期状态机（unloaded/loading/loaded/error/unloading）

4. 执行引擎层
- 基于 ebpf-go 完成程序加载、Attach、Detach、Map 读写
- 负责内核对象句柄生命周期管理
- 提供错误分级与回滚能力

### 3.3 核心流程
1. 智能体发起请求（定制探针或观测管理）
2. MCP 层完成参数校验和权限检查
3. 资源层根据 probeName 读取该探针在 Resource 中声明的可定制参数契约或状态
4. 策略层执行配额预检与风险评估
5. 执行层调用 ebpf-go 进行 load/attach、reload 或 detach/unload
6. 资源层更新探针状态并输出审计事件
7. 返回标准 MCP 响应

说明：
- 当探针已加载且收到参数变更请求时，优先执行 reload 流程使新参数生效。
- reload 失败时回滚到上一版稳定配置，并将状态标记为 error（附原因）。

## 4. 框架代码与模块实现设计
### 4.1 技术栈
- 协议框架：mcp-go
- 内核交互：ebpf-go
- 语言与运行时：Go（与 go.mod 保持一致）

### 4.2 模块边界与目录映射
模块按“接口定义在消费方、实现放在提供方”的原则划分，避免跨层循环依赖。

- 协议接入模块（MCP Server）
    - 目录：internal/server
    - 文件：
        - internal/server/server.go：服务启动、生命周期管理
        - internal/server/routes.go：Resource/Tool 注册
        - internal/server/handler_probe_customize.go：probe_customize 入口
        - internal/server/handler_observe_control.go：system_observe_control 入口
    - 说明：只做请求编排，不直接操作 ebpf-go。

- 资源目录模块（Resource Catalog）
    - 目录：internal/resource
    - 文件：
        - internal/resource/model.go：资源模型（ProbeResource、ParamSpec）
        - internal/resource/catalog.go：目录查询与状态读写接口
        - internal/resource/catalog_mem.go：内存实现（可替换为持久化实现）
        - internal/resource/catalog_loader_yaml.go：加载 docs/probe_catalog_nfs.yaml 到目录
    - 说明：维护探针声明契约，尤其是 customizableParams。

- 探针定制模块（Probe Customization）
    - 目录：internal/tooling/customize
    - 文件：
        - internal/tooling/customize/service.go：定制主流程（校验、准入、reload）
        - internal/tooling/customize/validator.go：参数类型/范围/枚举校验
        - internal/tooling/customize/translator.go：params -> ProbeRuntimeConfig 转换
    - 说明：接收 name + params，参数合法后触发执行层 Reload。

- 系统观测控制模块（System Observe Control）
    - 目录：internal/tooling/observe
    - 文件：
        - internal/tooling/observe/service.go：load/unload/status 编排
        - internal/tooling/observe/state_query.go：状态聚合查询
    - 说明：管理探针生命周期和部署目标，不处理参数契约细节。

- 策略与配额模块（Policy and Quota）
    - 目录：internal/policy
    - 文件：
        - internal/policy/rbac.go：身份与权限判定
        - internal/policy/quota.go：预算准入接口与实现
        - internal/policy/risk.go：高风险参数和操作拦截
    - 说明：对 Customize/Observe 两类请求提供统一准入能力。

- 执行引擎模块（Runtime Engine）
    - 目录：internal/runtime
    - 文件：
        - internal/runtime/manager.go：运行时总入口（Load/Reload/Unload）
        - internal/runtime/loader.go：程序加载与 attach
        - internal/runtime/reloader.go：原子 reload 与失败回滚
        - internal/runtime/objects.go：map/link/program/pin 句柄管理
    - 说明：是唯一直接依赖 ebpf-go 的模块。

- 审计与配置模块
    - 目录：internal/audit、internal/config
    - 文件：
        - internal/audit/logger.go：审计事件记录
        - internal/config/config.go：服务配置结构
        - internal/config/validate.go：配置合法性校验

### 4.3 关键接口声明位置
接口按“谁依赖谁，接口就声明在谁的包内”进行放置，减少不必要抽象。

- internal/tooling/customize/service.go 声明：
    - CatalogReader：读取 probe 的参数契约与状态
    - AdmissionChecker：策略/配额准入检查
    - RuntimeReloader：触发运行时 Reload

- internal/tooling/observe/service.go 声明：
    - RuntimeOperator：load/unload/status 运行时操作
    - AdmissionChecker：与 customize 复用同一准入接口语义

- internal/resource/catalog.go 声明：
    - CatalogStore：资源目录的读写接口（Get/List/UpdateStatus/UpdateRuntimeConfig）

- internal/policy/quota.go 声明：
    - QuotaManager：预算评估与准入（CheckLoadAdmission/CheckReloadAdmission）

- internal/runtime/manager.go 声明：
    - RuntimeManager：LoadAndAttach/Reload/DetachAndUnload

### 4.4 关键数据结构声明位置
- internal/resource/model.go：
    - ProbeResource、ProbeCapabilities、ParamSpec、ParamConstraint
- internal/tooling/customize/service.go：
    - CustomizeRequest（name、params、dryRun、reloadPolicy）
    - CustomizeResult（accepted、reason、newState、auditID）
- internal/runtime/manager.go：
    - ProbeRuntimeConfig、ReloadResult

### 4.5 name + params 到 reload 的代码执行链路
1. internal/server/handler_probe_customize.go 接收工具请求：name + params。
2. internal/tooling/customize/service.go 调用 CatalogReader 获取该 name 对应的 ParamSpec。
3. internal/tooling/customize/validator.go 对 params 做键、类型、范围、必填校验。
4. internal/policy/quota.go 与 internal/policy/risk.go 执行准入检查。
5. internal/tooling/customize/translator.go 生成 ProbeRuntimeConfig。
6. internal/runtime/reloader.go 执行原子 Reload。
7. 成功后由 internal/resource/catalog.go 更新 runtimeConfig 与状态；失败则回滚并写 error 状态。
8. internal/audit/logger.go 记录请求参数摘要、决策结果、回滚信息。

### 4.6 模块实现约束
- server 不允许直接 import ebpf-go。
- runtime 不允许依赖 server。
- tooling 通过接口依赖 resource/policy/runtime，不持有具体实现。
- probe 参数声明以 probe catalog 为事实来源，Resource 只保存已加载的标准化契约。
- reload 必须具备幂等语义：同参数重复调用不触发重复变更。

## 6. MCP 资源与工具定义
### 6.1 资源模型（Resource）
每个探针作为一个 MCP 资源，建议包含：
- id：唯一标识（如 probe.nfs.latency）
- name：探针名称
- description：功能描述
- tags：语义标签（如 network, process, io, nfs）
- status：unloaded / loaded / error
- capabilities：支持的定制能力
- customizableParams：参数声明（字段名、类型、默认值、范围、是否必填）
- runtimeConfig：当前生效参数
- constraints：可接受参数范围

参数声明示例（与 probe catalog 对齐）：
- filter_pid: u32, default=0, range=[0, 4294967295]
- is_collect_file_name: bool, default=false

落地建议：
- 以 docs/example_probe.yaml 作为探针参数声明来源之一，在服务启动时装载到 Resource Catalog，形成可校验的 customizableParams 契约。

### 6.2 工具一：probe_customize
用途：定制探针探测内容与点位，控制过滤与数据采集行为。该工具不直接暴露底层实现细节，仅接收探针名与参数集合。

请求字段（建议）：
- name：探针名称（必须匹配 Resource.name）
- params：参数对象（key-value），仅允许 Resource.customizableParams 中声明的键

返回字段（建议）：
- accepted：是否接受
- reason：拒绝原因（若 rejected）

执行规则：
- 校验 name 是否存在。
- 校验 params 是否全部命中该探针的 customizableParams 声明，且类型与范围合法。
- 若探针当前状态为 loaded 且参数发生变化，调用执行层 reload。
- 若探针当前状态为 unloaded，则直接拒绝。

### 6.3 工具二：system_observe_control
用途：统一管理探针生命周期、部署范围与资源配额。

请求字段（建议）：
- probeName：探针名称或探针类别
- operation：load | unload | status

返回字段（建议）：
- state：当前/变更后状态
- admission：allowed | denied
- quotaReport：预算消耗与余量
- reason：拒绝原因（若 denied）

### 6.4 错误码建议
- INVALID_ARGUMENT：参数不合法
- PERMISSION_DENIED：权限不足
- QUOTA_EXCEEDED：资源预算不足
- PROBE_NOT_FOUND：探针不存在
- RUNTIME_FAILURE：加载或卸载失败
- CONFLICT：状态冲突（例如重复加载）





