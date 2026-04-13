# ebpf-MCP
[eBPF-MCP架构](./assets/eBPF-MCP架构.png)

## 概述
运维场景中常用的 eBPF 探针涵盖网络、内存、CPU、进程等多个维度，不同探针的编写规范、调用参数、输出格式差异较大且缺乏统一的语义描述，导致智能体无法快速识别探针的功能定位与适用场景。

为解决上述难题，本项目基于MCP构建下一代eBPF管理中间件。它专为Agentic AI运维场景设计，通过标准化的资源抽象与严密的治理架构，解决了AI Agent直接操作eBPF时的安全性、复杂性和稳定性难题。

## 🧠 Features
1. 声明式 eBPF 探针管理：将eBPF探针抽象为声明式资源。
2. 边界隔离：在 MCP 与智能体交互边界实施权限控制，智能体不能直接操作内核资源。
3. 基于资源配额进行预检：在探针加载前动态检查系统资源是否充足。
4. 支持探针策略热更新：支持智能体动态更改探针收集策略。

## 📚 References
* [Linux Kernel eBPF Docs](https://docs.kernel.org/bpf/)
* [Model Context Protocol](https://modelcontextprotocol.io)
* [eBPF Security Best Practices](https://ebpf.io/security/)
* [Cilium for Kubernetes Observability](https://cilium.io/)

## 🏗️ Design Doc
* [eBPF-MCP 设计文档](./docs/DESIGN.md)

## 📦 Project Structure
```text
.
├── assets/       # 架构图、演示截图与文档插图等静态资源
├── docs/         # 说明和设计文档
├── ebpf/         # eBPF 程序源码（.c/.h）与编译产物管理
├── internal/     # Go 内部业务实现（仅仓库内可引用）
└── scripts/      # 构建、测试、部署、环境初始化脚本
```

## Todo
1. 增加磁盘细粒度跟踪

## 📜 Licensing
GPL-2.0 