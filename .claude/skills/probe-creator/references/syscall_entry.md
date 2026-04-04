# 系统调用探针模板 (tracepoint)

## 适用场景
- 监控系统调用
- 安全审计
- 系统行为分析

## 核心字段
| 字段 | 类型 | 说明 |
|------|------|------|
| pid | u64 | 进程ID |
| comm | string | 进程名 |
| syscall_id | u32 | 系统调用号 |

## 可选字段
| 字段 | 类型 | 说明 | 适用条件 |
|------|------|------|---------|
| args[6] | u64[] | 系统调用参数 | 入口探针 |
| ret | s64 | 返回值 | 退出探针 |
| duration | u64 | 执行耗时 | 配对入口/退出 |

## tracepoint 格式

系统调用 tracepoint 定义在：
- 入口: `/sys/kernel/tracing/events/raw_syscalls/sys_enter`
- 退出: `/sys/kernel/tracing/events/raw_syscalls/sys_exit`
- 具体调用: `/sys/kernel/tracing/events/syscalls/sys_enter_<name>`

## eBPF C 代码模板

### 通用系统调用入口

```c
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

volatile __u64 filter_pid;
volatile __u32 filter_syscall_id;

struct event {
    u64 pid;
    u32 syscall_id;
    u64 args[6];
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __type(value, struct event);
} events SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;
    __u32 syscall_id = ctx->id;

    if (filter_pid && filter_pid != pid)
        return 0;

    if (filter_syscall_id && filter_syscall_id != syscall_id)
        return 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return 0;

    event->pid = pid_tgid;
    event->syscall_id = syscall_id;
    event->args[0] = ctx->args[0];
    event->args[1] = ctx->args[1];
    event->args[2] = ctx->args[2];
    event->args[3] = ctx->args[3];
    event->args[4] = ctx->args[4];
    event->args[5] = ctx->args[5];
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

### 具体系统调用（如 openat）

```c
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

volatile __u64 filter_pid;

// sys_enter_openat 的参数结构
struct syscalls_enter_openat_args {
    unsigned long long unused;
    long syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

struct event {
    u64 pid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    long flags;
    long mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __type(value, struct event);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct syscalls_enter_openat_args *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;

    if (filter_pid && filter_pid != pid)
        return 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return 0;

    event->pid = pid_tgid;
    event->flags = ctx->flags;
    event->mode = ctx->mode;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // 读取字符串参数
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), ctx->filename);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

## 常用系统调用

| 调用名 | 用途 | 关键参数 |
|--------|------|---------|
| `execve` | 程序执行 | filename, argv, envp |
| `openat` | 打开文件 | dfd, filename, flags |
| `read` | 读取文件 | fd, buf, count |
| `write` | 写入文件 | fd, buf, count |
| `connect` | 网络连接 | sockfd, addr, addrlen |
| `clone` | 创建进程/线程 | flags, stack, ptid |

## 规范要点
1. tracepoint 参数结构体需要与内核定义匹配
2. 用户态字符串使用 `bpf_probe_read_user_str()`
3. 内核态字符串使用 `bpf_probe_read_kernel_str()`
4. tracepoint 不涉及延迟计算，只记录事件
