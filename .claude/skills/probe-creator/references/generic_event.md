# 通用事件探针模板

## 适用场景
- 自定义事件上报
- 特定内核事件监控
- 简单的计数/通知

## 核心字段
| 字段 | 类型 | 说明 |
|------|------|------|
| pid | u64 | 进程ID |
| time_stamp | u64 | 时间戳 |

## 可选字段
任意自定义字段，根据具体需求添加。

## eBPF C 代码模板

```c
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

// 过滤参数
volatile __u64 filter_pid;

// 事件结构体 - 用户自定义字段
struct event {
    u64 pid;
    u64 time_stamp;
    // 在此添加自定义字段
    // 例如：
    // u32 custom_field_1;
    // u64 custom_field_2;
    // char name[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __type(value, struct event);
} events SEC(".maps");

// kprobe 示例
SEC("kprobe/{FUNC_NAME}")
int BPF_PROG(kprobe_{FUNC_NAME}, /* 函数参数 */) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;

    if (filter_pid && filter_pid != pid)
        return 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return 0;

    event->pid = pid_tgid;
    event->time_stamp = bpf_ktime_get_ns();

    // 填充自定义字段
    // event->custom_field_1 = ...;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// fentry 示例
SEC("fentry/{FUNC_NAME}")
int BPF_PROG(fentry_{FUNC_NAME}, /* 函数参数 */) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;

    if (filter_pid && filter_pid != pid)
        return 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return 0;

    event->pid = pid_tgid;
    event->time_stamp = bpf_ktime_get_ns();

    // 使用 BPF_CORE_READ 直接读取函数参数
    // event->custom_field = BPF_CORE_READ(arg, field);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// tracepoint 示例
SEC("tracepoint/{SUBSYSTEM}/{EVENT}")
int trace_{EVENT}(void *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;

    if (filter_pid && filter_pid != pid)
        return 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return 0;

    event->pid = pid_tgid;
    event->time_stamp = bpf_ktime_get_ns();

    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

## 适用探针类型对比

| 类型 | 适用场景 | 优点 | 缺点 |
|------|---------|------|------|
| kprobe | 任意内核函数 | 兼容性好 | 性能略差 |
| fentry | BTF 可用函数 | 性能好，直接访问 | 需要 BTF |
| tracepoint | 内核预定义事件 | 稳定 API | 事件有限 |
| perf_event | 硬件事件 | 硬件级监控 | 需要特殊权限 |

## 添加自定义字段示例

### 示例 1：监控 kmalloc 分配大小
```c
struct event {
    u64 pid;
    u64 time_stamp;
    u64 size;        // 分配大小
    u64 ptr;         // 返回指针
};

SEC("kprobe/__kmalloc")
int BPF_PROG(kprobe_kmalloc, size_t size) {
    // ...
    event->size = size;
    // ...
}
```

### 示例 2：监控定时器触发
```c
struct event {
    u64 pid;
    u64 time_stamp;
    u64 expires;     // 过期时间
    u32 cpu;         // CPU 编号
};

SEC("tracepoint/timer/timer_expire_entry")
int trace_timer_expire(void *ctx) {
    // ...
    event->cpu = bpf_get_smp_processor_id();
    // ...
}
```

## 规范要点
1. 自定义字段类型要对齐（u8, u16, u32, u64）
2. 字符串字段需要预留足够长度
3. 使用 `bpf_get_smp_processor_id()` 获取 CPU 号
4. 时间戳使用 `bpf_ktime_get_ns()` 获取纳秒时间
