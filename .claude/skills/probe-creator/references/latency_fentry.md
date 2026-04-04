# 延迟追踪探针模板 (fentry/fexit)

## 适用场景
- 追踪函数执行延迟
- 性能分析
- 延迟异常检测

## 核心字段
| 字段 | 类型 | 说明 |
|------|------|------|
| pid | u64 | 进程ID (tgid << 32 \| pid) |
| lat | u64 | 延迟（纳秒） |
| time_stamp | u64 | 事件发生时间戳 |

## 可选字段
| 字段 | 类型 | 说明 | 适用条件 |
|------|------|------|---------|
| ret | s64 | 函数返回值 | 所有 fexit 探针 |
| comm | string | 进程名 | 需要进程信息 |
| size | u64 | 数据大小 | I/O 操作 |
| file | string | 文件路径 | 文件操作 |

## eBPF C 代码模板

```c
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define FILE_NAME_LEN 16
#define MAX_ENTRIES 8

char __license[] SEC("license") = "Dual MIT/GPL";

// 过滤参数
volatile __u64 filter_pid;
volatile char filter_comm[TASK_COMM_LEN];

// 事件结构体
struct event {
    u64 pid;
    u64 lat;
    u64 time_stamp;
    // 可选字段 START
    s64 ret;
    char comm[TASK_COMM_LEN];
    // 可选字段 END
};

// starts map: 记录入口时间
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64); // pid_tgid
    __type(value, u64);
} starts SEC(".maps");

// events ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __type(value, struct event);
} events SEC(".maps");

// fentry 探针
SEC("fentry/{FUNC_NAME}")
int BPF_PROG({FUNC_NAME}_entry, /* 函数参数 */) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;

    // filter_pid 过滤
    if (filter_pid && filter_pid != pid)
        return 0;

    // filter_comm 过滤
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (filter_comm[0] != '\0') {
        for (int i = 0; i < TASK_COMM_LEN; i++) {
            if (comm[i] != filter_comm[i])
                return 0;
            if (comm[i] == '\0' || filter_comm[i] == '\0')
                break;
        }
    }

    // 记录开始时间
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

// fexit 探针
SEC("fexit/{FUNC_NAME}")
int BPF_PROG({FUNC_NAME}_exit, /* 函数参数 */, long ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *start_time_ptr = bpf_map_lookup_elem(&starts, &pid_tgid);
    if (!start_time_ptr)
        return 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return 0;

    // 核心字段
    event->pid = pid_tgid;
    event->time_stamp = bpf_ktime_get_ns();
    event->lat = event->time_stamp - *start_time_ptr;

    // 可选字段填充
    event->ret = ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&starts, &pid_tgid);
    return 0;
}
```

## 使用示例

### nfs_file_read（文件读取延迟）
- 函数：`nfs_file_read(struct kiocb *iocb, struct iov_iter *to)`
- 添加字段：`size` (ret), `file` (from iocb->ki_filp)

### tcp_connect（连接延迟）
- 函数：`tcp_connect(struct sock *sk)`
- 添加字段：`comm`

## 规范要点
1. fentry 只记录开始时间，不做其他操作
2. fexit 计算延迟，填充事件，必须删除 starts map 中的记录
3. 所有过滤在 fentry 中完成
4. 延迟计算使用 `bpf_ktime_get_ns()`
