//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

// 过滤参数
volatile __u64 filter_pid;
volatile char filter_comm[TASK_COMM_LEN];

// 事件结构体
struct event {
    u64 pid;
    u64 latency;
    u64 time_stamp;
    char comm[TASK_COMM_LEN];
};

// Ringbuf用于输出事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __type(value, struct event);
} events SEC(".maps");

// Hash map用于存储I/O开始时间，以dev+sector为key
struct start_key {
    u64 dev;
    u64 sector;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct start_key);
    __type(value, u64); // 开始时间戳
} start_times SEC(".maps");

// block_io_start tracepoint处理
SEC("tracepoint/block/block_io_start")
int trace_block_io_start(struct trace_event_raw_block_rq *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;

    // PID过滤
    if (filter_pid && filter_pid != pid) {
        return 0;
    }

    // 进程名过滤
    if (filter_comm[0] != '\0') {
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(&comm, sizeof(comm));
        for (int i = 0; i < TASK_COMM_LEN; i++) {
            if (comm[i] != filter_comm[i]) {
                return 0;
            }
            if (comm[i] == '\0' || filter_comm[i] == '\0')
                break;
        }
    }

    // 记录开始时间，以dev+sector为key
    struct start_key key = {
        .dev = ctx->dev,
        .sector = ctx->sector,
    };
    u64 start_ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_times, &key, &start_ts, BPF_ANY);

    return 0;
}

// block_io_done tracepoint处理
SEC("tracepoint/block/block_io_done")
int trace_block_io_done(struct trace_event_raw_block_rq *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;

    // 使用dev+sector查找对应的开始时间
    struct start_key key = {
        .dev = ctx->dev,
        .sector = ctx->sector,
    };
    u64 *start_ts = bpf_map_lookup_elem(&start_times, &key);
    if (!start_ts) {
        // 没有找到对应的开始时间，可能是在探针启动前就开始了
        return 0;
    }

    // 计算延迟
    u64 end_ts = bpf_ktime_get_ns();
    u64 latency = end_ts - *start_ts;

    // 删除已处理的记录
    bpf_map_delete_elem(&start_times, &key);

    // 预留ringbuf空间
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) {
        return 0;
    }

    // 填充事件数据
    event->pid = pid;
    event->latency = latency;
    event->time_stamp = end_ts;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}
