//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES  1024
#define MAX_BUFF_ENTRIES 1 << 12
#define TASK_COMM_LEN 32
#define PROC_NAME_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

// 过滤参数
volatile __u64 filter_pid;
volatile char filter_comm[TASK_COMM_LEN];

// 事件结构体
struct event {
    u32 pid;
    u32 xid;
    char proc_name[PROC_NAME_LEN];
    u64 latency;
    u64 start_timestamp;
    s32 status;
};

// 开始信息结构体（存储在 starts map 中）
struct rpc_start_info {
    u64 start_time;
    u64 pid;
};

// starts map: 记录入口时间和 pid，key 为 rpc_task 指针
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, void *);        // rpc_task 指针
    __type(value, struct rpc_start_info);
} starts SEC(".maps");

// events ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_BUFF_ENTRIES);
    __type(value, struct event);
} events SEC(".maps");

// rpc_execute fentry 探针
SEC("fentry/rpc_execute")
int BPF_PROG(rpc_execute_entry, struct rpc_task *task) {
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

    // 记录开始时间和 pid
    struct rpc_start_info info = {};
    info.start_time = bpf_ktime_get_ns();
    info.pid = pid_tgid;

    bpf_map_update_elem(&starts, &task, &info, BPF_ANY);
    return 0;
}

// rpc_exit_task fentry 探针
SEC("fentry/rpc_exit_task")
int BPF_PROG(rpc_exit_task_entry, struct rpc_task *task) {
    // 从 starts map 查找对应的开始信息
    struct rpc_start_info *info = bpf_map_lookup_elem(&starts, &task);
    if (!info)
        return 0;

    // 分配事件
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        goto cleanup;

    // 填充基本字段
    event->pid = (u32)(info->pid >> 32);
    event->start_timestamp = info->start_time;
    event->latency = bpf_ktime_get_ns() - info->start_time;

    // 读取 xid: task->tk_rqstp->rq_xid
    event->xid = 0;
    struct rpc_rqst *rqst = BPF_CORE_READ(task, tk_rqstp);
    if (rqst) {
        __be32 xid_be = BPF_CORE_READ(rqst, rq_xid);
        event->xid = bpf_ntohl(xid_be);  // 转换为大端序到主机序
    }

    // 读取 proc_name: task->tk_msg.rpc_proc->p_name
    event->proc_name[0] = '\0';
    const struct rpc_procinfo *proc = BPF_CORE_READ(task, tk_msg.rpc_proc);
    if (proc) {
        const char *p_name = BPF_CORE_READ(proc, p_name);
        if (p_name) {
            bpf_probe_read_kernel_str(&event->proc_name, sizeof(event->proc_name), p_name);
        }
    }

    // 读取 status: task->tk_status
    event->status = BPF_CORE_READ(task, tk_status);

    bpf_ringbuf_submit(event, 0);

cleanup:
    // 清理 starts map 中的记录
    bpf_map_delete_elem(&starts, &task);
    return 0;
}
