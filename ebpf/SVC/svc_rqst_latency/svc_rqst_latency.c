//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_ENTRIES  1024
#define MAX_BUFF_ENTRIES 1 << 12

char __license[] SEC("license") = "Dual MIT/GPL";

// 事件结构体
struct event {
    u32 xid;
    u64 latency;
    u64 start_timestamp;
};

// starts map: 记录入口时间，key 为 svc_rqst 指针
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, void *);     // svc_rqst 指针
    __type(value, __u64);    // start_time
} starts SEC(".maps");

// events ringbuf
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_BUFF_ENTRIES);
    __type(value, struct event);
} events SEC(".maps");

// svc_process fentry 探针 - 记录开始时间
SEC("fentry/svc_process")
int BPF_PROG(svc_process_entry, struct svc_rqst *rqstp) {
    // 记录开始时间，key 使用 rqstp 指针（此时 rq_xid 可能尚未初始化）
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &rqstp, &ts, BPF_ANY);
    return 0;
}

// svc_send fentry 探针 - 计算延迟并输出
SEC("fentry/svc_send")
int BPF_PROG(svc_send_entry, struct svc_rqst *rqstp) {
    // 从 starts map 查找对应的开始时间，key 使用 rqstp 指针
    __u64 *start = bpf_map_lookup_elem(&starts, &rqstp);
    if (!start)
        return 0;

    // 分配事件
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        goto cleanup;

    // 填充事件
    __be32 xid_be = BPF_CORE_READ(rqstp, rq_xid);
    e->xid = bpf_ntohl(xid_be);
    e->start_timestamp = *start;
    e->latency = bpf_ktime_get_ns() - *start;

    bpf_ringbuf_submit(e, 0);

cleanup:
    // 清理 starts map 中的记录
    bpf_map_delete_elem(&starts, &rqstp);
    return 0;
}
