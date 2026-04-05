//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES  8
#define MAX_BUFF_ENTRIES 1 << 12
#define TASK_COMM_LEN 32

char __license[] SEC("license") = "Dual MIT/GPL";

volatile __u64 filter_pid;

struct event {
    u64 pid;
    u64 lat;
    u64 time_stamp;
    u64 size;
    u64 offset;
    u32 xid;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, u64);
} starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_BUFF_ENTRIES);
    __type(value, struct event);
} events SEC(".maps");

SEC("fentry/nfsd4_write")
int BPF_PROG(nfsd4_write_entry, void *rqstp, void *cstate, void *write) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid;

    if (filter_pid && filter_pid != pid)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

SEC("fexit/nfsd4_write")
int BPF_PROG(nfsd4_write_exit, void *rqstp, void *cstate, void *write, long ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *start_time_ptr = bpf_map_lookup_elem(&starts, &pid_tgid);
    __u64 start_time = start_time_ptr ? *start_time_ptr : 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return 0;

    event->pid = pid_tgid;
    event->time_stamp = bpf_ktime_get_ns();
    event->lat = start_time ? event->time_stamp - start_time : 0;

    // 获取进程名
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // 获取 XID (rpc transaction id) - 从 svc_rqst 的 rq_xid 字段读取
    if (rqstp) {
        event->xid = BPF_CORE_READ((struct svc_rqst *)rqstp, rq_xid);
    } else {
        event->xid = 0;
    }

    // 获取写操作的偏移量和大小
    // nfsd4_write 结构体: wr_offset (u64), wr_buflen (u32)
    if (write) {
        bpf_probe_read_kernel(&event->offset, sizeof(event->offset), (void *)((char *)write + 0));
        u32 buflen = 0;
        bpf_probe_read_kernel(&buflen, sizeof(buflen), (void *)((char *)write + 8));
        event->size = (u64)buflen;
    } else {
        event->offset = 0;
        event->size = 0;
    }

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&starts, &pid_tgid);
    return 0;
}
