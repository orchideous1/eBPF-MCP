//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES  8 // num of cpu
#define MAX_BUFF_ENTRIES 1 << 12
#define TASK_COMM_LEN 32
#define FILE_NAME_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

// 过滤参数
volatile __u64 filter_pid;
volatile char filter_file[FILE_NAME_LEN];

// 事件结构体
struct event {
    u64 pid;
    u64 lat;
    u64 time_stamp;
    s64 ret;
    char comm[TASK_COMM_LEN];
    char file[FILE_NAME_LEN];
};

// 用于存储开始时间的 map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64); // pid_tgid
    __type(value, u64); // start_time
} starts SEC(".maps");

// Ringbuf 用于发送事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_BUFF_ENTRIES);
    __type(value, struct event);
} events SEC(".maps");

SEC("fentry/nfs_getattr")
int BPF_PROG(nfs_getattr_entry, struct user_namespace *mnt_userns, struct dentry *dentry, struct kstat *stat) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;

    // 检查 filter_pid 过滤条件
    if (filter_pid && filter_pid != pid)
        return 0;

    // 记录开始时间
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &pid_tgid, &ts, BPF_ANY);

    return 0;
}

SEC("fexit/nfs_getattr")
int BPF_PROG(nfs_getattr_exit, struct user_namespace *mnt_userns, struct dentry *dentry, struct kstat *stat, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // 获取开始时间
    __u64 *start_time_ptr = bpf_map_lookup_elem(&starts, &pid_tgid);
    if (!start_time_ptr)
        return 0;

    // 预留 ringbuf 空间
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        goto cleanup;

    // 填充事件数据
    event->pid = pid_tgid >> 32;
    event->time_stamp = bpf_ktime_get_ns();
    event->lat = event->time_stamp - *start_time_ptr;
    event->ret = (s64)ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // 从 dentry 读取文件名
    if (dentry) {
        const __u8 *file_name = BPF_CORE_READ(dentry, d_name.name);
        if (file_name)
            bpf_probe_read_kernel_str(&event->file, sizeof(event->file), (char *)file_name);
        else
            event->file[0] = '\0';
    } else {
        event->file[0] = '\0';
    }

    // 检查 filter_file 过滤条件（精确匹配）
    if (filter_file[0] != '\0') {
        for (int i = 0; i < FILE_NAME_LEN; i++) {
            if (event->file[i] != filter_file[i]) {
                bpf_ringbuf_discard(event, 0);
                goto cleanup;
            }
            if (event->file[i] == '\0' || filter_file[i] == '\0')
                break;
        }
    }

    bpf_ringbuf_submit(event, 0);

cleanup:
    bpf_map_delete_elem(&starts, &pid_tgid);
    return 0;
}
