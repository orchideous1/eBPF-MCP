//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#define MAX_ENTRIES  8 // num of cpu
#define MAX_BUFF_ENTRIES 1 << 12
#define FILE_NAME_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";
volatile const __u64 filter_pid;
volatile const bool is_get_size;
volatile const bool is_get_name;

struct event {
    u64 pid;
    u64 lat;
    u64 time_stamp;
    u64 size;
    char comm[TASK_COMM_LEN];
    char file[FILE_NAME_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64); // pid_tgid
	__type(value, u64);
} starts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_BUFF_ENTRIES);
	__type(value, struct event);
} events SEC(".maps");

static __always_inline char * get_file_name(struct file *fp) {
    struct dentry *dentry = BPF_CORE_READ(fp, f_path.dentry);
    if (!dentry) return NULL;
    const __u8 *file_name = BPF_CORE_READ(dentry, d_name.name);
    if (!file_name) return NULL;
    return (char *)file_name;
}

SEC("fentry/nfs_file_write")
int BPF_PROG(nfs_file_write, struct kiocb *iocb, struct iov_iter *from) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid;

    if (filter_pid && filter_pid != pid)
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&starts, &pid_tgid, &ts, BPF_ANY);
    return 0;
}

SEC("fexit/nfs_file_write")
int BPF_PROG(nfs_file_write_exit, struct kiocb *iocb, struct iov_iter *from, ssize_t ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *start_time_ptr = bpf_map_lookup_elem(&starts, &pid_tgid);
    __u64 start_time = start_time_ptr ? *start_time_ptr : 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return 0;

    event->pid = pid_tgid;
    event->time_stamp = bpf_ktime_get_ns();
    event->lat = start_time ? event->time_stamp - start_time : 0;
    event->size = (u64)ret;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    struct file *fp = BPF_CORE_READ(iocb, ki_filp);
    char *file_name = get_file_name(fp);
    if (file_name)
        bpf_probe_read_kernel_str(&event->file, sizeof(event->file), file_name);
    else
        event->file[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&starts, &pid_tgid);
    return 0;
}
