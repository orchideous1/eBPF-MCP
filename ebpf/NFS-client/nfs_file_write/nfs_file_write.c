//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#define MAX_ENTRIES  8 // num of cpu
#define MAX_BUFF_ENTRIES 1 << 12
#define FILE_NAME_LEN 16
#define TASK_COMM_LEN 32
#define MAP_PREFIX nfs_file_write

char __license[] SEC("license") = "Dual MIT/GPL";
volatile __u64 filter_pid;
volatile char filter_file[FILE_NAME_LEN];
volatile char filter_comm[TASK_COMM_LEN];

struct event {
    u32 pid;
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

// 简化的通配符匹配：只支持前缀匹配（如 "*.log"）和完全匹配
static bool match_wildcard(const char *pattern, const char *str) {
    int pi = 0, si = 0;

    // 处理开头的 *
    if (pattern[0] == '*') {
        // 后缀匹配模式：*.ext
        int pat_len = 0;
        while (pat_len < FILE_NAME_LEN && pattern[pat_len] != '\0')
            pat_len++;

        if (pat_len <= 1) return true; // 只有*，匹配所有

        // 比较后缀
        int str_len = 0;
        while (str_len < FILE_NAME_LEN && str[str_len] != '\0')
            str_len++;

        int suffix_start = str_len - (pat_len - 1);
        if (suffix_start < 0) return false;

        for (int i = 1; i < pat_len; i++) {
            if (pattern[i] != str[suffix_start + i - 1])
                return false;
        }
        return true;
    }

    // 普通匹配（不包含回溯）
    while (pi < FILE_NAME_LEN && si < FILE_NAME_LEN) {
        if (pattern[pi] == '\0' && str[si] == '\0')
            return true;
        if (pattern[pi] == '\0' || str[si] == '\0')
            return false;
        if (pattern[pi] != '?' && pattern[pi] != str[si])
            return false;
        pi++;
        si++;
    }

    // 检查pattern是否只剩*
    while (pi < FILE_NAME_LEN && pattern[pi] == '*')
        pi++;

    return pattern[pi] == '\0';
}

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
    __u64 pid = pid_tgid >> 32;

    if (filter_pid && filter_pid != pid)
        return 0;

    // 获取当前进程名并检查 filter_comm
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (filter_comm[0] != '\0') {
        for (int i = 0; i < TASK_COMM_LEN; i++) {
            if (comm[i] != filter_comm[i]) {
                return 0;
            }
            if (comm[i] == '\0' || filter_comm[i] == '\0')
                break;
        }
    }

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

    event->pid = (u32)(pid_tgid >> 32);
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

    // 检查 filter_file 过滤条件（支持通配符 * 和 ?）
    if (filter_file[0] != '\0') {
        if (!match_wildcard((const char *)filter_file, event->file)) {
            bpf_ringbuf_discard(event, 0);
            bpf_map_delete_elem(&starts, &pid_tgid);
            return 0;
        }
    }

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&starts, &pid_tgid);
    return 0;
}
