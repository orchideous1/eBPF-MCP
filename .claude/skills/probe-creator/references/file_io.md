# 文件 I/O 探针模板 (fentry/fexit)

## 适用场景
- 追踪文件读写操作
- 监控文件访问模式
- 分析 I/O 性能

## 核心字段
| 字段 | 类型 | 说明 |
|------|------|------|
| pid | u64 | 进程ID |
| file | string | 文件名（不含路径） |
| offset | u64 | 文件偏移量 |
| size | s64 | 读写字节数（fexit 的返回值） |

## 可选字段
| 字段 | 类型 | 说明 | 适用条件 |
|------|------|------|---------|
| comm | string | 进程名 | 需要进程追踪 |
| flags | u32 | 打开标志 | vfs_open 等 |
| mode | u16 | 文件模式 | 创建文件时 |
| ino | u64 | inode 号 | 唯一标识文件 |

## 关键结构体和辅助函数

```c
// 从 struct file * 获取文件名
static __always_inline char *get_file_name(struct file *fp) {
    struct dentry *dentry = BPF_CORE_READ(fp, f_path.dentry);
    if (!dentry) return NULL;
    const __u8 *file_name = BPF_CORE_READ(dentry, d_name.name);
    if (!file_name) return NULL;
    return (char *)file_name;
}

// 获取 inode 号
static __always_inline u64 get_inode(struct file *fp) {
    struct inode *inode = BPF_CORE_READ(fp, f_inode);
    if (!inode) return 0;
    return BPF_CORE_READ(inode, i_ino);
}
```

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

volatile __u64 filter_pid;
volatile char filter_file[FILE_NAME_LEN];

struct event {
    u64 pid;
    u64 lat;
    u64 time_stamp;
    u64 offset;
    s64 size;           // 正值表示成功，负值表示错误
    char file[FILE_NAME_LEN];
    char comm[TASK_COMM_LEN];
};

struct start_info {
    u64 ts;
    u64 offset;
    char file[FILE_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct start_info);
} starts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __type(value, struct event);
} events SEC(".maps");

// 通配符匹配（简化版）
static bool match_wildcard(const char *pattern, const char *str) {
    if (pattern[0] == '*') {
        int pat_len = 0, str_len = 0;
        while (pat_len < FILE_NAME_LEN && pattern[pat_len]) pat_len++;
        while (str_len < FILE_NAME_LEN && str[str_len]) str_len++;
        if (pat_len <= 1) return true;
        int suffix_start = str_len - (pat_len - 1);
        if (suffix_start < 0) return false;
        for (int i = 1; i < pat_len; i++) {
            if (pattern[i] != str[suffix_start + i - 1])
                return false;
        }
        return true;
    }
    for (int i = 0; i < FILE_NAME_LEN; i++) {
        if (pattern[i] == '\0' && str[i] == '\0') return true;
        if (pattern[i] != str[i] && pattern[i] != '?') return false;
    }
    return false;
}

// 获取文件名的辅助函数
static __always_inline char *get_file_name(struct file *fp) {
    struct dentry *dentry = BPF_CORE_READ(fp, f_path.dentry);
    if (!dentry) return NULL;
    return (char *)BPF_CORE_READ(dentry, d_name.name);
}

SEC("fentry/{FUNC_NAME}")
int BPF_PROG({FUNC_NAME}_entry, struct kiocb *iocb, struct iov_iter *iter) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;

    if (filter_pid && filter_pid != pid)
        return 0;

    struct start_info info = {};
    info.ts = bpf_ktime_get_ns();
    info.offset = BPF_CORE_READ(iocb, ki_pos);

    // 读取文件名
    struct file *fp = BPF_CORE_READ(iocb, ki_filp);
    char *file_name = get_file_name(fp);
    if (file_name)
        bpf_probe_read_kernel_str(&info.file, sizeof(info.file), file_name);

    // filter_file 过滤（在入口过滤）
    if (filter_file[0] != '\0') {
        if (!match_wildcard(filter_file, info.file))
            return 0;
    }

    bpf_map_update_elem(&starts, &pid_tgid, &info, BPF_ANY);
    return 0;
}

SEC("fexit/{FUNC_NAME}")
int BPF_PROG({FUNC_NAME}_exit, struct kiocb *iocb, struct iov_iter *iter, ssize_t ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct start_info *info = bpf_map_lookup_elem(&starts, &pid_tgid);
    if (!info)
        return 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return 0;

    event->pid = pid_tgid;
    event->time_stamp = bpf_ktime_get_ns();
    event->lat = info->ts ? event->time_stamp - info->ts : 0;
    event->offset = info->offset;
    event->size = ret;  // 负值表示错误码
    bpf_probe_read_kernel_str(&event->file, sizeof(event->file), info->file);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    bpf_map_delete_elem(&starts, &pid_tgid);
    return 0;
}
```

## 常用监控函数

| 函数 | 参数 | 说明 |
|------|------|------|
| `vfs_read` | `struct file *`, `char *`, `size_t`, `loff_t *` | 通用读取 |
| `vfs_write` | `struct file *`, `const char *`, `size_t`, `loff_t *` | 通用写入 |
| `nfs_file_read` | `struct kiocb *`, `struct iov_iter *` | NFS 读取 |
| `nfs_file_write` | `struct kiocb *`, `struct iov_iter *` | NFS 写入 |
| `do_sys_openat2` | `int`, `const char *`, `struct open_how *` | 文件打开 |

## 规范要点
1. 文件名使用 `d_name.name`（不含路径），不是完整路径
2. 偏移量从 `kiocb->ki_pos` 或 `loff_t *` 参数读取
3. 大小在 fexit 中从返回值获取（负值表示错误）
4. 文件名过滤在 fentry 完成，避免不必要的事件生成
