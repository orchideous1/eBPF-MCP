# 网络套接字探针模板 (fentry)

## 适用场景
- 追踪网络连接
- 监控 TCP/UDP 流量
- 采集连接元数据

## 核心字段
| 字段 | 类型 | 说明 |
|------|------|------|
| pid | u64 | 进程ID |
| comm | string | 进程名 |
| saddr | u32 | 源IP地址 |
| daddr | u32 | 目的IP地址 |
| sport | u16 | 源端口 |
| dport | u16 | 目的端口 |

## 可选字段
| 字段 | 类型 | 说明 | 适用条件 |
|------|------|------|---------|
| family | u16 | 地址族 (AF_INET/AF_INET6) | 双栈支持 |
| protocol | u8 | 协议类型 | 多协议监控 |

## 内核结构体定义

```c
struct sock_common {
    union {
        struct {
            __be32 skc_daddr;      // 目的IP
            __be32 skc_rcv_saddr;  // 源IP
        };
    };
    union {
        struct {
            __be16 skc_dport;      // 目的端口 (网络字节序)
            __u16 skc_num;         // 源端口 (主机字节序)
        };
    };
    short unsigned int skc_family; // AF_INET = 2
};

struct sock {
    struct sock_common __sk_common;
};
```

## eBPF C 代码模板

```c
//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

// 过滤参数
volatile __u64 filter_pid;
volatile __u16 filter_dport;  // 网络字节序

struct event {
    u64 pid;
    char comm[TASK_COMM_LEN];
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    u16 family;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __type(value, struct event);
} events SEC(".maps");

SEC("fentry/{FUNC_NAME}")
int BPF_PROG({FUNC_NAME}, struct sock *sk) {
    // 只处理 IPv4
    if (sk->__sk_common.skc_family != AF_INET)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;

    if (filter_pid && filter_pid != pid)
        return 0;

    __be16 dport = sk->__sk_common.skc_dport;
    if (filter_dport && filter_dport != dport)
        return 0;

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event)
        return 0;

    event->pid = pid_tgid;
    event->saddr = sk->__sk_common.skc_rcv_saddr;
    event->daddr = sk->__sk_common.skc_daddr;
    event->dport = dport;
    event->sport = bpf_htons(sk->__sk_common.skc_num);
    event->family = sk->__sk_common.skc_family;
    bpf_get_current_comm(&event->comm, TASK_COMM_LEN);

    bpf_ringbuf_submit(event, 0);
    return 0;
}
```

## 常用监控函数

| 函数 | 触发时机 | 说明 |
|------|---------|------|
| `tcp_connect` | TCP 连接发起 | 客户端连接 |
| `tcp_close` | TCP 连接关闭 | 连接生命周期 |
| `tcp_sendmsg` | TCP 发送数据 | 数据流 |
| `tcp_recvmsg` | TCP 接收数据 | 数据流 |
| `udp_sendmsg` | UDP 发送 | 无连接协议 |
| `inet_csk_accept` | TCP 连接接受 | 服务端 |

## 规范要点
1. 使用 `bpf_htons()` / `bpf_ntohs()` 处理端口字节序
2. IP 地址保持网络字节序，Go 端转换
3. 先检查 `skc_family` 过滤不需要的协议
4. 注意：fentry 可以直接读取内核结构体字段
