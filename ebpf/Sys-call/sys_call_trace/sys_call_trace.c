//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

volatile __u64 filter_pid;
volatile __u32 filter_syscall_id;
volatile char filter_comm[TASK_COMM_LEN];

struct event {
	u64 pid;
	u32 syscall_id;
	s64 ret;
	u64 duration;
	u64 enter_time_stamp;
	char comm[TASK_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
	__type(value, struct event);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, u64);
} start_times SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 pid = pid_tgid >> 32;
	u32 syscall_id = (u32)ctx->id;

	bpf_printk("[sys_call_trace] sys_enter: pid=%llu, syscall_id=%u, filter_pid=%llu", pid, syscall_id, filter_pid);

	if (filter_pid && filter_pid != pid) {
		bpf_printk("[sys_call_trace] filtered by pid");
		return 0;
	}

	if (filter_syscall_id && filter_syscall_id != syscall_id) {
		bpf_printk("[sys_call_trace] filtered by syscall_id");
		return 0;
	}

	// 检查 filter_comm 过滤条件
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

	u64 enter_ts = bpf_ktime_get_ns();
	bpf_printk("[sys_call_trace] recording start time: pid_tgid=%llu, ts=%llu", pid_tgid, enter_ts);
	bpf_map_update_elem(&start_times, &pid_tgid, &enter_ts, BPF_ANY);

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 pid = pid_tgid >> 32;
	u32 syscall_id = (u32)ctx->id;

	bpf_printk("[sys_call_trace] sys_exit: pid=%llu, syscall_id=%u, ret=%lld", pid, syscall_id, ctx->ret);

	if (filter_pid && filter_pid != pid) {
		bpf_printk("[sys_call_trace] exit filtered by pid");
		return 0;
	}

	if (filter_syscall_id && filter_syscall_id != syscall_id) {
		bpf_printk("[sys_call_trace] exit filtered by syscall_id");
		return 0;
	}

	// 检查 filter_comm 过滤条件
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

	u64 enter_ts = 0;
	u64 *ts = bpf_map_lookup_elem(&start_times, &pid_tgid);
	if (ts) {
		enter_ts = *ts;
		bpf_map_delete_elem(&start_times, &pid_tgid);
		bpf_printk("[sys_call_trace] found start time: pid_tgid=%llu, enter_ts=%llu", pid_tgid, enter_ts);
	} else {
		bpf_printk("[sys_call_trace] no start time found for pid_tgid=%llu", pid_tgid);
	}

	struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!event) {
		bpf_printk("[sys_call_trace] failed to reserve ringbuf space");
		return 0;
	}

	event->pid = pid_tgid;
	event->syscall_id = syscall_id;
	event->ret = ctx->ret;
	u64 exit_ts = bpf_ktime_get_ns();
	if (enter_ts)
		event->duration = exit_ts - enter_ts;
	else
		event->duration = 0;
	event->enter_time_stamp = enter_ts;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	bpf_printk("[sys_call_trace] submitting event: pid=%llu, syscall=%u, duration=%llu",
		   event->pid, event->syscall_id, event->duration);
	bpf_ringbuf_submit(event, 0);
	return 0;
}
