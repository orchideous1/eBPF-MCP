#!/usr/bin/env python3
"""
系统调用数据可视化分析脚本

用于从 DuckDB 数据库中读取 sys_call_trace 表数据，
生成多种可视化图表用于系统调用性能分析。

依赖:
    pip install duckdb pandas matplotlib seaborn numpy

使用示例:
    python visualize.py --db-path database/ebpf-mcp.duckdb --output-dir ./analysis
    python visualize.py --db-path database/ebpf-mcp.duckdb --output-dir ./analysis --pid 1234
    python visualize.py --db-path database/ebpf-mcp.duckdb --output-dir ./analysis --time-range "1m"
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import duckdb
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

# 设置中文字体支持
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial Unicode MS', 'SimHei']
plt.rcParams['axes.unicode_minus'] = False

# 系统调用号对照表（x86_64）- 与 resource/unistd.h 保持一致
# 来源: Linux kernel uapi headers (uapi/asm-generic/unistd.h)
SYSCALL_NAMES = {
    # 0-100
    0: 'io_setup',
    1: 'io_destroy',
    2: 'io_submit',
    3: 'io_cancel',
    4: 'io_getevents',
    5: 'setxattr',
    6: 'lsetxattr',
    7: 'fsetxattr',
    8: 'getxattr',
    9: 'lgetxattr',
    10: 'fgetxattr',
    11: 'listxattr',
    12: 'llistxattr',
    13: 'flistxattr',
    14: 'removexattr',
    15: 'lremovexattr',
    16: 'fremovexattr',
    17: 'getcwd',
    18: 'lookup_dcookie',
    19: 'eventfd2',
    20: 'epoll_create1',
    21: 'epoll_ctl',
    22: 'epoll_pwait',
    23: 'dup',
    24: 'dup3',
    25: 'fcntl',
    26: 'inotify_init1',
    27: 'inotify_add_watch',
    28: 'inotify_rm_watch',
    29: 'ioctl',
    30: 'ioprio_set',
    31: 'ioprio_get',
    32: 'flock',
    33: 'mknodat',
    34: 'mkdirat',
    35: 'unlinkat',
    36: 'symlinkat',
    37: 'linkat',
    38: 'renameat',
    39: 'umount2',
    40: 'mount',
    41: 'pivot_root',
    42: 'nfsservctl',
    43: 'statfs',
    44: 'fstatfs',
    45: 'truncate',
    46: 'ftruncate',
    47: 'fallocate',
    48: 'faccessat',
    49: 'chdir',
    50: 'fchdir',
    51: 'chroot',
    52: 'fchmod',
    53: 'fchmodat',
    54: 'fchownat',
    55: 'fchown',
    56: 'openat',
    57: 'close',
    58: 'vhangup',
    59: 'pipe2',
    60: 'quotactl',
    61: 'getdents64',
    62: 'lseek',
    63: 'read',
    64: 'write',
    65: 'readv',
    66: 'writev',
    67: 'pread64',
    68: 'pwrite64',
    69: 'preadv',
    70: 'pwritev',
    71: 'sendfile',
    72: 'pselect6',
    73: 'ppoll',
    74: 'signalfd4',
    75: 'vmsplice',
    76: 'splice',
    77: 'tee',
    78: 'readlinkat',
    79: 'newfstatat',
    80: 'fstat',
    81: 'sync',
    82: 'fsync',
    83: 'fdatasync',
    84: 'sync_file_range',
    85: 'timerfd_create',
    86: 'timerfd_settime',
    87: 'timerfd_gettime',
    88: 'utimensat',
    89: 'acct',
    90: 'capget',
    91: 'capset',
    92: 'personality',
    93: 'exit',
    94: 'exit_group',
    95: 'waitid',
    96: 'set_tid_address',
    97: 'unshare',
    98: 'futex',
    99: 'set_robust_list',
    100: 'get_robust_list',
    # 101-200
    101: 'nanosleep',
    102: 'getitimer',
    103: 'setitimer',
    104: 'kexec_load',
    105: 'init_module',
    106: 'delete_module',
    107: 'timer_create',
    108: 'timer_gettime',
    109: 'timer_getoverrun',
    110: 'timer_settime',
    111: 'timer_delete',
    112: 'clock_settime',
    113: 'clock_gettime',
    114: 'clock_getres',
    115: 'clock_nanosleep',
    116: 'syslog',
    117: 'ptrace',
    118: 'sched_setparam',
    119: 'sched_setscheduler',
    120: 'sched_getscheduler',
    121: 'sched_getparam',
    122: 'sched_setaffinity',
    123: 'sched_getaffinity',
    124: 'sched_yield',
    125: 'sched_get_priority_max',
    126: 'sched_get_priority_min',
    127: 'sched_rr_get_interval',
    128: 'restart_syscall',
    129: 'kill',
    130: 'tkill',
    131: 'tgkill',
    132: 'sigaltstack',
    133: 'rt_sigsuspend',
    134: 'rt_sigaction',
    135: 'rt_sigprocmask',
    136: 'rt_sigpending',
    137: 'rt_sigtimedwait',
    138: 'rt_sigqueueinfo',
    139: 'rt_sigreturn',
    140: 'setpriority',
    141: 'getpriority',
    142: 'reboot',
    143: 'setregid',
    144: 'setgid',
    145: 'setreuid',
    146: 'setuid',
    147: 'setresuid',
    148: 'getresuid',
    149: 'setresgid',
    150: 'getresgid',
    151: 'setfsuid',
    152: 'setfsgid',
    153: 'times',
    154: 'setpgid',
    155: 'getpgid',
    156: 'getsid',
    157: 'setsid',
    158: 'getgroups',
    159: 'setgroups',
    160: 'uname',
    161: 'sethostname',
    162: 'setdomainname',
    163: 'getrlimit',
    164: 'setrlimit',
    165: 'getrusage',
    166: 'umask',
    167: 'prctl',
    168: 'getcpu',
    169: 'gettimeofday',
    170: 'settimeofday',
    171: 'adjtimex',
    172: 'getpid',
    173: 'getppid',
    174: 'getuid',
    175: 'geteuid',
    176: 'getgid',
    177: 'getegid',
    178: 'gettid',
    179: 'sysinfo',
    180: 'mq_open',
    181: 'mq_unlink',
    182: 'mq_timedsend',
    183: 'mq_timedreceive',
    184: 'mq_notify',
    185: 'mq_getsetattr',
    186: 'msgget',
    187: 'msgctl',
    188: 'msgrcv',
    189: 'msgsnd',
    190: 'semget',
    191: 'semctl',
    192: 'semtimedop',
    193: 'semop',
    194: 'shmget',
    195: 'shmctl',
    196: 'shmat',
    197: 'shmdt',
    198: 'socket',
    199: 'socketpair',
    200: 'bind',
    # 201-300
    201: 'listen',
    202: 'accept',
    203: 'connect',
    204: 'getsockname',
    205: 'getpeername',
    206: 'sendto',
    207: 'recvfrom',
    208: 'setsockopt',
    209: 'getsockopt',
    210: 'shutdown',
    211: 'sendmsg',
    212: 'recvmsg',
    213: 'readahead',
    214: 'brk',
    215: 'munmap',
    216: 'mremap',
    217: 'add_key',
    218: 'request_key',
    219: 'keyctl',
    220: 'clone',
    221: 'execve',
    222: 'mmap',
    223: 'fadvise64',
    224: 'swapon',
    225: 'swapoff',
    226: 'mprotect',
    227: 'msync',
    228: 'mlock',
    229: 'munlock',
    230: 'mlockall',
    231: 'munlockall',
    232: 'mincore',
    233: 'madvise',
    234: 'remap_file_pages',
    235: 'mbind',
    236: 'get_mempolicy',
    237: 'set_mempolicy',
    238: 'migrate_pages',
    239: 'move_pages',
    240: 'rt_tgsigqueueinfo',
    241: 'perf_event_open',
    242: 'accept4',
    243: 'recvmmsg',
    244: 'arch_specific_syscall',
    260: 'wait4',
    261: 'prlimit64',
    262: 'fanotify_init',
    263: 'fanotify_mark',
    264: 'name_to_handle_at',
    265: 'open_by_handle_at',
    266: 'clock_adjtime',
    267: 'syncfs',
    268: 'setns',
    269: 'sendmmsg',
    270: 'process_vm_readv',
    271: 'process_vm_writev',
    272: 'kcmp',
    273: 'finit_module',
    274: 'sched_setattr',
    275: 'sched_getattr',
    276: 'renameat2',
    277: 'seccomp',
    278: 'getrandom',
    279: 'memfd_create',
    280: 'bpf',
    281: 'execveat',
    282: 'userfaultfd',
    283: 'membarrier',
    284: 'mlock2',
    285: 'copy_file_range',
    286: 'preadv2',
    287: 'pwritev2',
    288: 'pkey_mprotect',
    289: 'pkey_alloc',
    290: 'pkey_free',
    291: 'statx',
    292: 'io_pgetevents',
    293: 'rseq',
    294: 'kexec_file_load',
    # 400+
    403: 'clock_gettime64',
    404: 'clock_settime64',
    405: 'clock_adjtime64',
    406: 'clock_getres_time64',
    407: 'clock_nanosleep_time64',
    408: 'timer_gettime64',
    409: 'timer_settime64',
    410: 'timerfd_gettime64',
    411: 'timerfd_settime64',
    412: 'utimensat_time64',
    413: 'pselect6_time64',
    414: 'ppoll_time64',
    416: 'io_pgetevents_time64',
    417: 'recvmmsg_time64',
    418: 'mq_timedsend_time64',
    419: 'mq_timedreceive_time64',
    420: 'semtimedop_time64',
    421: 'rt_sigtimedwait_time64',
    422: 'futex_time64',
    423: 'sched_rr_get_interval_time64',
    424: 'pidfd_send_signal',
    425: 'io_uring_setup',
    426: 'io_uring_enter',
    427: 'io_uring_register',
    428: 'open_tree',
    429: 'move_mount',
    430: 'fsopen',
    431: 'fsconfig',
    432: 'fsmount',
    433: 'fspick',
    434: 'pidfd_open',
    435: 'clone3',
    436: 'close_range',
    437: 'openat2',
    438: 'pidfd_getfd',
    439: 'faccessat2',
    440: 'process_madvise',
    441: 'epoll_pwait2',
    442: 'mount_setattr',
    443: 'quotactl_fd',
    444: 'landlock_create_ruleset',
    445: 'landlock_add_rule',
    446: 'landlock_restrict_self',
    447: 'memfd_secret',
    448: 'process_mrelease',
    449: 'futex_waitv',
    450: 'set_mempolicy_home_node',
    451: 'cachestat',
    452: 'fchmodat2',
    453: 'map_shadow_stack',
    454: 'futex_wake',
    455: 'futex_wait',
    456: 'futex_requeue',
    457: 'statmount',
    458: 'listmount',
    459: 'lsm_get_self_attr',
    460: 'lsm_set_self_attr',
    461: 'lsm_list_modules',
}

# resource/unistd.h 文件路径（相对路径）
UNISTD_H_PATH = Path(__file__).parent.parent / 'resource' / 'unistd.h'


def get_syscall_name(syscall_id: int) -> str:
    """获取系统调用名称"""
    return SYSCALL_NAMES.get(syscall_id, f'syscall_{syscall_id}')


class SyscallAnalyzer:
    """系统调用数据可视化分析器"""

    def __init__(self, db_path: str, output_dir: str):
        """
        初始化分析器

        Args:
            db_path: DuckDB 数据库路径
            output_dir: 输出目录
        """
        self.db_path = db_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.conn = None
        self.df = None

    def connect(self) -> bool:
        """连接数据库"""
        try:
            self.conn = duckdb.connect(self.db_path, read_only=True)
            print(f"[OK] 已连接数据库: {self.db_path}")
            return True
        except Exception as e:
            print(f"[ERROR] 连接数据库失败: {e}")
            return False

    def load_data(self, pid: Optional[int] = None, time_range: Optional[str] = None) -> bool:
        """
        加载系统调用数据

        Args:
            pid: 过滤特定进程ID
            time_range: 时间范围（如 "1m", "5m", "1h"）
        """
        if not self.conn:
            print("[ERROR] 数据库未连接")
            return False

        try:
            # 检查表是否存在
            result = self.conn.execute(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'sys_call_trace'"
            ).fetchone()
            if result[0] == 0:
                print("[ERROR] sys_call_trace 表不存在")
                return False

            # 构建查询条件
            conditions = []
            if pid:
                conditions.append(f"(pid & 0xFFFFFFFF) = {pid}")

            if time_range:
                # 解析时间范围
                if time_range.endswith('s'):
                    seconds = int(time_range[:-1])
                elif time_range.endswith('m'):
                    seconds = int(time_range[:-1]) * 60
                elif time_range.endswith('h'):
                    seconds = int(time_range[:-1]) * 3600
                else:
                    seconds = int(time_range)

                # 获取最新时间戳
                max_ts = self.conn.execute(
                    "SELECT MAX(enter_time_stamp) FROM sys_call_trace"
                ).fetchone()[0]
                if max_ts:
                    cutoff_ns = max_ts - (seconds * 1_000_000_000)
                    conditions.append(f"enter_time_stamp >= {cutoff_ns}")

            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

            # 加载数据
            query = f"""
                SELECT
                    (pid & 0xFFFFFFFF)::UINTEGER as process_id,
                    comm as process_name,
                    syscall_id,
                    ret,
                    duration,
                    enter_time_stamp,
                    (enter_time_stamp / 1000000000.0) as timestamp_sec
                FROM sys_call_trace
                {where_clause}
            """

            self.df = self.conn.execute(query).fetchdf()

            # 添加系统调用名称
            self.df['syscall_name'] = self.df['syscall_id'].apply(get_syscall_name)

            # 转换延迟为毫秒
            self.df['duration_ms'] = self.df['duration'] / 1_000_000.0

            print(f"[OK] 加载数据: {len(self.df)} 条记录")
            print(f"[INFO] 时间范围: {self.df['timestamp_sec'].min():.2f} - {self.df['timestamp_sec'].max():.2f} 秒")
            print(f"[INFO] 进程数: {self.df['process_id'].nunique()}")
            print(f"[INFO] 系统调用类型数: {self.df['syscall_id'].nunique()}")

            return True

        except Exception as e:
            print(f"[ERROR] 加载数据失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    def plot_syscall_frequency(self) -> str:
        """绘制系统调用频率分布图"""
        if self.df is None or len(self.df) == 0:
            return None

        try:
            # 统计频率
            freq = self.df['syscall_name'].value_counts().head(20)

            fig, ax = plt.subplots(figsize=(12, 8))
            colors = plt.cm.viridis(np.linspace(0, 1, len(freq)))
            bars = ax.barh(range(len(freq)), freq.values, color=colors)

            # 设置标签
            ax.set_yticks(range(len(freq)))
            ax.set_yticklabels(freq.index)
            ax.invert_yaxis()
            ax.set_xlabel('Call Count', fontsize=12)
            ax.set_ylabel('Syscall Name', fontsize=12)
            ax.set_title('Top 20 System Calls by Frequency', fontsize=14, fontweight='bold')

            # 添加数值标签
            for i, (bar, val) in enumerate(zip(bars, freq.values)):
                ax.text(val + max(freq.values) * 0.01, i, f'{val:,}',
                       va='center', fontsize=9)

            plt.tight_layout()
            output_path = self.output_dir / 'syscall_frequency.png'
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()

            print(f"[OK] 生成图表: {output_path}")
            return str(output_path)

        except Exception as e:
            print(f"[ERROR] 生成频率图失败: {e}")
            return None

    def plot_latency_distribution(self) -> str:
        """绘制延迟分布直方图"""
        if self.df is None or len(self.df) == 0:
            return None

        try:
            # 过滤异常值（超过99.9百分位的）
            p99_9 = self.df['duration_ms'].quantile(0.999)
            filtered_df = self.df[self.df['duration_ms'] <= p99_9]

            fig, axes = plt.subplots(1, 2, figsize=(14, 5))

            # 线性刻度
            ax1 = axes[0]
            ax1.hist(filtered_df['duration_ms'], bins=50, color='steelblue', edgecolor='white', alpha=0.7)
            ax1.set_xlabel('Duration (ms)', fontsize=11)
            ax1.set_ylabel('Count', fontsize=11)
            ax1.set_title('Latency Distribution (Linear)', fontsize=12, fontweight='bold')
            ax1.axvline(filtered_df['duration_ms'].median(), color='red', linestyle='--',
                       label=f"Median: {filtered_df['duration_ms'].median():.3f}ms")
            ax1.legend()

            # 对数刻度
            ax2 = axes[1]
            ax2.hist(filtered_df['duration_ms'], bins=50, color='darkgreen', edgecolor='white', alpha=0.7)
            ax2.set_xlabel('Duration (ms)', fontsize=11)
            ax2.set_ylabel('Count', fontsize=11)
            ax2.set_title('Latency Distribution (Log Scale)', fontsize=12, fontweight='bold')
            ax2.set_yscale('log')
            ax2.axvline(filtered_df['duration_ms'].median(), color='red', linestyle='--',
                       label=f"Median: {filtered_df['duration_ms'].median():.3f}ms")
            ax2.legend()

            plt.tight_layout()
            output_path = self.output_dir / 'syscall_latency_distribution.png'
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()

            print(f"[OK] 生成图表: {output_path}")
            return str(output_path)

        except Exception as e:
            print(f"[ERROR] 生成延迟分布图失败: {e}")
            return None

    def plot_syscall_heatmap(self) -> str:
        """绘制进程-系统调用热力图"""
        if self.df is None or len(self.df) == 0:
            return None

        try:
            # 获取Top进程和Top系统调用
            top_processes = self.df['process_name'].value_counts().head(15).index
            top_syscalls = self.df['syscall_name'].value_counts().head(15).index

            # 构建热力矩阵
            heatmap_data = self.df[
                self.df['process_name'].isin(top_processes) &
                self.df['syscall_name'].isin(top_syscalls)
            ].groupby(['process_name', 'syscall_name']).size().unstack(fill_value=0)

            if heatmap_data.empty:
                print("[WARN] 热力图数据为空")
                return None

            fig, ax = plt.subplots(figsize=(14, 10))

            # 使用对数颜色映射
            sns.heatmap(heatmap_data, annot=True, fmt='d', cmap='YlOrRd',
                       linewidths=0.5, ax=ax, cbar_kws={'label': 'Call Count'})

            ax.set_xlabel('System Call', fontsize=11)
            ax.set_ylabel('Process Name', fontsize=11)
            ax.set_title('Process vs Syscall Heatmap (Top 15)', fontsize=13, fontweight='bold')
            plt.xticks(rotation=45, ha='right')
            plt.yticks(rotation=0)

            plt.tight_layout()
            output_path = self.output_dir / 'syscall_heatmap.png'
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()

            print(f"[OK] 生成图表: {output_path}")
            return str(output_path)

        except Exception as e:
            print(f"[ERROR] 生成热力图失败: {e}")
            return None

    def plot_syscall_timeline(self) -> str:
        """绘制系统调用时间线"""
        if self.df is None or len(self.df) == 0:
            return None

        try:
            # 按秒聚合
            timeline = self.df.groupby(
                (self.df['timestamp_sec']).astype(int)
            ).agg({
                'duration_ms': ['count', 'mean'],
                'process_id': 'nunique'
            }).reset_index()

            timeline.columns = ['second', 'call_count', 'avg_latency_ms', 'unique_processes']

            fig, axes = plt.subplots(2, 1, figsize=(14, 10), sharex=True)

            # 调用数时间线
            ax1 = axes[0]
            ax1.plot(timeline['second'], timeline['call_count'], color='steelblue', linewidth=1.5)
            ax1.fill_between(timeline['second'], timeline['call_count'], alpha=0.3, color='steelblue')
            ax1.set_ylabel('Calls/sec', fontsize=11)
            ax1.set_title('System Call Timeline', fontsize=13, fontweight='bold')
            ax1.grid(True, alpha=0.3)

            # 平均延迟时间线
            ax2 = axes[1]
            ax2.plot(timeline['second'], timeline['avg_latency_ms'], color='darkgreen', linewidth=1.5)
            ax2.fill_between(timeline['second'], timeline['avg_latency_ms'], alpha=0.3, color='darkgreen')
            ax2.set_xlabel('Time (seconds since boot)', fontsize=11)
            ax2.set_ylabel('Avg Latency (ms)', fontsize=11)
            ax2.grid(True, alpha=0.3)

            plt.tight_layout()
            output_path = self.output_dir / 'syscall_timeline.png'
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()

            print(f"[OK] 生成图表: {output_path}")
            return str(output_path)

        except Exception as e:
            print(f"[ERROR] 生成时间线图失败: {e}")
            return None

    def plot_latency_by_syscall(self) -> str:
        """绘制各系统调用延迟箱线图"""
        if self.df is None or len(self.df) == 0:
            return None

        try:
            # 获取Top系统调用
            top_syscalls = self.df['syscall_name'].value_counts().head(15).index
            filtered_df = self.df[self.df['syscall_name'].isin(top_syscalls)]

            # 过滤极端异常值
            q99 = filtered_df['duration_ms'].quantile(0.99)
            filtered_df = filtered_df[filtered_df['duration_ms'] <= q99]

            fig, ax = plt.subplots(figsize=(14, 8))

            # 准备数据
            syscall_order = filtered_df.groupby('syscall_name')['duration_ms'].median().sort_values(ascending=False).index

            sns.boxplot(data=filtered_df, x='syscall_name', y='duration_ms',
                       order=syscall_order, ax=ax, palette='Set2')

            ax.set_xlabel('System Call', fontsize=11)
            ax.set_ylabel('Duration (ms)', fontsize=11)
            ax.set_title('Latency Distribution by System Call (P99 Filtered)', fontsize=13, fontweight='bold')
            plt.xticks(rotation=45, ha='right')
            ax.set_yscale('log')

            plt.tight_layout()
            output_path = self.output_dir / 'syscall_latency_by_type.png'
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()

            print(f"[OK] 生成图表: {output_path}")
            return str(output_path)

        except Exception as e:
            print(f"[ERROR] 生成延迟箱线图失败: {e}")
            return None

    def plot_top_slow_calls(self) -> str:
        """绘制最慢的系统调用散点图"""
        if self.df is None or len(self.df) == 0:
            return None

        try:
            # 获取Top 100最慢的调用
            slowest = self.df.nlargest(100, 'duration_ms')

            fig, ax = plt.subplots(figsize=(14, 8))

            # 按系统调用类型着色
            unique_syscalls = slowest['syscall_name'].unique()
            colors = plt.cm.tab10(np.linspace(0, 1, len(unique_syscalls)))
            color_map = dict(zip(unique_syscalls, colors))

            for syscall in unique_syscalls:
                subset = slowest[slowest['syscall_name'] == syscall]
                ax.scatter(subset['timestamp_sec'], subset['duration_ms'],
                          c=[color_map[syscall]], label=syscall, alpha=0.6, s=50)

            ax.set_xlabel('Time (seconds since boot)', fontsize=11)
            ax.set_ylabel('Duration (ms)', fontsize=11)
            ax.set_title('Top 100 Slowest System Calls', fontsize=13, fontweight='bold')
            ax.set_yscale('log')
            ax.legend(loc='upper right', fontsize=8, ncol=2)
            ax.grid(True, alpha=0.3)

            plt.tight_layout()
            output_path = self.output_dir / 'top_slow_calls.png'
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()

            print(f"[OK] 生成图表: {output_path}")
            return str(output_path)

        except Exception as e:
            print(f"[ERROR] 生成慢调用图失败: {e}")
            return None

    def generate_summary(self) -> Dict:
        """生成分析摘要"""
        if self.df is None or len(self.df) == 0:
            return {}

        summary = {
            'total_records': len(self.df),
            'time_range': {
                'start_sec': float(self.df['timestamp_sec'].min()),
                'end_sec': float(self.df['timestamp_sec'].max()),
                'duration_sec': float(self.df['timestamp_sec'].max() - self.df['timestamp_sec'].min())
            },
            'processes': {
                'count': int(self.df['process_id'].nunique()),
                'top_processes': self.df['process_name'].value_counts().head(5).to_dict()
            },
            'syscalls': {
                'unique_count': int(self.df['syscall_id'].nunique()),
                'top_syscalls': self.df['syscall_name'].value_counts().head(10).to_dict()
            },
            'latency': {
                'min_ms': float(self.df['duration_ms'].min()),
                'max_ms': float(self.df['duration_ms'].max()),
                'mean_ms': float(self.df['duration_ms'].mean()),
                'median_ms': float(self.df['duration_ms'].median()),
                'p95_ms': float(self.df['duration_ms'].quantile(0.95)),
                'p99_ms': float(self.df['duration_ms'].quantile(0.99)),
            },
            'errors': {
                'error_count': int((self.df['ret'] < 0).sum()),
                'error_rate': float((self.df['ret'] < 0).mean() * 100)
            }
        }

        return summary

    def save_summary(self) -> str:
        """保存分析摘要到JSON"""
        summary = self.generate_summary()
        if not summary:
            return None

        output_path = self.output_dir / 'syscall_summary.json'
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"[OK] 生成摘要: {output_path}")
        return str(output_path)

    def print_summary(self):
        """打印分析摘要"""
        summary = self.generate_summary()
        if not summary:
            print("[WARN] 无数据可分析")
            return

        print("\n" + "=" * 60)
        print("系统调用分析摘要")
        print("=" * 60)
        print(f"总记录数: {summary['total_records']:,}")
        print(f"时间范围: {summary['time_range']['duration_sec']:.2f} 秒")
        print(f"进程数: {summary['processes']['count']}")
        print(f"系统调用类型: {summary['syscalls']['unique_count']}")

        print("\n延迟统计:")
        print(f"  最小: {summary['latency']['min_ms']:.6f} ms")
        print(f"  平均: {summary['latency']['mean_ms']:.6f} ms")
        print(f"  中位数: {summary['latency']['median_ms']:.6f} ms")
        print(f"  P95: {summary['latency']['p95_ms']:.6f} ms")
        print(f"  P99: {summary['latency']['p99_ms']:.6f} ms")
        print(f"  最大: {summary['latency']['max_ms']:.6f} ms")

        print("\n错误统计:")
        print(f"  错误次数: {summary['errors']['error_count']}")
        print(f"  错误率: {summary['errors']['error_rate']:.4f}%")

        print("\nTop 5 进程:")
        for proc, count in list(summary['processes']['top_processes'].items())[:5]:
            print(f"  {proc}: {count:,} 次")

        print("\nTop 5 系统调用:")
        for syscall, count in list(summary['syscalls']['top_syscalls'].items())[:5]:
            print(f"  {syscall}: {count:,} 次")

        print("=" * 60)

    def run_all_analysis(self) -> List[str]:
        """运行所有分析"""
        outputs = []

        print("\n开始生成可视化分析...\n")

        # 频率分析
        path = self.plot_syscall_frequency()
        if path:
            outputs.append(path)

        # 延迟分布
        path = self.plot_latency_distribution()
        if path:
            outputs.append(path)

        # 热力图
        path = self.plot_syscall_heatmap()
        if path:
            outputs.append(path)

        # 时间线
        path = self.plot_syscall_timeline()
        if path:
            outputs.append(path)

        # 延迟箱线图
        path = self.plot_latency_by_syscall()
        if path:
            outputs.append(path)

        # 慢调用散点图
        path = self.plot_top_slow_calls()
        if path:
            outputs.append(path)

        # 保存摘要
        path = self.save_summary()
        if path:
            outputs.append(path)

        # 打印摘要
        self.print_summary()

        print(f"\n[OK] 分析完成！共生成 {len(outputs)} 个输出文件")
        print(f"[INFO] 输出目录: {self.output_dir}")

        return outputs

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
            print("[OK] 数据库连接已关闭")


def main():
    parser = argparse.ArgumentParser(
        description='系统调用数据可视化分析工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
    # 分析全部数据
    python visualize.py --db-path database/ebpf-mcp.duckdb --output-dir ./analysis

    # 分析特定进程
    python visualize.py --db-path database/ebpf-mcp.duckdb --output-dir ./analysis --pid 1234

    # 分析最近5分钟的数据
    python visualize.py --db-path database/ebpf-mcp.duckdb --output-dir ./analysis --time-range 5m
        """
    )

    parser.add_argument('--db-path', required=True,
                       help='DuckDB 数据库文件路径')
    parser.add_argument('--output-dir', required=True,
                       help='输出目录路径')
    parser.add_argument('--pid', type=int, default=None,
                       help='仅分析指定进程ID')
    parser.add_argument('--time-range', type=str, default=None,
                       help='时间范围（如 1m, 5m, 1h）')

    args = parser.parse_args()

    # 创建分析器
    analyzer = SyscallAnalyzer(args.db_path, args.output_dir)

    # 连接数据库
    if not analyzer.connect():
        sys.exit(1)

    # 加载数据
    if not analyzer.load_data(pid=args.pid, time_range=args.time_range):
        analyzer.close()
        sys.exit(1)

    # 运行分析
    analyzer.run_all_analysis()

    # 关闭连接
    analyzer.close()


if __name__ == '__main__':
    main()
