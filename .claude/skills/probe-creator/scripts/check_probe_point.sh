#!/usr/bin/env bash
# 检查探针点可用性
# 用法: check_probe_point.sh <function_name>

set -euo pipefail

FUNC_NAME="${1:-}"

if [[ -z "$FUNC_NAME" ]]; then
    echo "用法: $0 <function_name>" >&2
    echo "示例: $0 nfs_file_read" >&2
    exit 1
fi

echo "=== 检查探针点: $FUNC_NAME ==="

# 1. 检查函数是否在内核符号表中
if grep -qw "$FUNC_NAME" /proc/kallsyms 2>/dev/null; then
    echo "✅ 函数 '$FUNC_NAME' 在内核符号表中"
else
    echo "⚠️  函数 '$FUNC_NAME' 不在 /proc/kallsyms 中"
    echo "   可能原因: 函数被内联、未导出、或内核未配置符号表"
fi

# 2. 检查 fentry 可用性
if sudo grep -qw "$FUNC_NAME" /sys/kernel/debug/tracing/available_filter_functions 2>/dev/null; then
    echo "✅ 函数 '$FUNC_NAME' 支持 fentry/fexit 探针"
    PROBE_TYPE="fentry/fexit"
else
    echo "⚠️  函数 '$FUNC_NAME' 不支持 fentry/fexit"
    echo "   可能原因: 函数被内联、标记为 notrace、或内核未启用 FUNCTION_TRACER"

    # 建议备选方案
    echo ""
    echo "建议备选方案:"
    echo "  1. 使用 kprobe/kretprobe (兼容性更好，但性能略差)"
    echo "  2. 检查 tracepoint 是否可用:"

    # 尝试查找相关的 tracepoint
    TP_DIR="/sys/kernel/debug/tracing/events"
    if [[ -d "$TP_DIR" ]]; then
        MATCHING_TPS=$(find "$TP_DIR" -name "*$FUNC_NAME*" -type d 2>/dev/null | head -5)
        if [[ -n "$MATCHING_TPS" ]]; then
            echo "     找到相关 tracepoint:"
            echo "$MATCHING_TPS" | sed 's|/sys/kernel/debug/tracing/events/||' | sed 's|^|       - |'
        fi
    fi
    exit 1
fi

# 3. 输出建议
ec