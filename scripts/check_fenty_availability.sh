#!/bin/bash

FUNC_NAME=$1

if [ -z "$FUNC_NAME" ]; then
    echo "Usage: $0 <function_name>"
    exit 1
fi

echo "checking $1"

# 1. 检查内核配置
# if ! grep -q "CONFIG_FUNCTION_TRACER=y" /boot/config-$(uname -r) 2>/dev/null; then
#     if ! zgrep -q "CONFIG_FUNCTION_TRACER=y" /proc/config.gz 2>/dev/null; then
#         echo "❌ 错误: 当前内核未开启 CONFIG_FUNCTION_TRACER，不支持 fentry。"
#         exit 1
#     fi
# fi

# 2. 检查 available_filter_functions
if sudo grep -qw "$FUNC_NAME" /sys/kernel/debug/tracing/available_filter_functions 2>/dev/null; then
    echo "✅ 函数 '$FUNC_NAME' 支持 fentry/fexit。"
else
    echo "❌ 函数 '$FUNC_NAME' 不在 available_filter_functions 列表中。"
    echo "   可能原因：函数被内联、标记为 notrace、或名称不匹配。"
    echo "   提示：尝试使用 'bpf_trace_printk' 或 kprobe 作为备选方案。"
fi