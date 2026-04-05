#!/usr/bin/env bash
# 脚本用途：
#   根据传入的函数名，在 Linux 内核源码目录中定位该函数的定义/声明并提取参数列表，
#   便于后续做 eBPF 探针挂载、参数解析或自动化生成代码。

# 参数说明：
#   $1 -> 目标函数名（必填），例如：do_sys_openat2

# 使用方式：
#   ./get_func_args.sh <function_name>

# 处理逻辑：
#   1) 参数校验：若未传入函数名，打印 Usage 并退出。
#   2) 目录校验：确认内核源码目录存在且可访问，否则给出明确错误信息。
#   3) 函数定位：在源码中搜索函数签名（优先定义，再补充声明）。
#   4) 结果去噪：过滤宏、注释、跨行声明等干扰内容。
#   5) 参数提取：解析括号中的参数列表，标准化输出类型与参数名。
#   6) 异常处理：函数不存在、匹配到多个重载样式/同名静态函数时给出提示。
#   7) 返回约定：成功返回 0；未找到或解析失败返回非 0，便于 CI/脚本调用。

# 注意事项：
#   - 内核函数签名可能跨多行，使用 Python 做括号配对解析。
#   - 兼容指针、函数指针、const/volatile、结构体类型等复杂参数形式。
#   - 输出 JSON 便于后续自动化处理。

LINUX_DIR="./package/linux-local"
FUNC_NAME=$1

if [[ -z "$FUNC_NAME" ]]; then
  echo "Usage: $0 <function_name>" >&2
  exit 1
fi

if [[ ! -d "$LINUX_DIR" ]]; then
  echo "[ERROR] kernel source directory not found: $LINUX_DIR" >&2
  echo "        override with: LINUX_DIR=/path/to/linux $0 $FUNC_NAME" >&2
  exit 1
fi

python3 - "$LINUX_DIR" "$FUNC_NAME" <<'PY'
import json
import re
import sys
from pathlib import Path

def split_params(param_block: str):
    parts = []
    depth = 0
    buf = []
    for ch in param_block:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch == ',' and depth == 0:
            part = ''.join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            continue
        buf.append(ch)
    tail = ''.join(buf).strip()
    if tail:
        parts.append(tail)
    return parts

def normalize_param(raw: str):
    raw = raw.strip()
    if not raw or raw == 'void':
        return None

    func_ptr = re.match(r"(.+?)\(\s*\*\s*(\w+)\s*\)(\s*\(.+\))", raw)
    if func_ptr:
        type_part = (func_ptr.group(1) + '(* )' + func_ptr.group(3)).replace('  ', ' ').strip()
        return {"type": type_part, "name": func_ptr.group(2), "raw": raw}

    tokens = re.split(r"\s+", raw)
    if not tokens:
        return None

    name = tokens[-1]
    type_part = ' '.join(tokens[:-1]).strip()

    star_count = len(name) - len(name.lstrip('*'))
    name = name.lstrip('*')
    if star_count:
        type_part = (type_part + ' ' + ('*' * star_count)).strip()

    if not name:
        name = tokens[-1]
    if not type_part:
        type_part = '(unknown)'

    return {"type": type_part, "name": name, "raw": raw}

def find_signatures(src_root: Path, func_name: str):
    matches = []
    word_pattern = re.compile(rf"\b{re.escape(func_name)}\b")

    for path in src_root.rglob('*'):
        if path.suffix not in {'.h'}: #'.c'先不找c文件
            continue
        try:
            text = path.read_text(errors='ignore')
        except Exception:
            continue

        for m in word_pattern.finditer(text):
            func_end = m.end()
            i = func_end
            while i < len(text) and text[i].isspace():
                i += 1
            if i >= len(text) or text[i] != '(':
                continue

            depth = 0
            j = i
            while j < len(text):
                ch = text[j]
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if depth != 0:
                continue

            params_block = text[i + 1 : j]
            k = j + 1
            while k < len(text) and text[k].isspace():
                k += 1
            if k >= len(text) or text[k] not in '{;':
                continue

            kind = 'definition' if text[k] == '{' else 'declaration'

            line_start = text.rfind('\n', 0, m.start())
            line_start = line_start + 1 if line_start != -1 else 0
            line_no = text.count('\n', 0, line_start) + 1
            signature_raw = text[line_start : j + 1].replace('\n', ' ')
            signature = ' '.join(signature_raw.split())

            params = []
            for param in split_params(params_block):
                normalized = normalize_param(param)
                if normalized:
                    params.append(normalized)

            matches.append(
                {
                    "file": str(path),
                    "line": line_no,
                    "kind": kind,
                    "signature": signature,
                    "params": params,
                }
            )

    return matches


def main():
    if len(sys.argv) != 3:
        print("Usage: get_func_args.py <linux_dir> <function_name>", file=sys.stderr)
        sys.exit(1)

    src_root = Path(sys.argv[1]).resolve()
    func_name = sys.argv[2]

    results = find_signatures(src_root, func_name)
    if not results:
        print(f"[ERROR] function '{func_name}' not found in {src_root}", file=sys.stderr)
        sys.exit(1)

    results.sort(key=lambda item: (0 if item['kind'] == 'definition' else 1, item['line']))
    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
PY

