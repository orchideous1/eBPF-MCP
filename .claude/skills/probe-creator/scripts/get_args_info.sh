#!/usr/bin/env bash
set -euo pipefail

STRUCT_NAME="${1-}"
LINUX_DIR="${LINUX_DIR:-./package/linux-local}"
START_FILE="${START_FILE:-include/linux/fs.h}"
ALLOW_GLOBAL_FALLBACK="${ALLOW_GLOBAL_FALLBACK:-0}"

if [[ -z "$STRUCT_NAME" ]]; then
  echo "Usage: $0 <struct name>" >&2
  exit 1
fi

if [[ ! -d "$LINUX_DIR" ]]; then
  echo "[ERROR] kernel source directory not found: $LINUX_DIR" >&2
  echo "        override with: LINUX_DIR=/path/to/linux $0 $STRUCT_NAME" >&2
  exit 1
fi

python3 - "$LINUX_DIR" "$STRUCT_NAME" "$START_FILE" "$ALLOW_GLOBAL_FALLBACK" <<'PY'
import json
import re
import sys
from pathlib import Path


COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)


def strip_comments(text: str) -> str:
    return re.sub(COMMENT_RE, "", text)


def split_members(block: str):
    parts = []
    depth = 0
    buf = []
    for ch in block:
        if ch in "{" or ch == "(":
            depth += 1
        elif ch in "}" or ch == ")":
            depth -= 1
        if ch == ";" and depth == 0:
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            continue
        buf.append(ch)

    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def normalize_member(raw: str):
    raw = raw.strip()
    if not raw:
        return None

    raw_compact = re.sub(r"\s+", " ", raw)

    # Function pointer member, e.g. void (*fn)(int a)
    func_ptr = re.match(r"(.+?)\(\s*\*\s*(\w+)\s*\)\s*(\(.+\))$", raw_compact)
    if func_ptr:
        type_part = (func_ptr.group(1).strip() + " (*)" + func_ptr.group(3).strip()).strip()
        return {"type": type_part, "name": func_ptr.group(2), "raw": raw_compact}

    # Anonymous nested declarations (union/struct/enum blocks) keep as a synthetic field.
    if re.match(r"^(union|struct|enum)\s*\{", raw_compact):
        return {"type": "(anonymous_block)", "name": "(anonymous)", "raw": raw_compact}

    name_token = raw_compact.split()[-1]

    bitfield_width = None
    if ":" in name_token:
        name_token, _, bitfield_width = name_token.partition(":")
        bitfield_width = bitfield_width.strip()

    name_match = re.match(r"(\*+)?(\w+)(\[.*\])?", name_token)
    type_part = " ".join(raw_compact.split()[:-1]).strip()
    if not name_match:
        return {"type": type_part or "(unknown)", "name": name_token, "raw": raw_compact}

    stars = name_match.group(1) or ""
    name = name_match.group(2)
    array_suffix = name_match.group(3) or ""

    if stars:
        type_part = (type_part + " " + stars).strip()

    result = {
        "type": type_part or "(unknown)",
        "name": name,
        "raw": raw_compact,
    }

    if array_suffix:
        result["array"] = array_suffix
    if bitfield_width:
        result["bitfield"] = bitfield_width

    return result


def iter_source_files(src_root: Path, start_file_rel: str, allow_global_fallback: bool):
    start_file = src_root / start_file_rel
    yielded = set()

    if start_file.exists() and start_file.is_file():
        yielded.add(start_file.resolve())
        yield start_file

    if not allow_global_fallback:
        return

    for path in src_root.rglob("*"):
        if path.suffix not in {".h", ".c"}:
            continue
        try:
            resolved = path.resolve()
        except Exception:
            continue
        if resolved in yielded:
            continue
        yield path


def find_struct_definitions(src_root: Path, struct_name: str, start_file_rel: str, allow_global_fallback: bool):
    matches = []
    pattern = re.compile(rf"\bstruct\s+{re.escape(struct_name)}\b")

    for path in iter_source_files(src_root, start_file_rel, allow_global_fallback):
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue

        cleaned = strip_comments(text)

        for m in pattern.finditer(cleaned):
            brace_idx = m.end()
            while brace_idx < len(cleaned) and cleaned[brace_idx].isspace():
                brace_idx += 1

            while brace_idx < len(cleaned) and cleaned[brace_idx] != "{":
                if cleaned[brace_idx] == ";":
                    brace_idx = None
                    break
                brace_idx += 1

            if brace_idx is None or brace_idx >= len(cleaned) or cleaned[brace_idx] != "{":
                continue

            depth = 0
            end_idx = brace_idx
            while end_idx < len(cleaned):
                ch = cleaned[end_idx]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        break
                end_idx += 1

            if depth != 0:
                continue

            members_block = cleaned[brace_idx + 1 : end_idx]

            line_start = cleaned.rfind("\n", 0, m.start())
            line_start = line_start + 1 if line_start != -1 else 0
            line_no = cleaned.count("\n", 0, line_start) + 1

            definition_raw = cleaned[m.start() : end_idx + 1]
            definition = " ".join(definition_raw.replace("\n", " ").split())

            fields = []
            for member in split_members(members_block):
                normalized = normalize_member(member)
                if normalized:
                    fields.append(normalized)

            matches.append(
                {
                    "file": str(path),
                    "line": line_no,
                    "definition": definition,
                    "fields": fields,
                }
            )

    return matches


def _read_extent_text(file_path: Path, start_line: int, end_line: int) -> str:
    try:
        lines = file_path.read_text(errors="ignore").splitlines()
    except Exception:
        return ""
    start = max(1, start_line)
    end = max(start, end_line)
    block = "\n".join(lines[start - 1 : end])
    return " ".join(block.split())


def find_struct_definitions_with_clang(src_root: Path, struct_name: str, start_file_rel: str):
    try:
        from clang import cindex
    except Exception:
        return []

    entry = src_root / start_file_rel
    if not entry.exists() or not entry.is_file():
        return []

    include_dirs = [
        src_root / "include",
        src_root / "arch" / "x86" / "include",
        src_root / "arch" / "x86" / "include" / "uapi",
        src_root / "include" / "uapi",
    ]
    args = ["-x", "c", "-D__KERNEL__"] + [f"-I{p}" for p in include_dirs if p.exists()]

    try:
        index = cindex.Index.create()
        tu = index.parse(
            str(entry),
            args=args,
            options=(
                cindex.TranslationUnit.PARSE_INCOMPLETE
                | cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES
                | cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
            ),
        )
    except Exception:
        return []

    results = []
    ck = cindex.CursorKind

    def walk(cur):
        if cur.kind == ck.STRUCT_DECL and cur.spelling == struct_name and cur.is_definition():
            loc_file = cur.location.file
            if not loc_file:
                return
            file_path = Path(str(loc_file))
            try:
                # Keep only definitions under the target kernel source tree.
                file_path.resolve().relative_to(src_root.resolve())
            except Exception:
                return

            start_line = cur.extent.start.line
            end_line = cur.extent.end.line
            definition = _read_extent_text(file_path, start_line, end_line)

            fields = []
            for child in cur.get_children():
                if child.kind == ck.FIELD_DECL:
                    fields.append(
                        {
                            "type": child.type.spelling or "(unknown)",
                            "name": child.spelling or "(anonymous)",
                            "raw": f"{child.type.spelling} {child.spelling}".strip(),
                        }
                    )

            results.append(
                {
                    "file": str(file_path),
                    "line": start_line,
                    "definition": definition,
                    "fields": fields,
                    "source": "python-clang",
                }
            )
            return

        for c in cur.get_children():
            walk(c)

    walk(tu.cursor)
    return results


def main():
    if len(sys.argv) != 5:
        print("Usage: get_args_info.py <linux_dir> <struct_name> <start_file> <allow_global_fallback>", file=sys.stderr)
        sys.exit(1)

    src_root = Path(sys.argv[1]).resolve()
    struct_name = sys.argv[2]
    start_file_rel = sys.argv[3]
    allow_global_fallback = sys.argv[4] == "1"

    results = find_struct_definitions(src_root, struct_name, start_file_rel, allow_global_fallback)
    if not results:
        results = find_struct_definitions_with_clang(src_root, struct_name, start_file_rel)

    if not results:
        print(
            f"[ERROR] struct '{struct_name}' not found from {src_root / start_file_rel}",
            file=sys.stderr,
        )
        if not allow_global_fallback:
            print(
                "        hint: set ALLOW_GLOBAL_FALLBACK=1 to search entire kernel tree",
                file=sys.stderr,
            )
        print(
            "        hint: install python-clang/libclang to enable AST fallback",
            file=sys.stderr,
        )
        sys.exit(1)

    # Return the first match in current search order; default order starts at include/linux/fs.h.
    results.sort(key=lambda item: (item["file"], item["line"]))
    print(json.dumps(results[:1], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
PY