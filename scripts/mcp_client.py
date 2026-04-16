#!/usr/bin/env python3
"""模拟 MCP 客户端向 MCP 服务器发送工具请求的简单脚本。"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def send_jsonrpc(url: str, token: str, session_id: str | None, payload: dict) -> dict:
    """发送 JSON-RPC 请求并返回解析后的响应。"""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            **({"Mcp-Session-Id": session_id} if session_id else {}),
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            if not body:
                return {}
            return json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        raise RuntimeError(f"HTTP {e.code}: {body or e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"请求失败: {e.reason}") from e


def init_session(url: str, token: str) -> str:
    """初始化 MCP HTTP session，返回 Mcp-Session-Id。"""
    payload = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "mcp-client-script", "version": "1.0.0"},
        },
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            session_id = resp.headers.get("Mcp-Session-Id")
            if not session_id:
                raise RuntimeError("服务器响应中缺少 Mcp-Session-Id")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        raise RuntimeError(f"initialize 失败 HTTP {e.code}: {body or e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"initialize 请求失败: {e.reason}") from e

    # 发送 notifications/initialized 通知
    notify_payload = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }
    notify_data = json.dumps(notify_payload).encode("utf-8")
    notify_req = urllib.request.Request(
        url,
        data=notify_data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "Mcp-Session-Id": session_id,
        },
    )
    try:
        with urllib.request.urlopen(notify_req) as resp:
            # 202 Accepted 表示成功
            if resp.status not in (202, 200):
                body = resp.read().decode("utf-8")
                raise RuntimeError(f"initialized 通知失败 HTTP {resp.status}: {body}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        raise RuntimeError(f"initialized 通知失败 HTTP {e.code}: {body or e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"initialized 通知请求失败: {e.reason}") from e

    return session_id


def call_tool(url: str, token: str, session_id: str, tool_name: str, arguments: dict) -> dict:
    """调用 MCP 工具并返回响应。"""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    return send_jsonrpc(url, token, session_id, payload)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="模拟 MCP 客户端发送工具请求",
    )
    parser.add_argument("tool_name", help="工具名称，例如 probe_resource_info")
    parser.add_argument(
        "--args", "-a",
        default="{}",
        help="工具参数的 JSON 字符串，例如 '{\"probeName\":\"nfs_file_read\"}'",
    )
    parser.add_argument(
        "--url", "-u",
        default=os.environ.get("MCP_URL", "http://localhost:8080"),
        help="MCP 服务器地址（默认: http://localhost:8080，也可通过 MCP_URL 环境变量设置）",
    )
    parser.add_argument(
        "--token", "-t",
        default="2508247188",
        help="Bearer Token（也可通过 MCP_AUTH_TOKEN 环境变量设置）",
    )
    args = parser.parse_args()

    if not args.token:
        print("错误: 缺少认证 token，请使用 --token 或设置 MCP_AUTH_TOKEN 环境变量", file=sys.stderr)
        return 1

    try:
        tool_args = json.loads(args.args)
    except json.JSONDecodeError as e:
        print(f"错误: 无法解析工具参数 JSON: {e}", file=sys.stderr)
        return 1

    if not isinstance(tool_args, dict):
        print("错误: --args 必须是 JSON 对象", file=sys.stderr)
        return 1

    try:
        session_id = init_session(args.url, args.token)
        result = call_tool(args.url, args.token, session_id, args.tool_name, tool_args)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except RuntimeError as e:
        print(f"错误: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
