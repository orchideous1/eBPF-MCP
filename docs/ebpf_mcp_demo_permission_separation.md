# ebpf-mcp-demo 权限分离技巧总结

## 1. 技巧点-将内核特权收敛到服务进程（而非客户端）
证据代码片段：

来源：package/ebpf-mcp-demo/install.sh:196
```bash
[Service]
Type=simple
User=root
Group=root
ExecStart=${INSTALL_DIR}/${BINARY_NAME} ${exec_opts}
```

来源：package/ebpf-mcp-demo/internal/ebpf/load_program.go:128
```go
coll, err := ebpf.NewCollection(spec)
if err != nil {
    return &LoadProgramResult{Success: false, ErrorMessage: err.Error()}, err
}
```

说明：客户端不直接执行 eBPF 系统调用，真正触达内核加载逻辑的是服务端进程。

## 2. 技巧点-在协议入口做访问鉴权（Bearer Token）
证据代码片段：

来源：package/ebpf-mcp-demo/cmd/ebpf-mcp/main.go:85
```go
authenticated := tokenAuthMiddleware(token, httpServer)
mux.Handle("/mcp", authenticated)
```

来源：package/ebpf-mcp-demo/cmd/ebpf-mcp/main.go:119
```go
authHeader := r.Header.Get("Authorization")
if !strings.HasPrefix(authHeader, "Bearer ") {
    http.Error(w, "Unauthorized: Missing Bearer token", http.StatusUnauthorized)
    return
}
```

说明：请求权限由 token 控制，先过协议层认证，再进入工具调用流程。

## 3. 技巧点-将“协议调用”与“工具执行”解耦
证据代码片段：

来源：package/ebpf-mcp-demo/internal/tools/mcp_bridge.go:37
```go
s.AddTool(mcpTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    return handleToolCall(toolCopy, request)
})
```

来源：package/ebpf-mcp-demo/internal/tools/mcp_bridge.go:204
```go
input := request.GetArguments()
```

说明：MCP 协议层负责参数接收和路由，具体业务逻辑由工具函数执行。

## 4. 技巧点-工具白名单注册，避免任意命令执行面
证据代码片段：

来源：package/ebpf-mcp-demo/internal/tools/load_program.go:262
```go
func init() {
    RegisterTool(types.Tool{
        ID:          "load_program",
        Title:       "Load eBPF Program",
        Description: "Loads a raw eBPF object from file or base64 blob into the kernel.",
        ...
    })
}
```

来源：package/ebpf-mcp-demo/internal/tools/mcp_bridge.go:23
```go
for _, tool := range toolRegistry {
    ...
    s.AddTool(mcpTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        return handleToolCall(toolCopy, request)
    })
}
```

说明：客户端只能调用已注册的工具接口，不能绕过工具层直接执行系统命令。

## 5. 技巧点-在工具层做参数规范化与校验，再进入特权执行路径
证据代码片段：

来源：package/ebpf-mcp-demo/internal/tools/load_program.go:56
```go
args, err := parseLoadProgramInputRobust(processedInput)
if err != nil {
    return &ebpf.LoadProgramResult{
        Success:      false,
        ToolVersion:  "1.0.0",
        ErrorMessage: fmt.Sprintf("parsing error: %v", err),
    }, nil
}
```

来源：package/ebpf-mcp-demo/internal/tools/load_program.go:69
```go
result, err := ebpf.LoadProgram(args)
```

说明：工具层先做输入处理与错误兜底，再调用底层 eBPF 加载函数。

## 6. 技巧点-客户端仅持会话与令牌，不需要持有内核能力
证据代码片段：

来源：package/ebpf-mcp-demo/scripts/test-ebpf-mcp-server.sh:127
```bash
curl -s -X POST "$SERVER_URL" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Mcp-Protocol-Version: 2025-03-26" \
    -H "Mcp-Session-Id: $SESSION_ID" \
    -d '{ ... }'
```

来源：package/ebpf-mcp-demo/README.md:119
```md
| `load_program`   | ✅      | Load and validate `.o` files (CO-RE supported)  | `CAP_BPF` or `CAP_SYS_ADMIN` |
```

说明：客户端是“请求权限”，服务端进程是“执行权限”。二者通过进程边界完成分离。

## 7. 技巧点-通过不同传输模式控制暴露面（HTTP 对外、stdio 本地）
证据代码片段：

来源：package/ebpf-mcp-demo/cmd/ebpf-mcp/main.go:56
```go
if transport == "http" {
    ...
} else {
    if err := server.ServeStdio(mcpServer); err != nil {
        log.Fatalf("Server error: %v", err)
    }
}
```

说明：HTTP 模式通过 token 网关暴露远程入口；stdio 模式适合本地受控场景。
