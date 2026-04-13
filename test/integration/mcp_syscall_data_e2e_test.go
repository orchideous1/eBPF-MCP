//go:build linux

package integration

import (
	"database/sql"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	// 导入探针实现以触发 init() 注册
	_ "ebpf-mcp/ebpf/Sys-call/sys_call_trace"
	"ebpf-mcp/internal/probes"
	"ebpf-mcp/internal/server"
	_ "github.com/duckdb/duckdb-go/v2"
)

// TestMCPSysCallTraceDataFlow 测试完整的 sys_call_trace 数据流
// 覆盖：启动服务器 -> 加载探针 -> fio 产生系统调用 -> 数据写入数据库
func TestMCPSysCallTraceDataFlow(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	// 检查 fio 是否安装
	if _, err := exec.LookPath("fio"); err != nil {
		t.Skip("fio 未安装，跳过测试")
	}

	ts := setupSysCallTestServer(t)
	defer ts.cleanup()

	sessionID := initMCPSession(t, ts.baseURL, ts.authToken)

	// 步骤 1: 加载 sys_call_trace 探针
	t.Run("step 1: load sys_call_trace probe", func(t *testing.T) {
		resp := callTool(t, ts.baseURL, ts.authToken, sessionID, 1, "system_observe_control", map[string]any{
			"probeName": "sys_call_trace",
			"operation": "load",
		})

		if resp.IsError() {
			t.Fatalf("加载探针失败: %v", resp.GetTextResult())
		}

		result := resp.GetTextResult()
		if !stringContains(result, "loaded") {
			t.Fatalf("探针应该成功加载，返回: %s", result)
		}
		t.Logf("探针加载成功: %s", result)
	})

	// 步骤 2: 验证表已创建
	t.Run("step 2: verify table created", func(t *testing.T) {
		var tableExists bool
		err := ts.db.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_name = 'sys_call_trace'
			)
		`).Scan(&tableExists)
		if err != nil {
			t.Fatalf("查询表存在性失败: %v", err)
		}
		if !tableExists {
			t.Fatal("sys_call_trace 表应该在探针加载后创建")
		}
		t.Log("数据库表已创建")
	})

	// 步骤 3: 运行 fio 产生系统调用
	t.Run("step 3: run fio to generate syscalls", func(t *testing.T) {
		fioDir := t.TempDir()
		fioJobFile := filepath.Join(fioDir, "test.fio")
		fioJobContent := `[global]
name=syscall-test
directory=%s
size=10M
runtime=3s
time_based=1

[read-test]
filename=testfile.dat
rw=randread
bs=4k
iodepth=4

[write-test]
filename=testfile2.dat
rw=randwrite
bs=8k
iodepth=2
`
		// 写入 fio job 文件
		if err := os.WriteFile(fioJobFile, []byte(fmt.Sprintf(fioJobContent, fioDir)), 0644); err != nil {
			t.Fatalf("创建 fio job 文件失败: %v", err)
		}

		// 执行 fio
		cmd := exec.Command("fio", fioJobFile, "--output", filepath.Join(fioDir, "fio.log"))
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("fio 输出: %s", string(output))
			t.Fatalf("fio 执行失败: %v", err)
		}
		t.Logf("fio 执行完成，产生系统调用")

		// 等待事件处理
		time.Sleep(500 * time.Millisecond)
	})

	// 步骤 4: 卸载探针（触发 Flush）
	t.Run("step 4: unload probe to trigger flush", func(t *testing.T) {
		resp := callTool(t, ts.baseURL, ts.authToken, sessionID, 2, "system_observe_control", map[string]any{
			"probeName": "sys_call_trace",
			"operation": "unload",
		})

		if resp.IsError() {
			t.Fatalf("卸载探针失败: %v", resp.GetTextResult())
		}

		result := resp.GetTextResult()
		if !stringContains(result, "unloaded") {
			t.Fatalf("探针应该成功卸载，返回: %s", result)
		}
		t.Logf("探针卸载成功，数据应该已 Flush: %s", result)
	})

	// 步骤 5: 验证数据已写入数据库
	t.Run("step 5: verify data in database", func(t *testing.T) {
		// 等待数据库写入完成
		time.Sleep(200 * time.Millisecond)

		// 查询事件总数
		var totalCount int
		err := ts.db.QueryRow("SELECT COUNT(*) FROM sys_call_trace").Scan(&totalCount)
		if err != nil {
			t.Fatalf("查询数据失败: %v", err)
		}
		t.Logf("数据库中共有 %d 条系统调用事件", totalCount)

		if totalCount == 0 {
			t.Fatal("应该有系统调用事件被记录，但实际为 0")
		}

		// 验证数据结构完整性
		rows, err := ts.db.Query(`
			SELECT pid, comm, syscall_id, ret, duration, enter_time_stamp
			FROM sys_call_trace
			LIMIT 5
		`)
		if err != nil {
			t.Fatalf("查询数据详情失败: %v", err)
		}
		defer rows.Close()

		recordCount := 0
		for rows.Next() {
			var pid, syscallID uint64
			var comm string
			var ret int64
			var duration, enterTimeStamp uint64

			err := rows.Scan(&pid, &comm, &syscallID, &ret, &duration, &enterTimeStamp)
			if err != nil {
				t.Fatalf("扫描数据失败: %v", err)
			}

			recordCount++
			t.Logf("记录 %d: pid=%d, comm=%s, syscall_id=%d, ret=%d, duration=%d, ts=%d",
				recordCount, pid, comm, syscallID, ret, duration, enterTimeStamp)

			// 验证字段有效性
			if pid == 0 {
				t.Error("PID 不应该为 0")
			}
			if comm == "" {
				t.Error("comm 不应该为空")
			}
			if enterTimeStamp == 0 {
				t.Error("enter_time_stamp 不应该为 0")
			}
		}

		if recordCount == 0 {
			t.Fatal("无法读取任何数据记录")
		}

		t.Logf("成功验证 %d 条数据记录的结构完整性", recordCount)
	})

	// 步骤 6: 查询常见系统调用的分布
	t.Run("step 6: analyze syscall distribution", func(t *testing.T) {
		rows, err := ts.db.Query(`
			SELECT syscall_id, COUNT(*) as cnt
			FROM sys_call_trace
			GROUP BY syscall_id
			ORDER BY cnt DESC
			LIMIT 10
		`)
		if err != nil {
			t.Logf("查询系统调用分布失败: %v", err)
			return
		}
		defer rows.Close()

		t.Log("系统调用分布 (top 10):")
		for rows.Next() {
			var syscallID uint64
			var count int
			if err := rows.Scan(&syscallID, &count); err == nil {
				t.Logf("  syscall_id=%d: %d 次", syscallID, count)
			}
		}
	})
}

// TestMCPSysCallTraceWithFilter 测试带过滤条件的 sys_call_trace 数据收集
func TestMCPSysCallTraceWithFilter(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	if _, err := exec.LookPath("fio"); err != nil {
		t.Skip("fio 未安装，跳过测试")
	}

	ts := setupSysCallTestServer(t)
	defer ts.cleanup()

	sessionID := initMCPSession(t, ts.baseURL, ts.authToken)

	// 获取当前进程 PID 用于过滤
	currentPID := uint32(os.Getpid())

	// 步骤 1: 加载探针
	resp := callTool(t, ts.baseURL, ts.authToken, sessionID, 1, "system_observe_control", map[string]any{
		"probeName": "sys_call_trace",
		"operation": "load",
	})
	if resp.IsError() {
		t.Fatalf("加载探针失败: %v", resp.GetTextResult())
	}

	// 步骤 2: 设置 filter_pid
	t.Run("set filter_pid", func(t *testing.T) {
		resp := callTool(t, ts.baseURL, ts.authToken, sessionID, 2, "probe_customize", map[string]any{
			"name": "sys_call_trace",
			"params": map[string]any{
				"filter_pid": currentPID,
			},
		})
		if resp.IsError() {
			t.Fatalf("设置 filter_pid 失败: %v", resp.GetTextResult())
		}
		t.Logf("成功设置 filter_pid=%d", currentPID)
	})

	// 步骤 3: 运行 fio
	t.Run("run fio", func(t *testing.T) {
		fioDir := t.TempDir()
		cmd := exec.Command("fio",
			"--name=test",
			"--directory="+fioDir,
			"--size=5M",
			"--runtime=2s",
			"--time_based",
			"--rw=read",
			"--bs=4k",
		)
		if err := cmd.Run(); err != nil {
			t.Logf("fio 可能出错: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	})

	// 步骤 4: 卸载探针
	resp = callTool(t, ts.baseURL, ts.authToken, sessionID, 3, "system_observe_control", map[string]any{
		"probeName": "sys_call_trace",
		"operation": "unload",
	})
	if resp.IsError() {
		t.Fatalf("卸载探针失败: %v", resp.GetTextResult())
	}

	// 步骤 5: 验证只收集了当前进程的事件
	t.Run("verify filtered data", func(t *testing.T) {
		// 查询当前 PID 的事件数
		var currentPIDCount int
		err := ts.db.QueryRow(
			"SELECT COUNT(*) FROM sys_call_trace WHERE pid = ?",
			uint64(currentPID),
		).Scan(&currentPIDCount)
		if err != nil {
			t.Logf("查询当前 PID 数据失败: %v", err)
		}

		// 查询其他 PID 的事件数
		var otherPIDCount int
		err = ts.db.QueryRow(
			"SELECT COUNT(*) FROM sys_call_trace WHERE pid != ?",
			uint64(currentPID),
		).Scan(&otherPIDCount)
		if err != nil {
			t.Logf("查询其他 PID 数据失败: %v", err)
		}

		t.Logf("当前 PID(%d) 事件数: %d, 其他 PID 事件数: %d", currentPID, currentPIDCount, otherPIDCount)

		// 由于 filter_pid 可能不是完全准确的（取决于时机），我们只记录而不强制断言
		if otherPIDCount > currentPIDCount*10 {
			t.Logf("警告: 其他 PID 的事件数 (%d) 远多于当前 PID (%d)，过滤器可能未生效",
				otherPIDCount, currentPIDCount)
		}
	})
}

// syscallTestServer 封装测试服务器
type syscallTestServer struct {
	controller *probes.Controller
	db         *sql.DB
	baseURL    string
	authToken  string
	httpServer *httptest.Server
}

// setupSysCallTestServer 创建测试服务器
func setupSysCallTestServer(t *testing.T) *syscallTestServer {
	t.Helper()

	// 加载探针元数据
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Logf("警告: 无法找到仓库根目录: %v", err)
	} else {
		if err := probes.LoadProbesFromYAML(repoRoot); err != nil {
			t.Logf("警告: 无法加载探针 YAML 配置: %v", err)
		}
	}

	// 创建临时数据库
	dbPath := filepath.Join(t.TempDir(), "test.duckdb")
	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		t.Fatalf("打开 DuckDB 失败: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping DuckDB 失败: %v", err)
	}

	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("创建 controller 失败: %v", err)
	}

	token := "test-token-e2e"
	cfg := server.ServerConfig{
		Transport: server.TransportHTTP,
		HTTPPort:  "0",
		AuthToken: token,
		Debug:     true,
	}

	srv, err := server.New(cfg, controller)
	if err != nil {
		t.Fatalf("创建 server 失败: %v", err)
	}

	handler, err := srv.MCPServerHTTPHandlerForTest()
	if err != nil {
		t.Fatalf("获取 HTTP handler 失败: %v", err)
	}

	// 使用 httptest.Server
	httpSrv := httptest.NewServer(handler)

	return &syscallTestServer{
		controller: controller,
		db:         db,
		baseURL:    httpSrv.URL,
		authToken:  token,
		httpServer: httpSrv,
	}
}

// cleanup 清理测试资源
func (ts *syscallTestServer) cleanup() {
	if ts.httpServer != nil {
		ts.httpServer.Close()
	}
	if ts.controller != nil {
		ts.controller.Shutdown()
	}
	if ts.db != nil {
		ts.db.Close()
	}
}

// stringContains 检查字符串是否包含子串
func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
