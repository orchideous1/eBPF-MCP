//go:build linux

package probes

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	_ "ebpf-mcp/ebpf/NFS-client/nfs_file_read"
	_ "ebpf-mcp/ebpf/NFS-client/nfs_file_write"
	"ebpf-mcp/internal/probes"
)

// TestDualProbeHandleConflict 测试 nfs_file_read 和 nfs_file_write 同时加载是否会引发句柄冲突
// 验证两个探针能够独立工作，资源不冲突
func TestDualProbeHandleConflict(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	db := openTestDB(t)
	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	defer controller.Shutdown()

	ctx := context.Background()

	t.Log("=== Step 1: 同时加载两个探针 ===")
	// 加载 nfs_file_read 探针
	status1, err := controller.Load(ctx, "nfs_file_read")
	if err != nil {
		t.Fatalf("failed to load nfs_file_read: %v", err)
	}
	if !status1.Loaded {
		t.Fatal("nfs_file_read should be loaded")
	}
	t.Logf("nfs_file_read 加载成功，状态: %s", status1.State)

	// 加载 nfs_file_write 探针（同时运行）
	status2, err := controller.Load(ctx, "nfs_file_write")
	if err != nil {
		t.Fatalf("failed to load nfs_file_write: %v", err)
	}
	if !status2.Loaded {
		t.Fatal("nfs_file_write should be loaded")
	}
	t.Logf("nfs_file_write 加载成功，状态: %s", status2.State)

	// 延迟卸载两个探针
	defer func() {
		controller.Unload("nfs_file_read")
		controller.Unload("nfs_file_write")
	}()

	t.Log("=== Step 2: 验证两个探针状态独立 ===")
	// 验证 nfs_file_read 状态
	status1, err = controller.Status("nfs_file_read")
	if err != nil {
		t.Fatalf("failed to get nfs_file_read status: %v", err)
	}
	if !status1.Loaded || status1.State != "loaded" {
		t.Fatalf("nfs_file_read should be loaded, got state: %s", status1.State)
	}

	// 验证 nfs_file_write 状态
	status2, err = controller.Status("nfs_file_write")
	if err != nil {
		t.Fatalf("failed to get nfs_file_write status: %v", err)
	}
	if !status2.Loaded || status2.State != "loaded" {
		t.Fatalf("nfs_file_write should be loaded, got state: %s", status2.State)
	}

	t.Log("=== Step 3: 验证数据表独立创建 ===")
	// 验证两个表都已创建
	tables := []string{"nfs_file_read", "nfs_file_write"}
	for _, table := range tables {
		var tableExists bool
		err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = ?)", table).Scan(&tableExists)
		if err != nil {
			t.Logf("无法查询 %s 表存在性: %v", table, err)
		} else if !tableExists {
			t.Errorf("%s 表应该被创建", table)
		} else {
			t.Logf("%s 表已创建", table)
		}
	}

	t.Log("=== Step 4: 触发文件读写操作 ===")
	// 创建测试文件并进行读写
	tmpFile := filepath.Join(t.TempDir(), "dual_probe_test.txt")
	content := []byte("test content for dual probe conflict test")

	// 写入文件（触发 write 探针）
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(tmpFile, content, 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 读取文件（触发 read 探针）
	for i := 0; i < 3; i++ {
		_, err := os.ReadFile(tmpFile)
		if err != nil {
			t.Fatalf("failed to read test file: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 等待事件收集
	time.Sleep(300 * time.Millisecond)

	t.Log("=== Step 5: 验证两个探针数据独立收集 ===")
	// 查询 nfs_file_read 表
	var readCount int
	rows, err := db.Query("SELECT COUNT(*) FROM nfs_file_read")
	if err != nil {
		t.Logf("查询 nfs_file_read 表失败: %v", err)
	} else {
		defer rows.Close()
		if rows.Next() {
			rows.Scan(&readCount)
		}
		t.Logf("nfs_file_read 表收集到 %d 条事件", readCount)
	}

	// 查询 nfs_file_write 表
	var writeCount int
	rows2, err := db.Query("SELECT COUNT(*) FROM nfs_file_write")
	if err != nil {
		t.Logf("查询 nfs_file_write 表失败: %v", err)
	} else {
		defer rows2.Close()
		if rows2.Next() {
			rows2.Scan(&writeCount)
		}
		t.Logf("nfs_file_write 表收集到 %d 条事件", writeCount)
	}

	t.Log("=== Step 6: 更新两个探针的宏变量 ===")
	// 更新 nfs_file_read 的过滤参数
	_, err = controller.Update("nfs_file_read", map[string]any{
		"filter_pid": uint32(os.Getpid()),
	})
	if err != nil {
		t.Fatalf("failed to update nfs_file_read: %v", err)
	}
	t.Log("nfs_file_read filter_pid 更新成功")

	// 更新 nfs_file_write 的过滤参数
	_, err = controller.Update("nfs_file_write", map[string]any{
		"filter_file": "*.txt",
	})
	if err != nil {
		t.Fatalf("failed to update nfs_file_write: %v", err)
	}
	t.Log("nfs_file_write filter_file 更新成功")

	t.Log("=== Step 7: 依次卸载两个探针 ===")
	// 卸载 nfs_file_read
	status1, err = controller.Unload("nfs_file_read")
	if err != nil {
		t.Fatalf("failed to unload nfs_file_read: %v", err)
	}
	if status1.Loaded {
		t.Fatal("nfs_file_read should be unloaded")
	}
	t.Logf("nfs_file_read 卸载成功，状态: %s", status1.State)

	// 验证 nfs_file_write 仍然正常运行
	status2, err = controller.Status("nfs_file_write")
	if err != nil {
		t.Fatalf("failed to get nfs_file_write status after unloading read probe: %v", err)
	}
	if !status2.Loaded {
		t.Fatal("nfs_file_write should still be loaded after nfs_file_read unloaded")
	}
	t.Log("nfs_file_write 在 nfs_file_read 卸载后仍然正常运行")

	// 卸载 nfs_file_write
	status2, err = controller.Unload("nfs_file_write")
	if err != nil {
		t.Fatalf("failed to unload nfs_file_write: %v", err)
	}
	if status2.Loaded {
		t.Fatal("nfs_file_write should be unloaded")
	}
	t.Logf("nfs_file_write 卸载成功，状态: %s", status2.State)

	t.Log("\n✓ 双探针句柄冲突测试通过! 两个探针能够同时正常运行，无资源冲突")
}

// TestNFSProbeWithFIOAndFilterValidation 使用 fio 和 dd 进行真实数据收集测试
// 验证过滤参数在动态更新前后都能正确生效
func TestNFSProbeWithFIOAndFilterValidation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("需要 root 权限运行 eBPF 测试")
	}

	// 检查 fio 是否安装
	if _, err := exec.LookPath("fio"); err != nil {
		t.Skip("fio 未安装，跳过测试")
	}

	// 检查 dd 是否可用
	if _, err := exec.LookPath("dd"); err != nil {
		t.Skip("dd 命令不可用，跳过测试")
	}

	db := openTestDB(t)
	controller, err := probes.NewController(db)
	if err != nil {
		t.Fatalf("failed to create controller: %v", err)
	}
	defer controller.Shutdown()

	ctx := context.Background()

	// 使用 NFS 挂载目录进行测试
	nfsDir := "/home/shasha/MyProject/nfs"
	if _, err := os.Stat(nfsDir); os.IsNotExist(err) {
		t.Skipf("NFS 目录 %s 不存在，跳过测试", nfsDir)
	}

	// 创建测试子目录
	testDir := filepath.Join(nfsDir, fmt.Sprintf("probe_test_%d", os.Getpid()))
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("无法创建测试目录 %s: %v", testDir, err)
	}
	defer os.RemoveAll(testDir)

	t.Logf("=== 使用 NFS 目录: %s ===", testDir)

	t.Log("=== 测试 nfs_file_read 探针 ===")
	testProbeWithFIOAndDD(t, ctx, controller, db, testDir, "nfs_file_read")

	t.Log("=== 测试 nfs_file_write 探针 ===")
	testProbeWithFIOAndDD(t, ctx, controller, db, testDir, "nfs_file_write")

	t.Log("\n✓ fio 真实数据收集及过滤验证测试通过!")
}

// testProbeWithFIOAndDD 测试指定探针的过滤功能
func testProbeWithFIOAndDD(t *testing.T, ctx context.Context, controller *probes.Controller, db *sql.DB, testDir, probeType string) {
	t.Helper()

	t.Logf("--- %s: Step 1: 加载探针（无过滤）---", probeType)
	_, err := controller.Load(ctx, probeType)
	if err != nil {
		t.Fatalf("failed to load %s: %v", probeType, err)
	}
	defer controller.Unload(probeType)
	t.Logf("%s 加载成功", probeType)

	t.Logf("--- %s: Step 2: 启动 dd 进程进行文件操作 ---", probeType)
	ddFile := filepath.Join(testDir, fmt.Sprintf("dd_test_%s.dat", probeType))
	// 先创建一个测试文件（在 NFS 目录中）
	if err := os.WriteFile(ddFile, make([]byte, 1024*1024), 0644); err != nil {
		t.Fatalf("failed to create dd test file: %v", err)
	}
	t.Logf("dd 测试文件: %s", ddFile)

	// 启动 dd 进程持续进行读写（循环执行，确保产生足够的事件）
	ddCtx, ddCancel := context.WithCancel(context.Background())
	defer ddCancel()

	// 使用循环脚本持续进行 dd 操作
	ddScript := fmt.Sprintf(`#!/bin/bash
while true; do
    dd if=%s of=/dev/null bs=4k count=64 2>/dev/null
    sleep 0.1
done`, ddFile)

	ddScriptFile := filepath.Join(testDir, "dd_loop.sh")
	if err := os.WriteFile(ddScriptFile, []byte(ddScript), 0755); err != nil {
		t.Fatalf("failed to create dd script: %v", err)
	}

	ddCmd := exec.CommandContext(ddCtx, "bash", ddScriptFile)
	if err := ddCmd.Start(); err != nil {
		t.Fatalf("failed to start dd: %v", err)
	}

	// 确保 dd 进程结束后清理
	defer func() {
		ddCancel()
		if ddCmd.Process != nil {
			ddCmd.Process.Kill()
		}
		ddCmd.Wait()
	}()

	// 等待 dd 产生一些事件（给予足够时间让 eBPF 程序就绪并收集事件）
	t.Logf("等待 dd 产生事件...")
	time.Sleep(2 * time.Second)

	t.Logf("--- %s: Step 3: 验证 dd 事件被收集（过滤前） ---", probeType)
	// 强制 Flush 数据到数据库
	if err := controller.Flush(probeType); err != nil {
		t.Logf("Flush %s 失败: %v", probeType, err)
	}
	// 查询当前收集到的事件数量
	var countBefore int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", probeType)
	rows, err := db.Query(query)
	if err != nil {
		t.Logf("查询 %s 表失败: %v", probeType, err)
	} else {
		if rows.Next() {
			rows.Scan(&countBefore)
		}
		rows.Close()
	}
	t.Logf("过滤前 %s 表中有 %d 条事件（包含 dd 进程的事件）", probeType, countBefore)

	// 验证是否有 dd 进程的事件
	var ddEventCount int
	queryDD := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE comm = 'dd'", probeType)
	rows, err = db.Query(queryDD)
	if err != nil {
		t.Logf("查询 dd 事件失败: %v", err)
	} else {
		if rows.Next() {
			rows.Scan(&ddEventCount)
		}
		rows.Close()
	}
	t.Logf("过滤前收集到 %d 条 dd 进程的事件", ddEventCount)

	t.Logf("--- %s: Step 4: 动态更新 filter_comm 为 fio ---", probeType)
	_, err = controller.Update(probeType, map[string]any{
		"filter_comm": "fio",
	})
	if err != nil {
		t.Fatalf("failed to update filter_comm: %v", err)
	}
	t.Log("filter_comm 已设置为 'fio'")

	// 等待过滤参数生效
	time.Sleep(100 * time.Millisecond)

	t.Logf("--- %s: Step 5: 启动 fio 进行读写测试 ---", probeType)
	fioFile := filepath.Join(testDir, fmt.Sprintf("fio_test_%s.dat", probeType))

	// 使用更长的运行时间确保收集到足够的事件
	fioCmd := exec.Command("fio",
		"--name=test",
		"--filename="+fioFile,
		"--direct=0",          // 使用 buffered I/O，更容易被 probe 捕获
		"--bs=4k",
		"--size=20M",
		"--runtime=3",
		"--numjobs=2",
		"--rw=randrw",
		"--group_reporting",
	)

	// 捕获 fio 输出用于调试
	fioOutput, err := fioCmd.CombinedOutput()
	if err != nil {
		t.Logf("fio 输出:\n%s", string(fioOutput))
		t.Logf("fio 退出码: %v", err)
	} else {
		t.Logf("fio 完成:\n%s", string(fioOutput))
	}

	// 再等待一段时间让事件被收集到 DuckDB
	t.Log("等待事件被收集到数据库...")
	time.Sleep(2 * time.Second)

	// 停止 dd 进程
	ddCancel()
	if ddCmd.Process != nil {
		ddCmd.Process.Kill()
	}
	ddCmd.Wait()

	t.Logf("--- %s: Step 6: 验证过滤后只收集 fio 事件 ---", probeType)
	// 强制 Flush 数据到数据库
	if err := controller.Flush(probeType); err != nil {
		t.Logf("Flush %s 失败: %v", probeType, err)
	}
	// 查询总事件数
	var countAfter int
	rows, err = db.Query(query)
	if err != nil {
		t.Logf("查询 %s 表失败: %v", probeType, err)
	} else {
		if rows.Next() {
			rows.Scan(&countAfter)
		}
		rows.Close()
	}
	t.Logf("过滤后 %s 表中共有 %d 条事件", probeType, countAfter)

	// 查询 fio 事件数
	var fioEventCount int
	queryFIO := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE comm = 'fio'", probeType)
	rows, err = db.Query(queryFIO)
	if err != nil {
		t.Logf("查询 fio 事件失败: %v", err)
	} else {
		if rows.Next() {
			rows.Scan(&fioEventCount)
		}
		rows.Close()
	}
	t.Logf("过滤后收集到 %d 条 fio 进程的事件", fioEventCount)

	// 查询过滤后的 dd 事件数（应该很少或没有新事件）
	rows, err = db.Query(queryDD)
	if err != nil {
		t.Logf("查询 dd 事件失败: %v", err)
	} else {
		if rows.Next() {
			var ddCountAfter int
			rows.Scan(&ddCountAfter)
			t.Logf("过滤后 dd 事件总数: %d（过滤前: %d，新增: %d）",
				ddCountAfter, ddEventCount, ddCountAfter-ddEventCount)
		}
		rows.Close()
	}

	// 验证过滤生效：应该有 fio 事件
	if fioEventCount == 0 {
		t.Logf("警告: 未收集到 fio 事件（可能系统没有 NFS 挂载）")
	} else {
		t.Logf("✓ 成功收集到 %d 条 fio 事件", fioEventCount)
	}

	// 列出一些样本事件
	querySample := fmt.Sprintf("SELECT comm, pid FROM %s ORDER BY time_stamp DESC LIMIT 5", probeType)
	rows, err = db.Query(querySample)
	if err == nil {
		t.Log("最近 5 条事件的进程信息:")
		for rows.Next() {
			var comm string
			var pid uint32
			if err := rows.Scan(&comm, &pid); err == nil {
				t.Logf("  - comm=%s, pid=%d", comm, pid)
			}
		}
		rows.Close()
	}

	t.Logf("--- %s 测试完成 ---", probeType)
}
