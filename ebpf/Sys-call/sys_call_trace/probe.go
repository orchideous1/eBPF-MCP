//go:build linux

//go:generate go tool bpf2go -cflags "-O2" -tags linux bpf sys_call_trace.c -- -I ../../headers

package syscall

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/duckdb/duckdb-go/v2"

	database "ebpf-mcp/internal/db"
	"ebpf-mcp/internal/logx"
	"ebpf-mcp/internal/probes"
)

func init() {
	probes.Register("sys_call_trace", func() probes.Probe {
		return NewSysCallTraceProbe()
	})
}

// SysCallTraceProbe 是一个通过 tracepoint 监控 raw_syscalls/sys_enter 和 sys_exit 的系统调用探针。
type SysCallTraceProbe struct {
	probes.BaseProbe

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	cancel context.CancelFunc
	done   chan struct{} // 替代 WaitGroup，用于通知 consume 退出

	dbConn   *sql.Conn
	appender *duckdb.Appender
}

// NewSysCallTraceProbe 创建一个新的系统调用追踪探针实例。
func NewSysCallTraceProbe() *SysCallTraceProbe {
	meta, exists := probes.GetProbeMetadata("sys_call_trace")
	if !exists {
		meta = probes.ProbeMetadata{
			Type:        "sys_call_trace",
			Title:       "系统调用追踪",
			Layer:       "Sys-call",
			Level:       "L1",
			Scene:       "追踪全系统或特定进程的系统调用入口和出口，采集调用号、参数、返回值、进入时间戳和延迟",
			Entrypoints: []string{"raw_syscalls/sys_enter", "raw_syscalls/sys_exit"},
			Params: []probes.ParamField{
				{Name: "filter_pid", Type: "u32", Description: "过滤指定PID的进程", Optional: true},
				{Name: "filter_syscall_id", Type: "u32", Description: "过滤指定系统调用号", Optional: true},
				{Name: "filter_comm", Type: "string", Description: "过滤指定进程名", Optional: true},
			},
			Outputs: probes.OutputConfig{
				Fields: []probes.OutputField{
					{Name: "pid", Type: "u32", Description: "进程ID"},
					{Name: "comm", Type: "string", Description: "进程名"},
					{Name: "syscall_id", Type: "u32", Description: "系统调用号"},
					{Name: "ret", Type: "s64", Description: "返回值"},
					{Name: "duration", Type: "u64", Description: "延迟(纳秒)"},
					{Name: "enter_time_stamp", Type: "u64", Description: "进入时间戳"},
				},
			},
			Risks: "高频系统调用场景下全量追踪可能带来较大开销",
		}
	}
	return &SysCallTraceProbe{
		BaseProbe: probes.NewBaseProbe(meta),
	}
}

// Name 返回探针名称。
func (p *SysCallTraceProbe) Name() string {
	return "sys_call_trace"
}

// Start 启动探针，加载 eBPF 程序并附加到 tracepoint。
func (p *SysCallTraceProbe) Start(ctx context.Context, db *sql.DB) error {

	if db == nil {
		return logx.ErrDBIsNil
	}

	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS sys_call_trace (
pid UBIGINT,
syscall_id UINTEGER,
ret BIGINT,
duration UBIGINT,
enter_time_stamp UBIGINT,
comm VARCHAR
)`)
	if err != nil {
		return logx.NewDomainErrorWithCause(logx.ErrorDBOperation, "creating table", err)
	}
	log.Printf("[sys_call_trace] table created successfully")

	p.appender, p.dbConn, err = database.NewDuckDBAppender(ctx, db, "", "sys_call_trace")
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorDBOperation, "creating appender", err)
	}
	log.Printf("[sys_call_trace] appender created successfully")

	if err := loadBpfObjects(&p.objs, nil); err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "loading objects", err)
	}
	log.Printf("[sys_call_trace] eBPF objects loaded successfully")

	// Attach sys_enter tracepoint
	enterLink, err := link.Tracepoint("raw_syscalls", "sys_enter", p.objs.TraceSysEnter, nil)
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "attaching sys_enter tracepoint", err)
	}
	p.links = append(p.links, enterLink)
	log.Printf("[sys_call_trace] sys_enter tracepoint attached")

	// Attach sys_exit tracepoint
	exitLink, err := link.Tracepoint("raw_syscalls", "sys_exit", p.objs.TraceSysExit, nil)
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "attaching sys_exit tracepoint", err)
	}
	p.links = append(p.links, exitLink)
	log.Printf("[sys_call_trace] sys_exit tracepoint attached")

	rd, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "opening ringbuf reader", err)
	}
	p.reader = rd
	log.Printf("[sys_call_trace] ringbuf reader created")

	// 创建独立 context，不依赖传入的 ctx（MCP 工具上下文会在返回后取消）
	probeCtx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})

	// 桥接 goroutine：context 取消时关闭 reader，打断阻塞的 Read()
	go func() {
		<-probeCtx.Done()
		if p.reader != nil {
			_ = p.reader.Close()
		}
	}()

	go p.consume(probeCtx)
	return nil
}

func (p *SysCallTraceProbe) consume(ctx context.Context) {
	defer close(p.done)

	var event bpfEvent
	count := 0
	totalProcessed := 0

	log.Printf("[sys_call_trace] consumer started, waiting for events...")

	for {
		// 检查 context 是否已取消
		select {
		case <-ctx.Done():
			log.Printf("[sys_call_trace] context cancelled, exiting consumer. Total processed: %d", totalProcessed)
			return
		default:
		}

		// 阻塞读取，但会被 reader.Close() 打断
		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				// 正常退出路径，由 context 取消触发 reader.Close()
				log.Printf("[sys_call_trace] ringbuf closed, exiting consumer. Total processed: %d", totalProcessed)
				return
			}
			// 其他错误继续循环，让 select 检查 context
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("[sys_call_trace] ERROR parsing event: %v", err)
			continue
		}

		comm := cStringFromInt8(event.Comm[:])

		err = p.appender.AppendRow(
			event.Pid,
			uint64(event.SyscallId),
			event.Ret,
			event.Duration,
			event.EnterTimeStamp,
			comm,
		)
		if err != nil {
			log.Printf("[sys_call_trace] ERROR appending row (pid=%d, syscall=%d): %v", event.Pid, event.SyscallId, err)
		}

		count++
		totalProcessed++
		if count >= 100 {
			if err := p.appender.Flush(); err != nil {
				log.Printf("[sys_call_trace] ERROR flushing appender: %v", err)
			}
			count = 0
		}
	}
}

// Stop 停止探针并释放资源。
func (p *SysCallTraceProbe) Stop() error {
	log.Printf("[sys_call_trace] Stop() called, shutting down probe...")

	// 步骤 1: 取消 context，触发 reader.Close() 和 consume 退出
	if p.cancel != nil {
		p.cancel()
		log.Printf("[sys_call_trace] context cancelled")
	}

	// 步骤 2: 等待 consume goroutine 真正退出
	// context 取消会触发桥接 goroutine 调用 reader.Close()，打断阻塞的 Read()
	if p.done != nil {
		<-p.done
		log.Printf("[sys_call_trace] consumer exited")
	}

	// 步骤 3: Flush 数据到数据库
	if p.appender != nil {
		log.Printf("[sys_call_trace] flushing pending data...")
		if err := p.appender.Flush(); err != nil {
			log.Printf("[sys_call_trace] ERROR flush failed: %v", err)
		}
		_ = p.appender.Close()
		log.Printf("[sys_call_trace] appender closed")
	}

	// 步骤 4: 清理剩余资源
	if p.dbConn != nil {
		_ = p.dbConn.Close()
		log.Printf("[sys_call_trace] db connection closed")
	}
	for _, l := range p.links {
		_ = l.Close()
	}
	p.links = nil
	if p.objs != (bpfObjects{}) {
		_ = p.objs.Close()
		log.Printf("[sys_call_trace] bpf objects closed")
	}
	log.Printf("[sys_call_trace] Stop() completed")
	return nil
}

// Flush 强制将缓冲区中的数据写入数据库。
func (p *SysCallTraceProbe) Flush() error {
	if p.appender != nil {
		log.Printf("[sys_call_trace] Flush() called, flushing appender...")
		err := p.appender.Flush()
		if err != nil {
			log.Printf("[sys_call_trace] ERROR Flush() failed: %v", err)
		} else {
			log.Printf("[sys_call_trace] Flush() successful")
		}
		return err
	}
	log.Printf("[sys_call_trace] Flush() called but appender is nil")
	return nil
}

// Update 更新探针的运行时配置（filter_pid, filter_syscall_id, filter_comm）。
func (p *SysCallTraceProbe) Update(config map[string]interface{}) error {
	if config == nil {
		return nil
	}
	if p.objs.FilterPid == nil || p.objs.FilterSyscallId == nil || p.objs.FilterComm == nil {
		return logx.ErrProbeNotStarted
	}

	if raw, ok := config["filter_pid"]; ok {
		pid, err := toUint64(raw)
		if err != nil {
			return logx.NewDomainErrorWithCause(logx.ErrorInvalidArgument, "invalid filter_pid", err)
		}
		if err := p.objs.FilterPid.Set(pid); err != nil {
			return logx.NewDomainErrorWithCause(logx.ErrorProbeUpdateFailed, "set filter_pid", err)
		}
	}

	if raw, ok := config["filter_syscall_id"]; ok {
		sid, err := toUint64(raw)
		if err != nil {
			return logx.NewDomainErrorWithCause(logx.ErrorInvalidArgument, "invalid filter_syscall_id", err)
		}
		if sid > ^uint64(0) { // no-op range check, uint32 will truncate safely
			// sid fits into uint64, Set accepts uint64 for u32 map val
		}
		if err := p.objs.FilterSyscallId.Set(uint32(sid)); err != nil {
			return logx.NewDomainErrorWithCause(logx.ErrorProbeUpdateFailed, "set filter_syscall_id", err)
		}
	}

	if raw, ok := config["filter_comm"]; ok {
		s, ok := raw.(string)
		if !ok {
			return logx.NewDomainErrorWithCause(logx.ErrorInvalidArgument, fmt.Sprintf("invalid filter_comm: expected string, got %T", raw), nil)
		}
		// 限制长度并转换为字节数组
		var commBytes [16]byte
		copy(commBytes[:], s)
		if err := p.objs.FilterComm.Set(commBytes); err != nil {
			return logx.NewDomainErrorWithCause(logx.ErrorProbeUpdateFailed, "set filter_comm", err)
		}
	}

	return nil
}

func cStringFromInt8(src []int8) string {
	b := make([]byte, 0, len(src))
	for _, v := range src {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func toUint64(v interface{}) (uint64, error) {
	switch t := v.(type) {
	case uint64:
		return t, nil
	case uint32:
		return uint64(t), nil
	case uint:
		return uint64(t), nil
	case int64:
		if t < 0 {
			return 0, logx.ErrNegativeValue
		}
		return uint64(t), nil
	case int:
		if t < 0 {
			return 0, logx.ErrNegativeValue
		}
		return uint64(t), nil
	case float64:
		if t < 0 {
			return 0, logx.ErrNegativeValue
		}
		return uint64(t), nil
	default:
		return 0, logx.Wrapf(logx.ErrUnsupportedType, "unsupported type %T", v)
	}
}
