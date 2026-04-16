//go:build linux
//go:generate go tool bpf2go -cflags "-O2" -tags linux bpf rpc_task_latency.c -- -I ../../headers

package rpctasklatency

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/duckdb/duckdb-go/v2"

	database "ebpf-mcp/internal/db"
	"ebpf-mcp/internal/logx"
	"ebpf-mcp/internal/probes"
)

func init() {
	probes.Register("rpc_task_latency", func() probes.Probe {
		return NewRPCTaskLatencyProbe()
	})
}

type RPCTaskLatencyProbe struct {
	probes.BaseProbe

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	cancel context.CancelFunc
	done   chan struct{}

	dbConn   *sql.Conn
	appender *duckdb.Appender

	eventCount uint64
}

func NewRPCTaskLatencyProbe() *RPCTaskLatencyProbe {
	// 从YAML加载元数据
	meta, exists := probes.GetProbeMetadata("rpc_task_latency")
	if !exists {
		// 如果YAML中没有，使用默认元数据
		meta = probes.ProbeMetadata{
			Type:        "rpc_task_latency",
			Title:       "RPC任务延迟",
			Layer:       "RPC",
			Level:       "L2",
			Scene:       "度量RPC任务从执行到完成的延迟，包含事务ID和过程名",
			Entrypoints: []string{"rpc_execute", "rpc_exit_task"},
			Params: []probes.ParamField{
				{Name: "filter_pid", Type: "u32", Description: "过滤指定PID的进程", Optional: true},
				{Name: "filter_comm", Type: "string", Description: "过滤指定进程名", Optional: true},
			},
			Outputs: probes.OutputConfig{
				Fields: []probes.OutputField{
					{Name: "pid", Type: "u32", Description: "进程ID"},
					{Name: "xid", Type: "u32", Description: "RPC事务ID"},
					{Name: "proc_name", Type: "string", Description: "RPC过程名称"},
					{Name: "latency", Type: "u64", Description: "延迟(纳秒)"},
					{Name: "start_timestamp", Type: "u64", Description: "开始时间戳"},
					{Name: "status", Type: "s32", Description: "任务完成状态码"},
				},
			},
			Risks: "高并发RPC场景下全量追踪可能有开销",
		}
	}
	return &RPCTaskLatencyProbe{
		BaseProbe: probes.NewBaseProbe(meta),
	}
}

func (p *RPCTaskLatencyProbe) Name() string {
	return "rpc_task_latency"
}

func (p *RPCTaskLatencyProbe) Start(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return logx.ErrDBIsNil
	}

	// 1. Setup DuckDB table and appender
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS rpc_task_latency (
pid UINTEGER,
xid UINTEGER,
proc_name VARCHAR,
latency UBIGINT,
start_timestamp UBIGINT,
status INTEGER
)`)
	if err != nil {
		return logx.NewDomainErrorWithCause(logx.ErrorDBOperation, "creating table", err)
	}

	p.appender, p.dbConn, err = database.NewDuckDBAppender(ctx, db, "", "rpc_task_latency")
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorDBOperation, "creating appender", err)
	}

	// 2. Load BPF objects
	if err := loadBpfObjects(&p.objs, nil); err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "loading objects", err)
	}

	// 3. Attach tracing - rpc_execute
	entryLink, err := link.AttachTracing(link.TracingOptions{
		Program: p.objs.RpcExecuteEntry,
	})
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "attaching rpc_execute tracing", err)
	}
	p.links = append(p.links, entryLink)

	// 4. Attach tracing - rpc_exit_task
	exitLink, err := link.AttachTracing(link.TracingOptions{
		Program: p.objs.RpcExitTaskEntry,
	})
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "attaching rpc_exit_task tracing", err)
	}
	p.links = append(p.links, exitLink)

	// 5. Setup Ringbuf reader
	rd, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "opening ringbuf reader", err)
	}
	p.reader = rd

	// 6. Start consuming - 使用独立 context
	probeCtx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})

	// 桥接 goroutine：context 取消时关闭 reader
	go func() {
		<-probeCtx.Done()
		if p.reader != nil {
			_ = p.reader.Close()
		}
	}()

	go p.consume(probeCtx)
	log.Printf("[rpc_task_latency] probe started")
	return nil
}

func (p *RPCTaskLatencyProbe) consume(ctx context.Context) {
	defer close(p.done)

	var event bpfEvent
	count := 0

	for {
		// 检查 context 是否已取消
		select {
		case <-ctx.Done():
			log.Println("[rpc_task_latency] context cancelled, exiting consumer")
			return
		default:
		}

		// 阻塞读取，但会被 reader.Close() 打断
		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				// log.Println("[rpc_task_latency] ringbuf closed, exiting consumer")
				return
			}
			// 其他错误继续循环
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("[rpc_task_latency] parsing event: %v", err)
			continue
		}

		procName := cStringFromInt8(event.ProcName[:])

		err = p.appender.AppendRow(
			event.Pid,
			event.Xid,
			procName,
			event.Latency,
			event.StartTimestamp,
			event.Status,
		)
		if err != nil {
			log.Printf("[rpc_task_latency] appending row: %v", err)
			continue
		}
		atomic.AddUint64(&p.eventCount, 1)

		count++
		if count >= 100 {
			if err := p.appender.Flush(); err != nil {
				log.Printf("[rpc_task_latency] flushing appender: %v", err)
			}
			count = 0
		}
	}
}

func (p *RPCTaskLatencyProbe) Stop() error {
	// log.Println("[rpc_task_latency] Stop() called, shutting down...")

	// 1. 取消 context，触发 reader.Close() 和 consume 退出
	if p.cancel != nil {
		p.cancel()
		// log.Println("[rpc_task_latency] context cancelled")
	}

	// 2. 等待 consume goroutine 真正退出
	if p.done != nil {
		<-p.done
		// log.Println("[rpc_task_latency] consumer exited")
	}

	// 3. Flush 数据并清理资源
	if p.appender != nil {
		_ = p.appender.Flush()
		_ = p.appender.Close()
	}
	if p.dbConn != nil {
		_ = p.dbConn.Close()
	}
	for _, l := range p.links {
		_ = l.Close()
	}
	p.links = nil
	if p.objs != (bpfObjects{}) {
		_ = p.objs.Close()
	}
	runCount, _ := probes.SumProgramRunCount(p.objs.RpcExecuteEntry, p.objs.RpcExitTaskEntry)
	log.Printf("[rpc_task_latency] Stop() completed, total triggers: %d, total writes: %d", runCount, atomic.LoadUint64(&p.eventCount))
	return nil
}

// Flush 强制将缓冲区中的数据写入数据库
func (p *RPCTaskLatencyProbe) Flush() error {
	if p.appender != nil {
		return p.appender.Flush()
	}
	return nil
}

func (p *RPCTaskLatencyProbe) Update(config map[string]interface{}) error {
	if config == nil {
		return nil
	}
	if p.objs.FilterPid == nil || p.objs.FilterComm == nil {
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

	if raw, ok := config["filter_comm"]; ok {
		s, ok := raw.(string)
		if !ok {
			return logx.NewDomainErrorWithCause(logx.ErrorInvalidArgument, fmt.Sprintf("invalid filter_comm: expected string, got %T", raw), nil)
		}
		// 限制长度并转换为字节数组
		var commBytes [32]byte
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
