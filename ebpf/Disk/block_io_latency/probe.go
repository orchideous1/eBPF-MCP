//go:build linux

//go:generate go tool bpf2go -cflags "-O2" -tags linux bpf block_io_latency.c -- -I ../../headers

package disk

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
	probes.Register("block_io_latency", func() probes.Probe {
		return NewBlockIoLatencyProbe()
	})
}

// BlockIoLatencyProbe 是一个监控块设备I/O延迟的探针。
type BlockIoLatencyProbe struct {
	probes.BaseProbe

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	cancel context.CancelFunc
	done   chan struct{}

	dbConn   *sql.Conn
	appender *duckdb.Appender
}

// NewBlockIoLatencyProbe 创建一个新的块设备I/O延迟探针实例。
func NewBlockIoLatencyProbe() *BlockIoLatencyProbe {
	meta, exists := probes.GetProbeMetadata("block_io_latency")
	if !exists {
		meta = probes.ProbeMetadata{
			Type:        "block_io_latency",
			Title:       "块设备I/O延迟",
			Layer:       "Disk",
			Level:       "L1",
			Scene:       "监控块设备I/O操作的延迟，追踪I/O请求从发起到底盘完成的时间",
			Entrypoints: []string{"block/block_io_start", "block/block_io_done"},
			Params: []probes.ParamField{
				{Name: "filter_pid", Type: "u32", Description: "过滤指定PID的进程", Optional: true},
				{Name: "filter_comm", Type: "string", Description: "过滤指定进程名", Optional: true},
			},
			Outputs: probes.OutputConfig{
				Fields: []probes.OutputField{
					{Name: "pid", Type: "u32", Description: "进程ID"},
					{Name: "comm", Type: "string", Description: "进程名"},
					{Name: "latency", Type: "u64", Description: "I/O延迟(纳秒)"},
					{Name: "time_stamp", Type: "u64", Description: "完成时间戳"},
				},
			},
			Risks: "高I/O吞吐场景下可能产生较多事件",
		}
	}
	return &BlockIoLatencyProbe{
		BaseProbe: probes.NewBaseProbe(meta),
	}
}

// Name 返回探针名称。
func (p *BlockIoLatencyProbe) Name() string {
	return "block_io_latency"
}

// Start 启动探针，加载 eBPF 程序并附加到 tracepoint。
func (p *BlockIoLatencyProbe) Start(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return logx.ErrDBIsNil
	}

	// 创建表
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS block_io_latency (
		pid UBIGINT,
		latency UBIGINT,
		time_stamp UBIGINT,
		comm VARCHAR
	)`)
	if err != nil {
		return logx.NewDomainErrorWithCause(logx.ErrorDBOperation, "creating table", err)
	}
	log.Printf("[block_io_latency] table created successfully")

	// 创建appender
	p.appender, p.dbConn, err = database.NewDuckDBAppender(ctx, db, "", "block_io_latency")
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorDBOperation, "creating appender", err)
	}
	log.Printf("[block_io_latency] appender created successfully")

	// 加载eBPF对象
	if err := loadBpfObjects(&p.objs, nil); err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "loading objects", err)
	}
	log.Printf("[block_io_latency] eBPF objects loaded successfully")

	// 附加block_io_start tracepoint
	startLink, err := link.Tracepoint("block", "block_io_start", p.objs.TraceBlockIoStart, nil)
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "attaching block_io_start tracepoint", err)
	}
	p.links = append(p.links, startLink)
	log.Printf("[block_io_latency] block_io_start tracepoint attached")

	// 附加block_io_done tracepoint
	doneLink, err := link.Tracepoint("block", "block_io_done", p.objs.TraceBlockIoDone, nil)
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "attaching block_io_done tracepoint", err)
	}
	p.links = append(p.links, doneLink)
	log.Printf("[block_io_latency] block_io_done tracepoint attached")

	// 创建ringbuf reader
	rd, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "opening ringbuf reader", err)
	}
	p.reader = rd
	log.Printf("[block_io_latency] ringbuf reader created")

	// 创建独立context
	probeCtx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})

	// 桥接goroutine：context取消时关闭reader
	go func() {
		<-probeCtx.Done()
		if p.reader != nil {
			_ = p.reader.Close()
		}
	}()

	go p.consume(probeCtx)
	return nil
}

func (p *BlockIoLatencyProbe) consume(ctx context.Context) {
	defer close(p.done)

	var event bpfEvent
	count := 0
	totalProcessed := 0

	log.Printf("[block_io_latency] consumer started, waiting for events...")

	for {
		select {
		case <-ctx.Done():
			log.Printf("[block_io_latency] context cancelled, exiting consumer. Total processed: %d", totalProcessed)
			return
		default:
		}

		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Printf("[block_io_latency] ringbuf closed, exiting consumer. Total processed: %d", totalProcessed)
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("[block_io_latency] ERROR parsing event: %v", err)
			continue
		}

		comm := cStringFromInt8(event.Comm[:])

		err = p.appender.AppendRow(
			event.Pid,
			event.Latency,
			event.TimeStamp,
			comm,
		)
		if err != nil {
			log.Printf("[block_io_latency] ERROR appending row (pid=%d): %v", event.Pid, err)
		}

		count++
		totalProcessed++
		if count >= 100 {
			if err := p.appender.Flush(); err != nil {
				log.Printf("[block_io_latency] ERROR flushing appender: %v", err)
			}
			count = 0
		}
	}
}

// Stop 停止探针并释放资源。
func (p *BlockIoLatencyProbe) Stop() error {
	log.Printf("[block_io_latency] Stop() called, shutting down probe...")

	if p.cancel != nil {
		p.cancel()
		log.Printf("[block_io_latency] context cancelled")
	}

	if p.done != nil {
		<-p.done
		log.Printf("[block_io_latency] consumer exited")
	}

	if p.appender != nil {
		log.Printf("[block_io_latency] flushing pending data...")
		if err := p.appender.Flush(); err != nil {
			log.Printf("[block_io_latency] ERROR flush failed: %v", err)
		}
		_ = p.appender.Close()
		log.Printf("[block_io_latency] appender closed")
	}

	if p.dbConn != nil {
		_ = p.dbConn.Close()
		log.Printf("[block_io_latency] db connection closed")
	}

	for _, l := range p.links {
		_ = l.Close()
	}
	p.links = nil

	if p.objs != (bpfObjects{}) {
		_ = p.objs.Close()
		log.Printf("[block_io_latency] bpf objects closed")
	}

	log.Printf("[block_io_latency] Stop() completed")
	return nil
}

// Flush 强制将缓冲区中的数据写入数据库。
func (p *BlockIoLatencyProbe) Flush() error {
	if p.appender != nil {
		log.Printf("[block_io_latency] Flush() called, flushing appender...")
		err := p.appender.Flush()
		if err != nil {
			log.Printf("[block_io_latency] ERROR Flush() failed: %v", err)
		} else {
			log.Printf("[block_io_latency] Flush() successful")
		}
		return err
	}
	log.Printf("[block_io_latency] Flush() called but appender is nil")
	return nil
}

// Update 更新探针的运行时配置。
func (p *BlockIoLatencyProbe) Update(config map[string]interface{}) error {
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
