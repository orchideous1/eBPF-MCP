//go:build linux

//go:generate go tool bpf2go -cflags "-O2" -tags linux bpf nfsd4_read.c -- -I ../../headers

package nfsd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/duckdb/duckdb-go/v2"

	database "ebpf-mcp/internal/db"
	"ebpf-mcp/internal/logx"
	"ebpf-mcp/internal/probes"
)

func init() {
	probes.Register("nfsd4_read", func() probes.Probe {
		return NewNFSd4ReadProbe()
	})
}

type NFSd4ReadProbe struct {
	probes.BaseProbe

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	cancel context.CancelFunc
	done   chan struct{}

	dbConn   *sql.Conn
	appender *duckdb.Appender
}

func NewNFSd4ReadProbe() *NFSd4ReadProbe {
	// 尝试从 YAML 加载元数据
	meta, exists := probes.GetProbeMetadata("nfsd4_read")
	if !exists {
		// 如果 YAML 中没有，使用默认元数据
		meta = probes.ProbeMetadata{
			Type:        "nfsd4_read",
			Title:       "NFSD读操作",
			Layer:       "nfsd",
			Level:       "L2",
			Scene:       "度量NFS服务端(nfsd)处理NFSv4读请求的延迟与大小",
			Entrypoints: []string{"nfsd4_read"},
			Params: []probes.ParamField{
				{Name: "filter_pid", Type: "u32", Description: "过滤指定PID的nfsd进程", Optional: true},
			},
			Outputs: probes.OutputConfig{
				Fields: []probes.OutputField{
					{Name: "pid", Type: "u32", Description: "处理请求的nfsd进程ID"},
					{Name: "lat", Type: "u64", Description: "延迟(纳秒)"},
					{Name: "time_stamp", Type: "u64", Description: "时间戳"},
					{Name: "size", Type: "u64", Description: "读取大小"},
					{Name: "offset", Type: "u64", Description: "文件偏移量"},
					{Name: "xid", Type: "u32", Description: "RPC事务ID"},
					{Name: "comm", Type: "string", Description: "进程名"},
				},
			},
			Risks: "高并发场景下全量追踪可能有开销",
		}
	}
	return &NFSd4ReadProbe{
		BaseProbe: probes.NewBaseProbe(meta),
	}
}

func (p *NFSd4ReadProbe) Name() string {
	return "nfsd4_read"
}

func (p *NFSd4ReadProbe) Start(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return logx.ErrDBIsNil
	}

	// 1. Setup DuckDB table and appender
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS nfsd4_read (
pid UBIGINT,
lat UBIGINT,
time_stamp UBIGINT,
size UBIGINT,
"offset" UBIGINT,
xid UINTEGER,
comm VARCHAR
)`)
	if err != nil {
		return logx.NewDomainErrorWithCause(logx.ErrorDBOperation, "creating table", err)
	}

	p.appender, p.dbConn, err = database.NewDuckDBAppender(ctx, db, "", "nfsd4_read")
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorDBOperation, "creating appender", err)
	}

	// 2. Load BPF objects
	if err := loadBpfObjects(&p.objs, nil); err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "loading objects", err)
	}

	// 3. Attach tracing
	entryLink, err := link.AttachTracing(link.TracingOptions{
		Program: p.objs.Nfsd4ReadEntry,
	})
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "attaching tracing entry", err)
	}
	p.links = append(p.links, entryLink)

	exitLink, err := link.AttachTracing(link.TracingOptions{
		Program: p.objs.Nfsd4ReadExit,
	})
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "attaching tracing exit", err)
	}
	p.links = append(p.links, exitLink)

	// 4. Setup Ringbuf reader
	rd, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "opening ringbuf reader", err)
	}
	p.reader = rd

	// 5. Start consuming
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
	return nil
}

func (p *NFSd4ReadProbe) consume(ctx context.Context) {
	defer close(p.done)

	var event bpfEvent
	count := 0

	for {
		select {
		case <-ctx.Done():
			log.Println("[nfsd4_read] context cancelled, exiting consumer")
			return
		default:
		}

		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[nfsd4_read] ringbuf closed, exiting consumer")
				return
			}
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("[nfsd4_read] parsing event: %v", err)
			continue
		}

		comm := cStringFromInt8(event.Comm[:])

		err = p.appender.AppendRow(event.Pid, event.Lat, event.TimeStamp, event.Size, event.Offset, event.Xid, comm)
		if err != nil {
			log.Printf("[nfsd4_read] appending row: %v", err)
		}

		count++
		if count >= 100 {
			if err := p.appender.Flush(); err != nil {
				log.Printf("[nfsd4_read] flushing appender: %v", err)
			}
			count = 0
		}
	}
}

func (p *NFSd4ReadProbe) Stop() error {
	log.Println("[nfsd4_read] Stop() called, shutting down...")

	if p.cancel != nil {
		p.cancel()
		log.Println("[nfsd4_read] context cancelled")
	}

	if p.done != nil {
		<-p.done
		log.Println("[nfsd4_read] consumer exited")
	}

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
	log.Println("[nfsd4_read] Stop() completed")
	return nil
}

func (p *NFSd4ReadProbe) Flush() error {
	if p.appender != nil {
		return p.appender.Flush()
	}
	return nil
}

func (p *NFSd4ReadProbe) Update(config map[string]interface{}) error {
	if config == nil {
		return nil
	}
	if p.objs.FilterPid == nil {
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
