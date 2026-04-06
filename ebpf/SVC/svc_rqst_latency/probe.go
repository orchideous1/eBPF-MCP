//go:build linux
//go:generate go tool bpf2go -cflags "-O2" -tags linux bpf svc_rqst_latency.c -- -I ../../headers

package svcrqstlatency

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
	probes.Register("svc_rqst_latency", func() probes.Probe {
		return NewSvcRqstLatencyProbe()
	})
}

type SvcRqstLatencyProbe struct {
	probes.BaseProbe

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	cancel context.CancelFunc
	done   chan struct{}

	dbConn   *sql.Conn
	appender *duckdb.Appender
}

func NewSvcRqstLatencyProbe() *SvcRqstLatencyProbe {
	// 从YAML加载元数据
	meta, exists := probes.GetProbeMetadata("svc_rqst_latency")
	if !exists {
		// 如果YAML中没有，使用默认元数据
		meta = probes.ProbeMetadata{
			Type:        "svc_rqst_latency",
			Title:       "SVC请求延迟",
			Layer:       "SVC",
			Level:       "L2",
			Scene:       "度量SVC请求从process到send的延迟，包含事务ID",
			Entrypoints: []string{"svc_process", "svc_send"},
			Params:      []probes.ParamField{},
			Outputs: probes.OutputConfig{
				Fields: []probes.OutputField{
					{Name: "xid", Type: "u32", Description: "RPC事务ID（XID）"},
					{Name: "latency", Type: "u64", Description: "SVC请求处理延迟（纳秒）"},
					{Name: "start_timestamp", Type: "u64", Description: "SVC请求开始时间戳"},
				},
			},
			Risks: "系统调用频率较低，风险可控",
		}
	}
	return &SvcRqstLatencyProbe{
		BaseProbe: probes.NewBaseProbe(meta),
	}
}

func (p *SvcRqstLatencyProbe) Name() string {
	return "svc_rqst_latency"
}

func (p *SvcRqstLatencyProbe) Start(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return logx.ErrDBIsNil
	}

	// 1. Setup DuckDB table and appender
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS svc_rqst_latency (
xid UINTEGER,
latency UBIGINT,
start_timestamp UBIGINT
)`)
	if err != nil {
		return logx.NewDomainErrorWithCause(logx.ErrorDBOperation, "creating table", err)
	}

	p.appender, p.dbConn, err = database.NewDuckDBAppender(ctx, db, "", "svc_rqst_latency")
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorDBOperation, "creating appender", err)
	}

	// 2. Load BPF objects
	if err := loadBpfObjects(&p.objs, nil); err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "loading objects", err)
	}

	// 3. Attach tracing - svc_process
	processLink, err := link.AttachTracing(link.TracingOptions{
		Program: p.objs.SvcProcessEntry,
	})
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "attaching svc_process tracing", err)
	}
	p.links = append(p.links, processLink)

	// 4. Attach tracing - svc_send
	sendLink, err := link.AttachTracing(link.TracingOptions{
		Program: p.objs.SvcSendEntry,
	})
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "attaching svc_send tracing", err)
	}
	p.links = append(p.links, sendLink)

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
	return nil
}

func (p *SvcRqstLatencyProbe) consume(ctx context.Context) {
	defer close(p.done)

	var event bpfEvent
	count := 0

	for {
		// 检查 context 是否已取消
		select {
		case <-ctx.Done():
			log.Println("[svc_rqst_latency] context cancelled, exiting consumer")
			return
		default:
		}

		// 阻塞读取，但会被 reader.Close() 打断
		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[svc_rqst_latency] ringbuf closed, exiting consumer")
				return
			}
			// 其他错误继续循环
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("[svc_rqst_latency] parsing event: %v", err)
			continue
		}

		err = p.appender.AppendRow(
			event.Xid,
			event.Latency,
			event.StartTimestamp,
		)
		if err != nil {
			log.Printf("[svc_rqst_latency] appending row: %v", err)
		}

		count++
		if count >= 100 {
			if err := p.appender.Flush(); err != nil {
				log.Printf("[svc_rqst_latency] flushing appender: %v", err)
			}
			count = 0
		}
	}
}

func (p *SvcRqstLatencyProbe) Stop() error {
	log.Println("[svc_rqst_latency] Stop() called, shutting down...")

	// 1. 取消 context，触发 reader.Close() 和 consume 退出
	if p.cancel != nil {
		p.cancel()
		log.Println("[svc_rqst_latency] context cancelled")
	}

	// 2. 等待 consume goroutine 真正退出
	if p.done != nil {
		<-p.done
		log.Println("[svc_rqst_latency] consumer exited")
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
	log.Println("[svc_rqst_latency] Stop() completed")
	return nil
}

// Flush 强制将缓冲区中的数据写入数据库
func (p *SvcRqstLatencyProbe) Flush() error {
	if p.appender != nil {
		return p.appender.Flush()
	}
	return nil
}

// Update 支持运行时配置更新（本探针无过滤参数，为空实现）
func (p *SvcRqstLatencyProbe) Update(config map[string]interface{}) error {
	// 本探针无过滤参数，无需更新
	return nil
}
