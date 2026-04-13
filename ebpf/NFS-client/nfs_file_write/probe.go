//go:build linux

//go:generate go tool bpf2go -cflags "-O2" -tags linux bpf nfs_file_write.c -- -I ../../headers

package nfsclient

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
	probes.Register("nfs_file_write", func() probes.Probe {
		return NewNFSFileWriteProbe()
	})
}

type NFSFileWriteProbe struct {
	probes.BaseProbe

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	cancel context.CancelFunc
	done   chan struct{}

	dbConn   *sql.Conn
	appender *duckdb.Appender
}

func NewNFSFileWriteProbe() *NFSFileWriteProbe {
	// 尝试从 YAML 加载元数据
	meta, exists := probes.GetProbeMetadata("nfs_file_write")
	if !exists {
		// 如果 YAML 中没有，使用默认元数据
		meta = probes.ProbeMetadata{
			Type:        "nfs_file_write",
			Title:       "客户端 NFS 文件写入",
			Layer:       "nfs-client",
			Level:       "L2",
			Scene:       "度量NFS-Client侧的文件写入请求的延迟与大小",
			Entrypoints: []string{"nfs_file_write"},
			Params: []probes.ParamField{
				{Name: "filter_pid", Type: "u32", Description: "过滤指定PID的进程", Optional: true},
				{Name: "filter_file", Type: "string", Description: "过滤指定文件名（支持通配符）", Optional: true},
				{Name: "filter_comm", Type: "string", Description: "过滤指定进程名", Optional: true},
			},
			Outputs: probes.OutputConfig{
				Fields: []probes.OutputField{
					{Name: "pid", Type: "u32", Description: "进程ID"},
					{Name: "lat", Type: "u64", Description: "延迟(纳秒)"},
					{Name: "time_stamp", Type: "u64", Description: "时间戳"},
					{Name: "size", Type: "u64", Description: "写入大小"},
					{Name: "comm", Type: "string", Description: "进程名"},
					{Name: "file", Type: "string", Description: "文件名"},
				},
			},
			Risks: "高并发I/O场景下全量追踪可能有开销",
		}
	}
	return &NFSFileWriteProbe{
		BaseProbe: probes.NewBaseProbe(meta),
	}
}

func (p *NFSFileWriteProbe) Name() string {
	return "nfs_file_write"
}

func (p *NFSFileWriteProbe) Start(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return logx.ErrDBIsNil
	}

	// 1. Setup DuckDB table and appender
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS nfs_file_write (
pid UINTEGER,
lat UBIGINT,
time_stamp UBIGINT,
size UBIGINT,
comm VARCHAR,
file VARCHAR
)`)
	if err != nil {
		return logx.NewDomainErrorWithCause(logx.ErrorDBOperation, "creating table", err)
	}

	p.appender, p.dbConn, err = database.NewDuckDBAppender(ctx, db, "", "nfs_file_write")
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
		Program: p.objs.NfsFileWrite,
	})
	if err != nil {
		p.Stop()
		return logx.NewDomainErrorWithCause(logx.ErrorProbeStartFailed, "attaching tracing", err)
	}
	p.links = append(p.links, entryLink)

	// Attach fexit program too so ringbuf events can be emitted.
	exitLink, err := link.AttachTracing(link.TracingOptions{
		Program: p.objs.NfsFileWriteExit,
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

	// 5. Start consuming - 使用独立 context，不依赖上层 ctx
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

func (p *NFSFileWriteProbe) consume(ctx context.Context) {
	defer close(p.done)

	var event bpfEvent
	count := 0

	for {
		// 检查 context 是否已取消
		select {
		case <-ctx.Done():
			log.Println("[nfs_file_write] context cancelled, exiting consumer")
			return
		default:
		}

		// 阻塞读取，但会被 reader.Close() 打断
		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[nfs_file_write] ringbuf closed, exiting consumer")
				return
			}
			// 其他错误继续循环，让 select 检查 context
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("[nfs_file_write] parsing event: %v", err)
			continue
		}

		comm := cStringFromInt8(event.Comm[:])
		file := cStringFromInt8(event.File[:])

		err = p.appender.AppendRow(event.Pid, event.Lat, event.TimeStamp, event.Size, comm, file)
		if err != nil {
			log.Printf("[nfs_file_write] appending row: %v", err)
		}

		count++
		if count >= 100 {
			if err := p.appender.Flush(); err != nil {
				log.Printf("[nfs_file_write] flushing appender: %v", err)
			}
			count = 0
		}
	}
}

func (p *NFSFileWriteProbe) Stop() error {
	log.Println("[nfs_file_write] Stop() called, shutting down...")

	// 1. 取消 context，触发 reader.Close() 和 consume 退出
	if p.cancel != nil {
		p.cancel()
		log.Println("[nfs_file_write] context cancelled")
	}

	// 2. 等待 consume goroutine 真正退出
	if p.done != nil {
		<-p.done
		log.Println("[nfs_file_write] consumer exited")
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
	log.Println("[nfs_file_write] Stop() completed")
	return nil
}

// Flush 强制将缓冲区中的数据写入数据库
func (p *NFSFileWriteProbe) Flush() error {
	if p.appender != nil {
		return p.appender.Flush()
	}
	return nil
}

func (p *NFSFileWriteProbe) Update(config map[string]interface{}) error {
	if config == nil {
		return nil
	}
	if p.objs.FilterPid == nil || p.objs.FilterFile == nil || p.objs.FilterComm == nil {
		return logx.ErrProbeNotStarted
	}

	// // 诊断：检查变量是否为只读
	// log.Printf("[DEBUG] FilterPid ReadOnly: %v", p.objs.FilterPid.ReadOnly())
	// log.Printf("[DEBUG] FilterFile ReadOnly: %v", p.objs.FilterFile.ReadOnly())
	// log.Printf("[DEBUG] FilterComm ReadOnly: %v", p.objs.FilterComm.ReadOnly())

	if raw, ok := config["filter_pid"]; ok {
		pid, err := toUint64(raw)
		if err != nil {
			return logx.NewDomainErrorWithCause(logx.ErrorInvalidArgument, "invalid filter_pid", err)
		}
		if err := p.objs.FilterPid.Set(pid); err != nil {
			return logx.NewDomainErrorWithCause(logx.ErrorProbeUpdateFailed, "set filter_pid", err)
		}
	}

	if raw, ok := config["filter_file"]; ok {
		s, ok := raw.(string)
		if !ok {
			return logx.NewDomainErrorWithCause(logx.ErrorInvalidArgument, fmt.Sprintf("invalid filter_file: expected string, got %T", raw), nil)
		}
		// 将字符串复制到固定大小的字节数组
		var fileBytes [16]byte
		copy(fileBytes[:], s)
		if err := p.objs.FilterFile.Set(fileBytes); err != nil {
			return logx.NewDomainErrorWithCause(logx.ErrorProbeUpdateFailed, "set filter_file", err)
		}
	}

	if raw, ok := config["filter_comm"]; ok {
		s, ok := raw.(string)
		if !ok {
			return logx.NewDomainErrorWithCause(logx.ErrorInvalidArgument, fmt.Sprintf("invalid filter_comm: expected string, got %T", raw), nil)
		}
		// 将字符串复制到固定大小的字节数组
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

func toBool(v interface{}) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, logx.Wrapf(logx.ErrUnsupportedType, "unsupported type %T", v)
	}
	return b, nil
}
