//go:build linux
//go:generate go tool bpf2go -cflags "-O2" -tags linux bpf nfs_file_read.c -- -I ../../headers
package nfsclient

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/duckdb/duckdb-go/v2"

	database "ebpf-mcp/internal/db"
	"ebpf-mcp/internal/probes"
)

func init() {
	probes.Register("nfs_file_read", func() probes.Probe {
		return NewNFSFileReadProbe()
	})
}

type NFSFileReadProbe struct {
	probes.BaseProbe

	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	cancel context.CancelFunc
	wg     sync.WaitGroup

	dbConn   *sql.Conn
	appender *duckdb.Appender
}

func NewNFSFileReadProbe() *NFSFileReadProbe {
	// 从YAML加载元数据
	meta, exists := probes.GetProbeMetadata("nfs_file_read")
	if !exists {
		// 如果YAML中没有，使用默认元数据
		meta = probes.ProbeMetadata{
			Type:        "nfs_file_read",
			Title:       "客户端 NFS 文件读取",
			Layer:       "nfs-client",
			Level:       "L2",
			Scene:       "度量NFS-Client侧的文件读取请求的延迟与大小",
			Entrypoints: []string{"nfs_file_read"},
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
					{Name: "size", Type: "u64", Description: "读取大小"},
					{Name: "comm", Type: "string", Description: "进程名"},
					{Name: "file", Type: "string", Description: "文件名"},
				},
			},
			Risks: "高并发I/O场景下全量追踪可能有开销",
		}
	}
	return &NFSFileReadProbe{
		BaseProbe: probes.NewBaseProbe(meta),
	}
}

func (p *NFSFileReadProbe) Name() string {
	return "nfs_file_read"
}

func (p *NFSFileReadProbe) Start(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("db is nil")
	}

	// 1. Setup DuckDB table and appender
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS nfs_file_read (
pid UBIGINT,
lat UBIGINT,
time_stamp UBIGINT,
size UBIGINT,
comm VARCHAR,
file VARCHAR
)`)
	if err != nil {
		return fmt.Errorf("creating table: %w", err)
	}

	p.appender, p.dbConn, err = database.NewDuckDBAppender(ctx, db, "", "nfs_file_read")
	if err != nil {
		p.Stop()
		return fmt.Errorf("creating appender: %w", err)
	}

	// 2. Load BPF objects
	if err := loadBpfObjects(&p.objs, nil); err != nil {
		p.Stop()
		return fmt.Errorf("loading objects: %w", err)
	}

	// 3. Attach tracing
	entryLink, err := link.AttachTracing(link.TracingOptions{
		Program: p.objs.NfsFileRead,
	})
	if err != nil {
		p.Stop()
		return fmt.Errorf("attaching tracing: %w", err)
	}
	p.links = append(p.links, entryLink)

	// Attach fexit program too so ringbuf events can be emitted.
	exitLink, err := link.AttachTracing(link.TracingOptions{
		Program: p.objs.NfsFileReadExit,
	})
	if err != nil {
		p.Stop()
		return fmt.Errorf("attaching tracing exit: %w", err)
	}
	p.links = append(p.links, exitLink)

	// 4. Setup Ringbuf reader
	rd, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		p.Stop()
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	p.reader = rd

	// 5. Start consuming
	evtCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	p.wg.Add(1)
	go p.consume()

	go func() {
		<-evtCtx.Done()
		if p.reader != nil {
			p.reader.Close() // Unblock reader loop.
		}
	}()

	return nil
}

func (p *NFSFileReadProbe) consume() {
	defer p.wg.Done()
	var event bpfEvent
	count := 0

	for {
		// 设置读取超时，避免无限阻塞
		p.reader.SetDeadline(time.Now().Add(100 * time.Millisecond))

		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[nfs_file_read] ringbuf closed, exiting consumer")
				return
			}
			// 超时错误是预期的，继续循环
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("[nfs_file_read] reading from ringbuf: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		comm := cStringFromInt8(event.Comm[:])
		file := cStringFromInt8(event.File[:])

		err = p.appender.AppendRow(event.Pid, event.Lat, event.TimeStamp, event.Size, comm, file)
		if err != nil {
			log.Printf("appending row: %v", err)
		}

		count++
		if count >= 100 {
			if err := p.appender.Flush(); err != nil {
				log.Printf("flushing appender: %v", err)
			}
			count = 0
		}
	}
}

func (p *NFSFileReadProbe) Stop() error {
	log.Println("[nfs_file_read] Stop() called, shutting down...")

	// 1. 先 Flush 数据
	if p.appender != nil {
		log.Println("[nfs_file_read] flushing pending data...")
		_ = p.appender.Flush()
	}

	// 2. 取消 context
	if p.cancel != nil {
		p.cancel()
		log.Println("[nfs_file_read] context cancelled")
	}

	// 3. 关闭 ringbuf reader，使 Read() 立即返回
	if p.reader != nil {
		_ = p.reader.Close()
		log.Println("[nfs_file_read] ringbuf reader closed")
	}

	// 4. 等待 consumer 退出（带 2 秒超时）
	log.Println("[nfs_file_read] waiting for consumer to finish (max 2s)...")
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("[nfs_file_read] consumer finished gracefully")
	case <-time.After(2 * time.Second):
		log.Println("[nfs_file_read] consumer wait timeout, forcing continue")
	}

	// 5. 清理资源
	if p.appender != nil {
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
	log.Println("[nfs_file_read] Stop() completed")
	return nil
}

// Flush 强制将缓冲区中的数据写入数据库
func (p *NFSFileReadProbe) Flush() error {
	if p.appender != nil {
		return p.appender.Flush()
	}
	return nil
}

func (p *NFSFileReadProbe) Update(config map[string]interface{}) error {
	if config == nil {
		return nil
	}
	if p.objs.FilterPid == nil || p.objs.FilterFile == nil || p.objs.FilterComm == nil {
		return fmt.Errorf("probe is not started")
	}

	// // 诊断：检查变量是否为只读
	// log.Printf("[DEBUG] FilterPid ReadOnly: %v", p.objs.FilterPid.ReadOnly())
	// log.Printf("[DEBUG] FilterFile ReadOnly: %v", p.objs.FilterFile.ReadOnly())
	// log.Printf("[DEBUG] FilterComm ReadOnly: %v", p.objs.FilterComm.ReadOnly())

	if raw, ok := config["filter_pid"]; ok {
		pid, err := toUint64(raw)
		if err != nil {
			return fmt.Errorf("invalid filter_pid: %w", err)
		}
		if err := p.objs.FilterPid.Set(pid); err != nil {
			return fmt.Errorf("set filter_pid: %w", err)
		}
	}

	if raw, ok := config["filter_file"]; ok {
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("invalid filter_file: expected string, got %T", raw)
		}
		// 限制长度并转换为字节数组
		var fileBytes [16]byte
		copy(fileBytes[:], s)
		if err := p.objs.FilterFile.Set(fileBytes); err != nil {
			return fmt.Errorf("set filter_file: %w", err)
		}
	}

	if raw, ok := config["filter_comm"]; ok {
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("invalid filter_comm: expected string, got %T", raw)
		}
		// 限制长度并转换为字节数组
		var commBytes [32]byte
		copy(commBytes[:], s)
		if err := p.objs.FilterComm.Set(commBytes); err != nil {
			return fmt.Errorf("set filter_comm: %w", err)
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
			return 0, fmt.Errorf("negative value")
		}
		return uint64(t), nil
	case int:
		if t < 0 {
			return 0, fmt.Errorf("negative value")
		}
		return uint64(t), nil
	case float64:
		if t < 0 {
			return 0, fmt.Errorf("negative value")
		}
		return uint64(t), nil
	default:
		return 0, fmt.Errorf("unsupported type %T", v)
	}
}

func toBool(v interface{}) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("unsupported type %T", v)
	}
	return b, nil
}
