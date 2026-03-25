//go:build linux

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

	"ebpf-mcp/database"
	"ebpf-mcp/internal/probes"
)

func init() {
	probes.Register("nfs_file_read", func() probes.Probe {
		return &NFSFileReadProbe{}
	})
}

type NFSFileReadProbe struct {
	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader
	cancel context.CancelFunc

	dbConn   *sql.Conn
	appender *duckdb.Appender
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

	go func() {
		<-evtCtx.Done()
		if p.reader != nil {
			p.reader.Close() // Unblock reader loop.
		}
	}()

	go p.consume()

	return nil
}

func (p *NFSFileReadProbe) consume() {
	var event bpfEvent
	count := 0

	for {
		record, err := p.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("ringbuf closed, exiting nfs_file_read consumer")
				return
			}
			log.Printf("reading from ringbuf: %v", err)
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
		if count >= 1000 {
			if err := p.appender.Flush(); err != nil {
				log.Printf("flushing appender: %v", err)
			}
			count = 0
		}
	}
}

func (p *NFSFileReadProbe) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}

	if p.reader != nil {
		_ = p.reader.Close()
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
	return nil
}

func (p *NFSFileReadProbe) Update(config map[string]interface{}) error {
	if config == nil {
		return nil
	}
	if p.objs.FilterPid == nil || p.objs.IsGetName == nil || p.objs.IsGetSize == nil {
		return fmt.Errorf("probe is not started")
	}

	if raw, ok := config["filter_pid"]; ok {
		pid, err := toUint64(raw)
		if err != nil {
			return fmt.Errorf("invalid filter_pid: %w", err)
		}
		if err := p.objs.FilterPid.Set(pid); err != nil {
			return fmt.Errorf("set filter_pid: %w", err)
		}
	}

	if raw, ok := config["is_get_name"]; ok {
		v, err := toBool(raw)
		if err != nil {
			return fmt.Errorf("invalid is_get_name: %w", err)
		}
		if err := p.objs.IsGetName.Set(v); err != nil {
			return fmt.Errorf("set is_get_name: %w", err)
		}
	}

	if raw, ok := config["is_get_size"]; ok {
		v, err := toBool(raw)
		if err != nil {
			return fmt.Errorf("invalid is_get_size: %w", err)
		}
		if err := p.objs.IsGetSize.Set(v); err != nil {
			return fmt.Errorf("set is_get_size: %w", err)
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
