package probes

import (
	"context"
	"database/sql"
)

// Probe defines the interface for eBPF probes
type Probe interface {
	Name() string
	Start(ctx context.Context, dbConn *sql.DB) error
	Stop() error
	Update(config map[string]interface{}) error
}