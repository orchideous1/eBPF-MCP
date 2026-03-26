package database

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/duckdb/duckdb-go/v2"
)

// NewDuckDBAppender returns an Appender for a specific table
func NewDuckDBAppender(ctx context.Context, db *sql.DB, schema, table string) (*duckdb.Appender, *sql.Conn, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get connection: %w", err)
	}

	var appender *duckdb.Appender
	err = conn.Raw(func(driverConn any) error {
		duckdbConn, ok := driverConn.(*duckdb.Conn)
		if !ok {
			return fmt.Errorf("connection is not a duckdb.Conn")
		}

		app, err := duckdb.NewAppenderFromConn(duckdbConn, schema, table)
		if err != nil {
			return err
		}
		appender = app
		return nil
	})

	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	return appender, conn, nil
}