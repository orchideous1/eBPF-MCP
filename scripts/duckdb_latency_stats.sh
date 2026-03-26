#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   scripts/duckdb_latency_stats.sh [db_path] [table_name] [latency_column]
# Example:
#   scripts/duckdb_latency_stats.sh database/nfs-probe-e2e.duckdb nfs_file_read lat

DB_PATH="${1:-database/nfs-probe-e2e.duckdb}"
TABLE_NAME="${2:-nfs_file_read}"
LAT_COL="${3:-lat}"

if ! command -v duckdb >/dev/null 2>&1; then
  echo "ERROR: duckdb CLI not found in PATH."
  exit 1
fi

if [[ ! -r "$DB_PATH" ]]; then
  echo "ERROR: database file is not readable: $DB_PATH"
  exit 1
fi

if ! duckdb -readonly "$DB_PATH" -c "SELECT 1 FROM information_schema.tables WHERE table_schema='main' AND table_name='${TABLE_NAME}' LIMIT 1;" >/dev/null 2>&1; then
  echo "ERROR: failed to inspect table metadata in database: $DB_PATH"
  exit 1
fi

TABLE_EXISTS=$(duckdb -readonly "$DB_PATH" -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='main' AND table_name='${TABLE_NAME}';" | tr -dc '0-9')
if [[ "${TABLE_EXISTS:-0}" -eq 0 ]]; then
  echo "ERROR: table not found: $TABLE_NAME"
  exit 1
fi

COL_EXISTS=$(duckdb -readonly "$DB_PATH" -c "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='main' AND table_name='${TABLE_NAME}' AND column_name='${LAT_COL}';" | tr -dc '0-9')
if [[ "${COL_EXISTS:-0}" -eq 0 ]]; then
  echo "ERROR: latency column not found: $LAT_COL (table: $TABLE_NAME)"
  echo "Hint: columns are:"
  duckdb -readonly "$DB_PATH" -c "PRAGMA table_info('${TABLE_NAME}');"
  exit 1
fi

echo "=== DuckDB Latency Basic Statistics ==="
echo "DB: $DB_PATH"
echo "Table: $TABLE_NAME"
echo "Latency Column: $LAT_COL"
echo

duckdb -readonly "$DB_PATH" <<SQL
.mode box
SELECT
  COUNT(*) AS total_rows,
  COUNT(${LAT_COL}) AS non_null_latency_rows,
  MIN(${LAT_COL}) AS min_latency,
  MAX(${LAT_COL}) AS max_latency,
  ROUND(AVG(${LAT_COL}), 3) AS avg_latency,
  quantile_cont(${LAT_COL}, 0.50) AS p50_latency,
  quantile_cont(${LAT_COL}, 0.90) AS p90_latency,
  quantile_cont(${LAT_COL}, 0.95) AS p95_latency,
  quantile_cont(${LAT_COL}, 0.99) AS p99_latency
FROM ${TABLE_NAME}
WHERE ${LAT_COL} IS NOT NULL;
SQL

echo
echo "=== Row Corresponding To P99 Latency (first row where latency >= p99) ==="

duckdb -readonly "$DB_PATH" <<SQL
.mode box
WITH stats AS (
  SELECT quantile_cont(${LAT_COL}, 0.99) AS p99_latency
  FROM ${TABLE_NAME}
  WHERE ${LAT_COL} IS NOT NULL
), p99_row AS (
  SELECT t.*
  FROM ${TABLE_NAME} t, stats s
  WHERE t.${LAT_COL} IS NOT NULL
    AND t.${LAT_COL} >= s.p99_latency
  ORDER BY t.${LAT_COL} ASC
  LIMIT 1
)
SELECT * FROM p99_row;
SQL
