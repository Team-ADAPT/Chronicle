# Chronicle — Database & History Repository

The **Database Layer** is Chronicle's structured memory. It applies foundational Database Management System (DBMS) principles to record, index, and query fine-grained host behavioural history locally.

---

## 1. DBMS Concepts Applied

| Concept | Implementation in Chronicle |
| --- | --- |
| **Relational Data Model** | Structured tables representing processes, events, behaviour windows, system metrics, baselines, and detections. |
| **Primary & Foreign Keys** | `instance_id` (UUID) guarantees identity across Linux PID recycling; cascading deletes and deferred foreign keys maintain integrity. |
| **Normalization** | Relational separation between atomic telemetry events, windowed time-slice aggregates, and persistent program-level baselines. |
| **Targeted Indexing** | Compound and temporal B-Tree indexes (`idx_proc_comm_start`, `idx_win_profile_label`, `idx_detections_inst_time`) ensure sub-millisecond retrieval. |
| **Query Optimization** | Temporal range filtering, analytical window functions, and indexed aggregations prevent full-table scans. |
| **ACID Transactions** | Batch ingestion transactions and atomic profile baseline calculations. |
| **Data Retention** | Configurable time-based and count-based pruning routines to prevent disk exhaustion. |

---

## 2. Dual-Engine Architecture

Chronicle implements a dual-engine architecture:

1. **PostgreSQL (Primary / Production):**
   - High-throughput concurrent writes for high-event server environments.
   - Rich JSONB indexing and parallel query execution.
   - Connected via `psycopg` (v3).

2. **SQLite (Embedded / Zero-Config Fallback):**
   - Self-contained, single-file embedded database (`data/chronicle.db`).
   - Default for out-of-the-box desktop execution without requiring a background PostgreSQL server daemon.
   - Complete parity in schema, indexes, and queries.

---

## 3. CLI Database Management

Chronicle provides a built-in CLI utility for database administration:

```bash
# 1. Run pending schema migrations
python3 -m chronicle.db migrate

# 2. Inspect database connectivity, engine, and migration status
python3 -m chronicle.db status

# 3. Compute or recompute historical behavioural baselines
python3 -m chronicle.db profile --min-obs 5

# 4. Ingest an eBPF collector dataset with automatic baseline calculation
python3 -m chronicle.db ingest /path/to/collector_run/ --auto-profile

# 5. Execute retention policy cleanup (dry-run mode available)
python3 -m chronicle.db retention --dry-run
```

---

## 4. Schema Files

- `database/schema.sql`: Consolidated master DDL schema.
- `chronicle/db/sql/`: Versioned migration files (`001_initial_schema.sql`, `002_profiles_and_detections.sql`, `003_advanced_profiling.sql`, `sqlite_schema.sql`).
