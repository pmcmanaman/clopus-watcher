package db

import (
	"database/sql"
	"sort"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type Run struct {
	ID              int
	StartedAt       string
	EndedAt         string
	Namespace       string
	Mode            string
	Status          string // ok, fixed, failed, running
	PodCount        int
	ErrorCount      int
	FixCount        int
	Report          string
	Log             string
	ProactiveChecks bool
}

type Fix struct {
	ID           int
	RunID        int
	Timestamp    string
	Namespace    string
	PodName      string
	ErrorType    string
	ErrorMessage string
	FixApplied   string
	Status       string
}

type NamespaceStats struct {
	Namespace   string
	RunCount    int
	OkCount     int
	FixedCount  int
	FailedCount int
}

// Analytics types

type ErrorTrendData struct {
	Date       string `json:"date"`
	Namespace  string `json:"namespace"`
	ErrorCount int    `json:"error_count"`
	FixCount   int    `json:"fix_count"`
}

type FixSuccessRate struct {
	Total   int     `json:"total"`
	Success int     `json:"success"`
	Failed  int     `json:"failed"`
	Rate    float64 `json:"rate"`
}

type ProblematicPod struct {
	PodName    string `json:"pod_name"`
	Namespace  string `json:"namespace"`
	ErrorCount int    `json:"error_count"`
	LastSeen   string `json:"last_seen"`
}

type CategoryBreakdown struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// Advanced filter types

type DateRange struct {
	Start string
	End   string
}

type AdvancedFilters struct {
	Namespace  string
	Status     string
	Search     string
	DateRange  *DateRange
	PodName    string
}

type DB struct {
	conn *sql.DB
}

func New(path string) (*DB, error) {
	conn, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	// Create runs table
	_, err = conn.Exec(`
		CREATE TABLE IF NOT EXISTS runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			started_at TEXT NOT NULL,
			ended_at TEXT,
			namespace TEXT NOT NULL,
			mode TEXT NOT NULL DEFAULT 'autonomous',
			status TEXT NOT NULL DEFAULT 'running',
			pod_count INTEGER DEFAULT 0,
			error_count INTEGER DEFAULT 0,
			fix_count INTEGER DEFAULT 0,
			report TEXT,
			log TEXT
		)
	`)
	if err != nil {
		return nil, err
	}

	// Create fixes table with run_id
	_, err = conn.Exec(`
		CREATE TABLE IF NOT EXISTS fixes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id INTEGER,
			timestamp TEXT NOT NULL,
			namespace TEXT NOT NULL,
			pod_name TEXT NOT NULL,
			error_type TEXT NOT NULL,
			error_message TEXT,
			fix_applied TEXT,
			status TEXT DEFAULT 'pending',
			FOREIGN KEY (run_id) REFERENCES runs(id)
		)
	`)
	if err != nil {
		return nil, err
	}

	// Add run_id column if it doesn't exist (migration for existing DBs)
	conn.Exec(`ALTER TABLE fixes ADD COLUMN run_id INTEGER`)

	// Add proactive_checks column if it doesn't exist (migration for existing DBs)
	conn.Exec(`ALTER TABLE runs ADD COLUMN proactive_checks INTEGER DEFAULT 0`)

	// Create indices for better query performance
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_runs_namespace ON runs(namespace)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at DESC)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_runs_namespace_status ON runs(namespace, status)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_fixes_run_id ON fixes(run_id)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_fixes_timestamp ON fixes(timestamp DESC)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_fixes_namespace ON fixes(namespace)`)

	// Analytics indexes
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_runs_started_at_namespace ON runs(started_at, namespace)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_fixes_error_type ON fixes(error_type)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_fixes_pod_name ON fixes(pod_name)`)
	conn.Exec(`CREATE INDEX IF NOT EXISTS idx_fixes_namespace_timestamp ON fixes(namespace, timestamp)`)

	return &DB{conn: conn}, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

// Run operations

func (db *DB) CreateRun(namespace, mode string) (int64, error) {
	result, err := db.conn.Exec(`
		INSERT INTO runs (started_at, namespace, mode, status)
		VALUES (datetime('now'), ?, ?, 'running')
	`, namespace, mode)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (db *DB) CompleteRun(id int64, status string, podCount, errorCount, fixCount int, report, log string) error {
	_, err := db.conn.Exec(`
		UPDATE runs SET
			ended_at = datetime('now'),
			status = ?,
			pod_count = ?,
			error_count = ?,
			fix_count = ?,
			report = ?,
			log = ?
		WHERE id = ?
	`, status, podCount, errorCount, fixCount, report, log, id)
	return err
}

func (db *DB) GetRuns(namespace string, limit int) ([]Run, error) {
	return db.GetRunsPaginated(namespace, limit, 0, "", "")
}

// GetRunsPaginated returns runs with pagination and optional filters
// Namespace filtering uses LIKE to match runs containing the namespace in comma-separated lists
func (db *DB) GetRunsPaginated(namespace string, limit, offset int, status, search string) ([]Run, error) {
	query := `
		SELECT id, started_at, COALESCE(ended_at, ''), namespace, mode, status,
		       pod_count, error_count, fix_count, COALESCE(report, ''), COALESCE(log, ''),
		       COALESCE(proactive_checks, 0)
		FROM runs
		WHERE 1=1
	`
	args := []interface{}{}

	if namespace != "" {
		// Match namespace in comma-separated list: exact match, at start, at end, or in middle
		query += " AND (namespace = ? OR namespace LIKE ? OR namespace LIKE ? OR namespace LIKE ?)"
		args = append(args, namespace, namespace+",%", "%,"+namespace, "%,"+namespace+",%")
	}

	if status != "" {
		if status == "issues" {
			query += " AND (status = 'failed' OR status = 'issues_found')"
		} else {
			query += " AND status = ?"
			args = append(args, status)
		}
	}

	if search != "" {
		query += " AND (namespace LIKE ? OR report LIKE ?)"
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern)
	}

	query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []Run
	for rows.Next() {
		var r Run
		err := rows.Scan(&r.ID, &r.StartedAt, &r.EndedAt, &r.Namespace, &r.Mode,
			&r.Status, &r.PodCount, &r.ErrorCount, &r.FixCount, &r.Report, &r.Log, &r.ProactiveChecks)
		if err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}
	return runs, nil
}

// CountRuns returns total count of runs matching filters
// Namespace filtering uses LIKE to match runs containing the namespace in comma-separated lists
func (db *DB) CountRuns(namespace, status, search string) (int, error) {
	query := "SELECT COUNT(*) FROM runs WHERE 1=1"
	args := []interface{}{}

	if namespace != "" {
		// Match namespace in comma-separated list: exact match, at start, at end, or in middle
		query += " AND (namespace = ? OR namespace LIKE ? OR namespace LIKE ? OR namespace LIKE ?)"
		args = append(args, namespace, namespace+",%", "%,"+namespace, "%,"+namespace+",%")
	}

	if status != "" {
		if status == "issues" {
			query += " AND (status = 'failed' OR status = 'issues_found')"
		} else {
			query += " AND status = ?"
			args = append(args, status)
		}
	}

	if search != "" {
		query += " AND (namespace LIKE ? OR report LIKE ?)"
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern)
	}

	var count int
	err := db.conn.QueryRow(query, args...).Scan(&count)
	return count, err
}

func (db *DB) GetRun(id int) (*Run, error) {
	var r Run
	err := db.conn.QueryRow(`
		SELECT id, started_at, COALESCE(ended_at, ''), namespace, mode, status,
		       pod_count, error_count, fix_count, COALESCE(report, ''), COALESCE(log, ''),
		       COALESCE(proactive_checks, 0)
		FROM runs WHERE id = ?
	`, id).Scan(&r.ID, &r.StartedAt, &r.EndedAt, &r.Namespace, &r.Mode,
		&r.Status, &r.PodCount, &r.ErrorCount, &r.FixCount, &r.Report, &r.Log, &r.ProactiveChecks)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (db *DB) GetLastRunTime(namespace string) (string, error) {
	var lastRun string
	err := db.conn.QueryRow(`
		SELECT COALESCE(MAX(ended_at), '') FROM runs WHERE namespace = ? AND status != 'running'
	`, namespace).Scan(&lastRun)
	return lastRun, err
}

// Namespace operations

// GetNamespaces returns distinct individual namespaces extracted from comma-separated namespace fields
// This is optimized to only return namespace names without computing stats (which is expensive)
func (db *DB) GetNamespaces() ([]NamespaceStats, error) {
	// First get all unique namespace strings from runs
	rows, err := db.conn.Query(`SELECT DISTINCT namespace FROM runs ORDER BY namespace`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Parse comma-separated namespaces and collect unique ones
	nsSet := make(map[string]bool)
	for rows.Next() {
		var nsField string
		if err := rows.Scan(&nsField); err != nil {
			return nil, err
		}
		// Split by comma and add each namespace
		for _, ns := range strings.Split(nsField, ",") {
			ns = strings.TrimSpace(ns)
			if ns != "" {
				nsSet[ns] = true
			}
		}
	}

	// Just return namespace names (stats computed only when selected)
	var stats []NamespaceStats
	for ns := range nsSet {
		stats = append(stats, NamespaceStats{Namespace: ns})
	}

	// Sort by namespace name
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Namespace < stats[j].Namespace
	})

	return stats, nil
}

// GetNamespaceStats returns stats for runs that contain the given namespace
// (namespace can be part of a comma-separated list in the database)
// Optimized to use a single query instead of 4 separate queries
func (db *DB) GetNamespaceStats(namespace string) (*NamespaceStats, error) {
	var s NamespaceStats
	s.Namespace = namespace

	// Match namespace in comma-separated list: exact match, at start, at end, or in middle
	// Single query to get all stats at once
	err := db.conn.QueryRow(`
		SELECT
			COUNT(*) as run_count,
			SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END) as ok_count,
			SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed_count,
			SUM(CASE WHEN status = 'failed' OR status = 'issues_found' THEN 1 ELSE 0 END) as failed_count
		FROM runs
		WHERE namespace = ? OR namespace LIKE ? OR namespace LIKE ? OR namespace LIKE ?
	`, namespace, namespace+",%", "%,"+namespace, "%,"+namespace+",%").Scan(&s.RunCount, &s.OkCount, &s.FixedCount, &s.FailedCount)

	if err != nil {
		return nil, err
	}

	return &s, nil
}

// GetAllNamespacesStats returns aggregated stats across all namespaces
// Optimized to use a single query
func (db *DB) GetAllNamespacesStats() (*NamespaceStats, error) {
	var s NamespaceStats
	s.Namespace = "All Namespaces"

	err := db.conn.QueryRow(`
		SELECT
			COUNT(*) as run_count,
			SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END) as ok_count,
			SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed_count,
			SUM(CASE WHEN status = 'failed' OR status = 'issues_found' THEN 1 ELSE 0 END) as failed_count
		FROM runs
	`).Scan(&s.RunCount, &s.OkCount, &s.FixedCount, &s.FailedCount)

	if err != nil {
		return nil, err
	}

	return &s, nil
}

// Fix operations

func (db *DB) GetFixes(limit int) ([]Fix, error) {
	rows, err := db.conn.Query(`
		SELECT id, COALESCE(run_id, 0), timestamp, namespace, pod_name, error_type,
		       COALESCE(error_message, ''), COALESCE(fix_applied, ''), status
		FROM fixes
		ORDER BY timestamp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fixes []Fix
	for rows.Next() {
		var f Fix
		err := rows.Scan(&f.ID, &f.RunID, &f.Timestamp, &f.Namespace, &f.PodName,
			&f.ErrorType, &f.ErrorMessage, &f.FixApplied, &f.Status)
		if err != nil {
			return nil, err
		}
		fixes = append(fixes, f)
	}
	return fixes, nil
}

func (db *DB) GetFixesByRun(runID int) ([]Fix, error) {
	rows, err := db.conn.Query(`
		SELECT id, COALESCE(run_id, 0), timestamp, namespace, pod_name, error_type,
		       COALESCE(error_message, ''), COALESCE(fix_applied, ''), status
		FROM fixes
		WHERE run_id = ?
		ORDER BY timestamp DESC
	`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fixes []Fix
	for rows.Next() {
		var f Fix
		err := rows.Scan(&f.ID, &f.RunID, &f.Timestamp, &f.Namespace, &f.PodName,
			&f.ErrorType, &f.ErrorMessage, &f.FixApplied, &f.Status)
		if err != nil {
			return nil, err
		}
		fixes = append(fixes, f)
	}
	return fixes, nil
}

func (db *DB) GetStats() (total, success, failed, pending int, err error) {
	err = db.conn.QueryRow("SELECT COUNT(*) FROM fixes").Scan(&total)
	if err != nil {
		return
	}
	err = db.conn.QueryRow("SELECT COUNT(*) FROM fixes WHERE status = 'success'").Scan(&success)
	if err != nil {
		return
	}
	err = db.conn.QueryRow("SELECT COUNT(*) FROM fixes WHERE status = 'failed'").Scan(&failed)
	if err != nil {
		return
	}
	err = db.conn.QueryRow("SELECT COUNT(*) FROM fixes WHERE status = 'pending' OR status = 'analyzing'").Scan(&pending)
	return
}

// DeleteRun deletes a specific run and its associated fixes
func (db *DB) DeleteRun(runID int) error {
	// Delete fixes associated with this run
	_, err := db.conn.Exec(`DELETE FROM fixes WHERE run_id = ?`, runID)
	if err != nil {
		return err
	}

	// Delete the run
	_, err = db.conn.Exec(`DELETE FROM runs WHERE id = ?`, runID)
	return err
}

// ResetDatabase deletes all runs and fixes from the database
func (db *DB) ResetDatabase() error {
	// Delete all fixes first (foreign key)
	_, err := db.conn.Exec(`DELETE FROM fixes`)
	if err != nil {
		return err
	}

	// Delete all runs
	_, err = db.conn.Exec(`DELETE FROM runs`)
	if err != nil {
		return err
	}

	// Reclaim space
	db.conn.Exec(`VACUUM`)

	return nil
}

// CleanupOldRuns deletes runs and their associated fixes older than the specified number of days
// Returns the number of deleted runs
func (db *DB) CleanupOldRuns(retentionDays int) (int64, error) {
	// First delete fixes associated with old runs
	_, err := db.conn.Exec(`
		DELETE FROM fixes WHERE run_id IN (
			SELECT id FROM runs WHERE started_at < datetime('now', ? || ' days')
		)
	`, -retentionDays)
	if err != nil {
		return 0, err
	}

	// Then delete old runs
	result, err := db.conn.Exec(`
		DELETE FROM runs WHERE started_at < datetime('now', ? || ' days')
	`, -retentionDays)
	if err != nil {
		return 0, err
	}

	deleted, _ := result.RowsAffected()

	// Run VACUUM to reclaim space (only if we deleted something)
	if deleted > 0 {
		db.conn.Exec(`VACUUM`)
	}

	return deleted, nil
}

// Analytics query functions

// GetErrorTrend returns daily error/fix counts for the specified time range
func (db *DB) GetErrorTrend(namespace string, days int) ([]ErrorTrendData, error) {
	query := `
		SELECT
			date(started_at) as date,
			namespace,
			SUM(error_count) as error_count,
			SUM(fix_count) as fix_count
		FROM runs
		WHERE started_at >= datetime('now', ? || ' days')
	`
	args := []interface{}{-days}

	if namespace != "" {
		query += " AND (namespace = ? OR namespace LIKE ? OR namespace LIKE ? OR namespace LIKE ?)"
		args = append(args, namespace, namespace+",%", "%,"+namespace, "%,"+namespace+",%")
	}

	query += " GROUP BY date(started_at), namespace ORDER BY date ASC"

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var data []ErrorTrendData
	for rows.Next() {
		var d ErrorTrendData
		if err := rows.Scan(&d.Date, &d.Namespace, &d.ErrorCount, &d.FixCount); err != nil {
			return nil, err
		}
		data = append(data, d)
	}
	return data, nil
}

// GetErrorTrendAggregated returns daily totals (not broken down by namespace)
func (db *DB) GetErrorTrendAggregated(namespace string, days int) ([]ErrorTrendData, error) {
	query := `
		SELECT
			date(started_at) as date,
			'' as namespace,
			SUM(error_count) as error_count,
			SUM(fix_count) as fix_count
		FROM runs
		WHERE started_at >= datetime('now', ? || ' days')
	`
	args := []interface{}{-days}

	if namespace != "" {
		query += " AND (namespace = ? OR namespace LIKE ? OR namespace LIKE ? OR namespace LIKE ?)"
		args = append(args, namespace, namespace+",%", "%,"+namespace, "%,"+namespace+",%")
	}

	query += " GROUP BY date(started_at) ORDER BY date ASC"

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var data []ErrorTrendData
	for rows.Next() {
		var d ErrorTrendData
		if err := rows.Scan(&d.Date, &d.Namespace, &d.ErrorCount, &d.FixCount); err != nil {
			return nil, err
		}
		data = append(data, d)
	}
	return data, nil
}

// GetFixSuccessRate calculates fix success rate for a time period
func (db *DB) GetFixSuccessRate(namespace string, days int) (*FixSuccessRate, error) {
	query := `
		SELECT
			COUNT(*) as total,
			SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success,
			SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
		FROM fixes
		WHERE timestamp >= datetime('now', ? || ' days')
	`
	args := []interface{}{-days}

	if namespace != "" {
		query += " AND (namespace = ? OR namespace LIKE ? OR namespace LIKE ? OR namespace LIKE ?)"
		args = append(args, namespace, namespace+",%", "%,"+namespace, "%,"+namespace+",%")
	}

	var rate FixSuccessRate
	err := db.conn.QueryRow(query, args...).Scan(&rate.Total, &rate.Success, &rate.Failed)
	if err != nil {
		return nil, err
	}

	if rate.Total > 0 {
		rate.Rate = float64(rate.Success) / float64(rate.Total) * 100
	}

	return &rate, nil
}

// GetMostProblematicPods returns pods ranked by error frequency
func (db *DB) GetMostProblematicPods(namespace string, days, limit int) ([]ProblematicPod, error) {
	query := `
		SELECT
			pod_name,
			namespace,
			COUNT(*) as error_count,
			MAX(timestamp) as last_seen
		FROM fixes
		WHERE timestamp >= datetime('now', ? || ' days')
	`
	args := []interface{}{-days}

	if namespace != "" {
		query += " AND (namespace = ? OR namespace LIKE ? OR namespace LIKE ? OR namespace LIKE ?)"
		args = append(args, namespace, namespace+",%", "%,"+namespace, "%,"+namespace+",%")
	}

	query += " GROUP BY pod_name, namespace ORDER BY error_count DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pods []ProblematicPod
	for rows.Next() {
		var p ProblematicPod
		if err := rows.Scan(&p.PodName, &p.Namespace, &p.ErrorCount, &p.LastSeen); err != nil {
			return nil, err
		}
		pods = append(pods, p)
	}
	return pods, nil
}

// GetCategoryBreakdown returns error distribution by error_type
func (db *DB) GetCategoryBreakdown(namespace string, days int) ([]CategoryBreakdown, error) {
	query := `
		SELECT
			error_type as category,
			COUNT(*) as count
		FROM fixes
		WHERE timestamp >= datetime('now', ? || ' days')
		AND error_type != ''
	`
	args := []interface{}{-days}

	if namespace != "" {
		query += " AND (namespace = ? OR namespace LIKE ? OR namespace LIKE ? OR namespace LIKE ?)"
		args = append(args, namespace, namespace+",%", "%,"+namespace, "%,"+namespace+",%")
	}

	query += " GROUP BY error_type ORDER BY count DESC"

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var breakdown []CategoryBreakdown
	for rows.Next() {
		var c CategoryBreakdown
		if err := rows.Scan(&c.Category, &c.Count); err != nil {
			return nil, err
		}
		breakdown = append(breakdown, c)
	}
	return breakdown, nil
}

// GetRunsWithAdvancedFilters returns runs matching all specified filters
func (db *DB) GetRunsWithAdvancedFilters(filters AdvancedFilters, limit, offset int) ([]Run, error) {
	query := `
		SELECT id, started_at, COALESCE(ended_at, ''), namespace, mode, status,
		       pod_count, error_count, fix_count, COALESCE(report, ''), COALESCE(log, ''),
		       COALESCE(proactive_checks, 0)
		FROM runs
		WHERE 1=1
	`
	args := []interface{}{}

	if filters.Namespace != "" {
		query += " AND (namespace = ? OR namespace LIKE ? OR namespace LIKE ? OR namespace LIKE ?)"
		args = append(args, filters.Namespace, filters.Namespace+",%", "%,"+filters.Namespace, "%,"+filters.Namespace+",%")
	}

	if filters.Status != "" {
		if filters.Status == "issues" {
			query += " AND (status = 'failed' OR status = 'issues_found')"
		} else {
			query += " AND status = ?"
			args = append(args, filters.Status)
		}
	}

	if filters.Search != "" {
		query += " AND (namespace LIKE ? OR report LIKE ?)"
		searchPattern := "%" + filters.Search + "%"
		args = append(args, searchPattern, searchPattern)
	}

	if filters.DateRange != nil {
		if filters.DateRange.Start != "" {
			query += " AND started_at >= ?"
			args = append(args, filters.DateRange.Start)
		}
		if filters.DateRange.End != "" {
			query += " AND started_at <= ?"
			args = append(args, filters.DateRange.End+" 23:59:59")
		}
	}

	if filters.PodName != "" {
		// Search for runs that have fixes matching this pod name
		query += " AND id IN (SELECT DISTINCT run_id FROM fixes WHERE pod_name LIKE ?)"
		args = append(args, "%"+filters.PodName+"%")
	}

	query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var runs []Run
	for rows.Next() {
		var r Run
		err := rows.Scan(&r.ID, &r.StartedAt, &r.EndedAt, &r.Namespace, &r.Mode,
			&r.Status, &r.PodCount, &r.ErrorCount, &r.FixCount, &r.Report, &r.Log, &r.ProactiveChecks)
		if err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}
	return runs, nil
}

// CountRunsWithAdvancedFilters counts runs matching all specified filters
func (db *DB) CountRunsWithAdvancedFilters(filters AdvancedFilters) (int, error) {
	query := "SELECT COUNT(*) FROM runs WHERE 1=1"
	args := []interface{}{}

	if filters.Namespace != "" {
		query += " AND (namespace = ? OR namespace LIKE ? OR namespace LIKE ? OR namespace LIKE ?)"
		args = append(args, filters.Namespace, filters.Namespace+",%", "%,"+filters.Namespace, "%,"+filters.Namespace+",%")
	}

	if filters.Status != "" {
		if filters.Status == "issues" {
			query += " AND (status = 'failed' OR status = 'issues_found')"
		} else {
			query += " AND status = ?"
			args = append(args, filters.Status)
		}
	}

	if filters.Search != "" {
		query += " AND (namespace LIKE ? OR report LIKE ?)"
		searchPattern := "%" + filters.Search + "%"
		args = append(args, searchPattern, searchPattern)
	}

	if filters.DateRange != nil {
		if filters.DateRange.Start != "" {
			query += " AND started_at >= ?"
			args = append(args, filters.DateRange.Start)
		}
		if filters.DateRange.End != "" {
			query += " AND started_at <= ?"
			args = append(args, filters.DateRange.End+" 23:59:59")
		}
	}

	if filters.PodName != "" {
		query += " AND id IN (SELECT DISTINCT run_id FROM fixes WHERE pod_name LIKE ?)"
		args = append(args, "%"+filters.PodName+"%")
	}

	var count int
	err := db.conn.QueryRow(query, args...).Scan(&count)
	return count, err
}
