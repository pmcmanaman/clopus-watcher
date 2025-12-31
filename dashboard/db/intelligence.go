package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// IssueFingerprint represents a unique issue pattern
type IssueFingerprint struct {
	ID              int       `json:"id"`
	Fingerprint     string    `json:"fingerprint"`
	ErrorType       string    `json:"error_type"`
	ErrorPattern    string    `json:"error_pattern"`
	Category        string    `json:"category"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	OccurrenceCount int       `json:"occurrence_count"`
	FixSuccessCount int       `json:"fix_success_count"`
	FixFailCount    int       `json:"fix_fail_count"`
	BestFix         string    `json:"best_fix"`
	BestFixRate     float64   `json:"best_fix_rate"`
	AffectedPods    string    `json:"affected_pods"` // JSON array of pod names
}

// FixOutcome tracks the success of fixes for fingerprinted issues
type FixOutcome struct {
	ID            int       `json:"id"`
	FingerprintID int       `json:"fingerprint_id"`
	FixID         int       `json:"fix_id"`
	FixApplied    string    `json:"fix_applied"`
	Success       bool      `json:"success"`
	Timestamp     time.Time `json:"timestamp"`
	Duration      int       `json:"duration_seconds"` // How long until issue resolved
}

// PodBaseline represents normal behavior metrics for a pod
type PodBaseline struct {
	ID                int       `json:"id"`
	PodName           string    `json:"pod_name"`
	Namespace         string    `json:"namespace"`
	AvgRestarts24h    float64   `json:"avg_restarts_24h"`
	AvgErrorsPerRun   float64   `json:"avg_errors_per_run"`
	NormalMemoryUsage float64   `json:"normal_memory_pct"`
	NormalCPUUsage    float64   `json:"normal_cpu_pct"`
	LastUpdated       time.Time `json:"last_updated"`
	DataPoints        int       `json:"data_points"`
	StdDevRestarts    float64   `json:"stddev_restarts"`
	StdDevErrors      float64   `json:"stddev_errors"`
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	ID          int       `json:"id"`
	RunID       int       `json:"run_id"`
	PodName     string    `json:"pod_name"`
	Namespace   string    `json:"namespace"`
	AnomalyType string    `json:"anomaly_type"` // restart_spike, error_spike, resource_spike
	Severity    string    `json:"severity"`
	ExpectedVal float64   `json:"expected_value"`
	ActualVal   float64   `json:"actual_value"`
	Deviation   float64   `json:"deviation"` // Standard deviations from mean
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
}

// IssueCorrelation represents a link between related issues
type IssueCorrelation struct {
	ID              int       `json:"id"`
	PrimaryFixID    int       `json:"primary_fix_id"`
	SecondaryFixID  int       `json:"secondary_fix_id"`
	CorrelationType string    `json:"correlation_type"` // cascade, shared_root, temporal
	Confidence      float64   `json:"confidence"`       // 0-1 score
	TimeWindowSec   int       `json:"time_window_sec"`
	Description     string    `json:"description"`
	Timestamp       time.Time `json:"timestamp"`
}

// Runbook represents auto-generated documentation for fixing issues
type Runbook struct {
	ID              int       `json:"id"`
	FingerprintID   int       `json:"fingerprint_id"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Steps           string    `json:"steps"` // JSON array
	Prerequisites   string    `json:"prerequisites"`
	SuccessRate     float64   `json:"success_rate"`
	AvgResolutionMs int64     `json:"avg_resolution_ms"`
	LastUpdated     time.Time `json:"last_updated"`
	UsageCount      int       `json:"usage_count"`
}

// RunbookStep represents a single step in a runbook
type RunbookStep struct {
	Order       int    `json:"order"`
	Action      string `json:"action"`
	Command     string `json:"command,omitempty"`
	Description string `json:"description"`
	Expected    string `json:"expected_outcome"`
	Fallback    string `json:"fallback,omitempty"`
}

// NodeHealth represents node-level health status
type NodeHealth struct {
	ID                int       `json:"id"`
	RunID             int       `json:"run_id"`
	NodeName          string    `json:"node_name"`
	Status            string    `json:"status"` // Ready, NotReady, Unknown
	MemoryPressure    bool      `json:"memory_pressure"`
	DiskPressure      bool      `json:"disk_pressure"`
	PIDPressure       bool      `json:"pid_pressure"`
	NetworkUnavail    bool      `json:"network_unavailable"`
	AllocatableCPU    string    `json:"allocatable_cpu"`
	AllocatableMemory string    `json:"allocatable_memory"`
	UsedCPU           string    `json:"used_cpu"`
	UsedMemory        string    `json:"used_memory"`
	PodCount          int       `json:"pod_count"`
	Conditions        string    `json:"conditions"` // JSON
	Timestamp         time.Time `json:"timestamp"`
}

// InitIntelligenceTables creates the tables for intelligence features
func (db *DB) InitIntelligenceTables() error {
	// Issue fingerprints table
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS issue_fingerprints (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fingerprint TEXT UNIQUE NOT NULL,
			error_type TEXT NOT NULL,
			error_pattern TEXT,
			category TEXT,
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			occurrence_count INTEGER DEFAULT 1,
			fix_success_count INTEGER DEFAULT 0,
			fix_fail_count INTEGER DEFAULT 0,
			best_fix TEXT,
			best_fix_rate REAL DEFAULT 0,
			affected_pods TEXT DEFAULT '[]'
		)
	`)
	if err != nil {
		return err
	}

	// Fix outcomes table
	_, err = db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS fix_outcomes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fingerprint_id INTEGER,
			fix_id INTEGER,
			fix_applied TEXT,
			success INTEGER DEFAULT 0,
			timestamp TEXT NOT NULL,
			duration_seconds INTEGER DEFAULT 0,
			FOREIGN KEY (fingerprint_id) REFERENCES issue_fingerprints(id),
			FOREIGN KEY (fix_id) REFERENCES fixes(id)
		)
	`)
	if err != nil {
		return err
	}

	// Pod baselines table
	_, err = db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS pod_baselines (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			pod_name TEXT NOT NULL,
			namespace TEXT NOT NULL,
			avg_restarts_24h REAL DEFAULT 0,
			avg_errors_per_run REAL DEFAULT 0,
			normal_memory_pct REAL DEFAULT 0,
			normal_cpu_pct REAL DEFAULT 0,
			last_updated TEXT NOT NULL,
			data_points INTEGER DEFAULT 0,
			stddev_restarts REAL DEFAULT 0,
			stddev_errors REAL DEFAULT 0,
			UNIQUE(pod_name, namespace)
		)
	`)
	if err != nil {
		return err
	}

	// Anomalies table
	_, err = db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS anomalies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id INTEGER,
			pod_name TEXT NOT NULL,
			namespace TEXT NOT NULL,
			anomaly_type TEXT NOT NULL,
			severity TEXT NOT NULL,
			expected_value REAL,
			actual_value REAL,
			deviation REAL,
			timestamp TEXT NOT NULL,
			description TEXT,
			FOREIGN KEY (run_id) REFERENCES runs(id)
		)
	`)
	if err != nil {
		return err
	}

	// Issue correlations table
	_, err = db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS issue_correlations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			primary_fix_id INTEGER,
			secondary_fix_id INTEGER,
			correlation_type TEXT NOT NULL,
			confidence REAL DEFAULT 0,
			time_window_sec INTEGER DEFAULT 0,
			description TEXT,
			timestamp TEXT NOT NULL,
			FOREIGN KEY (primary_fix_id) REFERENCES fixes(id),
			FOREIGN KEY (secondary_fix_id) REFERENCES fixes(id)
		)
	`)
	if err != nil {
		return err
	}

	// Runbooks table
	_, err = db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS runbooks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fingerprint_id INTEGER UNIQUE,
			title TEXT NOT NULL,
			description TEXT,
			steps TEXT DEFAULT '[]',
			prerequisites TEXT DEFAULT '[]',
			success_rate REAL DEFAULT 0,
			avg_resolution_ms INTEGER DEFAULT 0,
			last_updated TEXT NOT NULL,
			usage_count INTEGER DEFAULT 0,
			FOREIGN KEY (fingerprint_id) REFERENCES issue_fingerprints(id)
		)
	`)
	if err != nil {
		return err
	}

	// Node health table
	_, err = db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS node_health (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			run_id INTEGER,
			node_name TEXT NOT NULL,
			status TEXT NOT NULL,
			memory_pressure INTEGER DEFAULT 0,
			disk_pressure INTEGER DEFAULT 0,
			pid_pressure INTEGER DEFAULT 0,
			network_unavailable INTEGER DEFAULT 0,
			allocatable_cpu TEXT,
			allocatable_memory TEXT,
			used_cpu TEXT,
			used_memory TEXT,
			pod_count INTEGER DEFAULT 0,
			conditions TEXT DEFAULT '{}',
			timestamp TEXT NOT NULL,
			FOREIGN KEY (run_id) REFERENCES runs(id)
		)
	`)
	if err != nil {
		return err
	}

	// Create indexes
	db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_fingerprints_type ON issue_fingerprints(error_type)`)
	db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_fingerprints_last_seen ON issue_fingerprints(last_seen DESC)`)
	db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_fix_outcomes_fingerprint ON fix_outcomes(fingerprint_id)`)
	db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_pod_baselines_pod ON pod_baselines(pod_name, namespace)`)
	db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_anomalies_run ON anomalies(run_id)`)
	db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_anomalies_pod ON anomalies(pod_name, namespace)`)
	db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_correlations_primary ON issue_correlations(primary_fix_id)`)
	db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_node_health_run ON node_health(run_id)`)
	db.conn.Exec(`CREATE INDEX IF NOT EXISTS idx_node_health_node ON node_health(node_name)`)

	return nil
}

// === Issue Fingerprinting ===

// GenerateFingerprint creates a unique hash for an issue based on its characteristics
func GenerateFingerprint(errorType, errorMessage, category, podNamePattern string) string {
	// Normalize the error message by removing variable parts
	normalized := normalizeErrorMessage(errorMessage)

	// Create a composite key
	key := strings.Join([]string{
		errorType,
		normalized,
		category,
		podNamePattern,
	}, "|")

	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes for shorter ID
}

// normalizeErrorMessage removes variable parts from error messages
func normalizeErrorMessage(msg string) string {
	// Remove timestamps
	msg = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`).ReplaceAllString(msg, "<TIMESTAMP>")

	// Remove UUIDs
	msg = regexp.MustCompile(`[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`).ReplaceAllString(msg, "<UUID>")

	// Remove pod suffixes (e.g., myapp-7d4f5b6c8d-abc12 -> myapp-<POD_SUFFIX>)
	msg = regexp.MustCompile(`-[a-z0-9]{8,10}-[a-z0-9]{5}$`).ReplaceAllString(msg, "-<POD_SUFFIX>")

	// Remove IP addresses
	msg = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`).ReplaceAllString(msg, "<IP>")

	// Remove port numbers after colons
	msg = regexp.MustCompile(`:\d{2,5}`).ReplaceAllString(msg, ":<PORT>")

	// Remove numeric values that look like counts or IDs
	msg = regexp.MustCompile(`\b\d{6,}\b`).ReplaceAllString(msg, "<NUM>")

	return strings.TrimSpace(msg)
}

// ExtractPodNamePattern extracts the deployment/statefulset name from a pod name
func ExtractPodNamePattern(podName string) string {
	// Remove ReplicaSet suffix (e.g., myapp-7d4f5b6c8d-abc12 -> myapp)
	pattern := regexp.MustCompile(`^(.+)-[a-z0-9]{8,10}-[a-z0-9]{5}$`)
	if matches := pattern.FindStringSubmatch(podName); len(matches) > 1 {
		return matches[1]
	}

	// Remove StatefulSet suffix (e.g., myapp-0 -> myapp)
	pattern = regexp.MustCompile(`^(.+)-\d+$`)
	if matches := pattern.FindStringSubmatch(podName); len(matches) > 1 {
		return matches[1]
	}

	return podName
}

// RecordIssueFingerprint records or updates an issue fingerprint
func (db *DB) RecordIssueFingerprint(fix Fix, category string) (*IssueFingerprint, error) {
	podPattern := ExtractPodNamePattern(fix.PodName)
	fingerprint := GenerateFingerprint(fix.ErrorType, fix.ErrorMessage, category, podPattern)

	now := time.Now().Format("2006-01-02 15:04:05")

	// Try to update existing fingerprint
	result, err := db.conn.Exec(`
		UPDATE issue_fingerprints 
		SET last_seen = ?, 
			occurrence_count = occurrence_count + 1,
			affected_pods = json_insert(affected_pods, '$[#]', ?)
		WHERE fingerprint = ?
	`, now, fix.PodName, fingerprint)

	if err != nil {
		return nil, err
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Insert new fingerprint
		affectedPods, _ := json.Marshal([]string{fix.PodName})
		_, err = db.conn.Exec(`
			INSERT INTO issue_fingerprints 
			(fingerprint, error_type, error_pattern, category, first_seen, last_seen, occurrence_count, affected_pods)
			VALUES (?, ?, ?, ?, ?, ?, 1, ?)
		`, fingerprint, fix.ErrorType, normalizeErrorMessage(fix.ErrorMessage), category, now, now, string(affectedPods))

		if err != nil {
			return nil, err
		}
	}

	// Return the fingerprint record
	return db.GetIssueFingerprint(fingerprint)
}

// GetIssueFingerprint retrieves a fingerprint by its hash
func (db *DB) GetIssueFingerprint(fingerprint string) (*IssueFingerprint, error) {
	var fp IssueFingerprint
	var firstSeen, lastSeen string

	err := db.conn.QueryRow(`
		SELECT id, fingerprint, error_type, COALESCE(error_pattern, ''), COALESCE(category, ''),
			   first_seen, last_seen, occurrence_count, fix_success_count, fix_fail_count,
			   COALESCE(best_fix, ''), best_fix_rate, COALESCE(affected_pods, '[]')
		FROM issue_fingerprints WHERE fingerprint = ?
	`, fingerprint).Scan(
		&fp.ID, &fp.Fingerprint, &fp.ErrorType, &fp.ErrorPattern, &fp.Category,
		&firstSeen, &lastSeen, &fp.OccurrenceCount, &fp.FixSuccessCount, &fp.FixFailCount,
		&fp.BestFix, &fp.BestFixRate, &fp.AffectedPods,
	)

	if err != nil {
		return nil, err
	}

	fp.FirstSeen, _ = time.Parse("2006-01-02 15:04:05", firstSeen)
	fp.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastSeen)

	return &fp, nil
}

// GetSimilarIssues finds previous occurrences of a similar issue
func (db *DB) GetSimilarIssues(errorType, errorMessage, category string, limit int) ([]IssueFingerprint, error) {
	podPattern := ExtractPodNamePattern("")
	fingerprint := GenerateFingerprint(errorType, errorMessage, category, podPattern)

	// First try exact match
	fp, err := db.GetIssueFingerprint(fingerprint)
	if err == nil {
		return []IssueFingerprint{*fp}, nil
	}

	// Fall back to similar error types
	rows, err := db.conn.Query(`
		SELECT id, fingerprint, error_type, COALESCE(error_pattern, ''), COALESCE(category, ''),
			   first_seen, last_seen, occurrence_count, fix_success_count, fix_fail_count,
			   COALESCE(best_fix, ''), best_fix_rate, COALESCE(affected_pods, '[]')
		FROM issue_fingerprints 
		WHERE error_type = ? OR category = ?
		ORDER BY occurrence_count DESC, last_seen DESC
		LIMIT ?
	`, errorType, category, limit)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fingerprints []IssueFingerprint
	for rows.Next() {
		var fp IssueFingerprint
		var firstSeen, lastSeen string
		err := rows.Scan(
			&fp.ID, &fp.Fingerprint, &fp.ErrorType, &fp.ErrorPattern, &fp.Category,
			&firstSeen, &lastSeen, &fp.OccurrenceCount, &fp.FixSuccessCount, &fp.FixFailCount,
			&fp.BestFix, &fp.BestFixRate, &fp.AffectedPods,
		)
		if err != nil {
			continue
		}
		fp.FirstSeen, _ = time.Parse("2006-01-02 15:04:05", firstSeen)
		fp.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastSeen)
		fingerprints = append(fingerprints, fp)
	}

	return fingerprints, nil
}

// GetRecurringIssues returns issues that have occurred multiple times
func (db *DB) GetRecurringIssues(minOccurrences int, days int) ([]IssueFingerprint, error) {
	rows, err := db.conn.Query(`
		SELECT id, fingerprint, error_type, COALESCE(error_pattern, ''), COALESCE(category, ''),
			   first_seen, last_seen, occurrence_count, fix_success_count, fix_fail_count,
			   COALESCE(best_fix, ''), best_fix_rate, COALESCE(affected_pods, '[]')
		FROM issue_fingerprints 
		WHERE occurrence_count >= ? 
		AND last_seen >= datetime('now', ? || ' days')
		ORDER BY occurrence_count DESC
	`, minOccurrences, -days)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var fingerprints []IssueFingerprint
	for rows.Next() {
		var fp IssueFingerprint
		var firstSeen, lastSeen string
		err := rows.Scan(
			&fp.ID, &fp.Fingerprint, &fp.ErrorType, &fp.ErrorPattern, &fp.Category,
			&firstSeen, &lastSeen, &fp.OccurrenceCount, &fp.FixSuccessCount, &fp.FixFailCount,
			&fp.BestFix, &fp.BestFixRate, &fp.AffectedPods,
		)
		if err != nil {
			continue
		}
		fp.FirstSeen, _ = time.Parse("2006-01-02 15:04:05", firstSeen)
		fp.LastSeen, _ = time.Parse("2006-01-02 15:04:05", lastSeen)
		fingerprints = append(fingerprints, fp)
	}

	return fingerprints, nil
}

// === Fix Success Tracking ===

// RecordFixOutcome records the outcome of a fix attempt
func (db *DB) RecordFixOutcome(fingerprintID, fixID int, fixApplied string, success bool, durationSec int) error {
	now := time.Now().Format("2006-01-02 15:04:05")

	_, err := db.conn.Exec(`
		INSERT INTO fix_outcomes (fingerprint_id, fix_id, fix_applied, success, timestamp, duration_seconds)
		VALUES (?, ?, ?, ?, ?, ?)
	`, fingerprintID, fixID, fixApplied, success, now, durationSec)

	if err != nil {
		return err
	}

	// Update fingerprint stats
	if success {
		db.conn.Exec(`UPDATE issue_fingerprints SET fix_success_count = fix_success_count + 1 WHERE id = ?`, fingerprintID)
	} else {
		db.conn.Exec(`UPDATE issue_fingerprints SET fix_fail_count = fix_fail_count + 1 WHERE id = ?`, fingerprintID)
	}

	// Update best fix if this fix has better success rate
	db.updateBestFix(fingerprintID)

	return nil
}

// updateBestFix recalculates and updates the best fix for a fingerprint
func (db *DB) updateBestFix(fingerprintID int) {
	var bestFix string
	var bestRate float64

	err := db.conn.QueryRow(`
		SELECT fix_applied, 
			   CAST(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS REAL) / COUNT(*) as success_rate
		FROM fix_outcomes 
		WHERE fingerprint_id = ?
		GROUP BY fix_applied
		ORDER BY success_rate DESC, COUNT(*) DESC
		LIMIT 1
	`, fingerprintID).Scan(&bestFix, &bestRate)

	if err == nil && bestFix != "" {
		db.conn.Exec(`UPDATE issue_fingerprints SET best_fix = ?, best_fix_rate = ? WHERE id = ?`,
			bestFix, bestRate, fingerprintID)
	}
}

// GetFixSuccessRateByType returns success rates grouped by fix type
func (db *DB) GetFixSuccessRateByType(days int) (map[string]float64, error) {
	rows, err := db.conn.Query(`
		SELECT fix_applied, 
			   CAST(SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS REAL) / COUNT(*) as success_rate
		FROM fix_outcomes 
		WHERE timestamp >= datetime('now', ? || ' days')
		GROUP BY fix_applied
		HAVING COUNT(*) >= 3
		ORDER BY success_rate DESC
	`, -days)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rates := make(map[string]float64)
	for rows.Next() {
		var fixType string
		var rate float64
		if err := rows.Scan(&fixType, &rate); err == nil {
			rates[fixType] = rate
		}
	}

	return rates, nil
}

// GetRecommendedFix returns the best fix for a given issue based on historical data
func (db *DB) GetRecommendedFix(errorType, category string) (string, float64, error) {
	var fix string
	var rate float64

	err := db.conn.QueryRow(`
		SELECT best_fix, best_fix_rate 
		FROM issue_fingerprints 
		WHERE error_type = ? AND category = ? AND best_fix IS NOT NULL AND best_fix != ''
		ORDER BY fix_success_count DESC
		LIMIT 1
	`, errorType, category).Scan(&fix, &rate)

	return fix, rate, err
}

// === Anomaly Detection ===

// UpdatePodBaseline updates the baseline metrics for a pod
func (db *DB) UpdatePodBaseline(podName, namespace string, restarts int, errors int) error {
	now := time.Now().Format("2006-01-02 15:04:05")

	// Get existing baseline
	var existing PodBaseline
	var lastUpdated string
	err := db.conn.QueryRow(`
		SELECT id, avg_restarts_24h, avg_errors_per_run, data_points, stddev_restarts, stddev_errors, last_updated
		FROM pod_baselines WHERE pod_name = ? AND namespace = ?
	`, podName, namespace).Scan(
		&existing.ID, &existing.AvgRestarts24h, &existing.AvgErrorsPerRun,
		&existing.DataPoints, &existing.StdDevRestarts, &existing.StdDevErrors, &lastUpdated,
	)

	if err != nil {
		// Insert new baseline
		_, err = db.conn.Exec(`
			INSERT INTO pod_baselines (pod_name, namespace, avg_restarts_24h, avg_errors_per_run, last_updated, data_points)
			VALUES (?, ?, ?, ?, ?, 1)
		`, podName, namespace, float64(restarts), float64(errors), now)
		return err
	}

	// Update existing baseline using exponential moving average
	n := float64(existing.DataPoints)
	alpha := 0.1 // Smoothing factor

	newAvgRestarts := alpha*float64(restarts) + (1-alpha)*existing.AvgRestarts24h
	newAvgErrors := alpha*float64(errors) + (1-alpha)*existing.AvgErrorsPerRun

	// Update standard deviation (Welford's algorithm simplified)
	newStdDevRestarts := calculateRunningStdDev(existing.StdDevRestarts, existing.AvgRestarts24h, float64(restarts), n)
	newStdDevErrors := calculateRunningStdDev(existing.StdDevErrors, existing.AvgErrorsPerRun, float64(errors), n)

	_, err = db.conn.Exec(`
		UPDATE pod_baselines 
		SET avg_restarts_24h = ?, avg_errors_per_run = ?, 
			stddev_restarts = ?, stddev_errors = ?,
			last_updated = ?, data_points = data_points + 1
		WHERE id = ?
	`, newAvgRestarts, newAvgErrors, newStdDevRestarts, newStdDevErrors, now, existing.ID)

	return err
}

// calculateRunningStdDev calculates a running standard deviation approximation
func calculateRunningStdDev(prevStdDev, prevMean, newValue, n float64) float64 {
	if n < 2 {
		return 0
	}
	// Simplified running variance calculation
	diff := newValue - prevMean
	newVariance := (prevStdDev*prevStdDev*(n-1) + diff*diff) / n
	if newVariance < 0 {
		return 0
	}
	return newVariance // Return variance, caller can sqrt if needed
}

// DetectAnomalies checks for anomalies based on baselines
func (db *DB) DetectAnomalies(runID int, podName, namespace string, restarts, errors int) ([]Anomaly, error) {
	var anomalies []Anomaly
	now := time.Now().Format("2006-01-02 15:04:05")

	// Get baseline
	var baseline PodBaseline
	err := db.conn.QueryRow(`
		SELECT avg_restarts_24h, avg_errors_per_run, stddev_restarts, stddev_errors, data_points
		FROM pod_baselines WHERE pod_name = ? AND namespace = ?
	`, podName, namespace).Scan(
		&baseline.AvgRestarts24h, &baseline.AvgErrorsPerRun,
		&baseline.StdDevRestarts, &baseline.StdDevErrors, &baseline.DataPoints,
	)

	if err != nil || baseline.DataPoints < 5 {
		// Not enough data for anomaly detection
		return anomalies, nil
	}

	// Check for restart anomaly (>2 standard deviations)
	if baseline.StdDevRestarts > 0 {
		deviation := (float64(restarts) - baseline.AvgRestarts24h) / baseline.StdDevRestarts
		if deviation > 2.0 {
			severity := "warning"
			if deviation > 3.0 {
				severity = "critical"
			}
			anomaly := Anomaly{
				RunID:       runID,
				PodName:     podName,
				Namespace:   namespace,
				AnomalyType: "restart_spike",
				Severity:    severity,
				ExpectedVal: baseline.AvgRestarts24h,
				ActualVal:   float64(restarts),
				Deviation:   deviation,
				Description: "Restart count significantly higher than baseline",
			}
			anomalies = append(anomalies, anomaly)

			// Record anomaly
			db.conn.Exec(`
				INSERT INTO anomalies (run_id, pod_name, namespace, anomaly_type, severity, expected_value, actual_value, deviation, timestamp, description)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			`, runID, podName, namespace, "restart_spike", severity, baseline.AvgRestarts24h, restarts, deviation, now, anomaly.Description)
		}
	}

	// Check for error anomaly
	if baseline.StdDevErrors > 0 {
		deviation := (float64(errors) - baseline.AvgErrorsPerRun) / baseline.StdDevErrors
		if deviation > 2.0 {
			severity := "warning"
			if deviation > 3.0 {
				severity = "critical"
			}
			anomaly := Anomaly{
				RunID:       runID,
				PodName:     podName,
				Namespace:   namespace,
				AnomalyType: "error_spike",
				Severity:    severity,
				ExpectedVal: baseline.AvgErrorsPerRun,
				ActualVal:   float64(errors),
				Deviation:   deviation,
				Description: "Error count significantly higher than baseline",
			}
			anomalies = append(anomalies, anomaly)

			db.conn.Exec(`
				INSERT INTO anomalies (run_id, pod_name, namespace, anomaly_type, severity, expected_value, actual_value, deviation, timestamp, description)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			`, runID, podName, namespace, "error_spike", severity, baseline.AvgErrorsPerRun, errors, deviation, now, anomaly.Description)
		}
	}

	return anomalies, nil
}

// GetRecentAnomalies returns recent anomalies
func (db *DB) GetRecentAnomalies(namespace string, days, limit int) ([]Anomaly, error) {
	query := `
		SELECT id, run_id, pod_name, namespace, anomaly_type, severity, 
			   expected_value, actual_value, deviation, timestamp, COALESCE(description, '')
		FROM anomalies 
		WHERE timestamp >= datetime('now', ? || ' days')
	`
	args := []interface{}{-days}

	if namespace != "" {
		query += " AND namespace = ?"
		args = append(args, namespace)
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var anomalies []Anomaly
	for rows.Next() {
		var a Anomaly
		var ts string
		err := rows.Scan(&a.ID, &a.RunID, &a.PodName, &a.Namespace, &a.AnomalyType,
			&a.Severity, &a.ExpectedVal, &a.ActualVal, &a.Deviation, &ts, &a.Description)
		if err != nil {
			continue
		}
		a.Timestamp, _ = time.Parse("2006-01-02 15:04:05", ts)
		anomalies = append(anomalies, a)
	}

	return anomalies, nil
}

// === Root Cause Correlation ===

// FindCorrelatedIssues finds issues that may be related
func (db *DB) FindCorrelatedIssues(runID int, timeWindowMinutes int) ([]IssueCorrelation, error) {
	// Get fixes from current run
	fixes, err := db.GetFixesByRun(runID)
	if err != nil || len(fixes) < 2 {
		return nil, err
	}

	var correlations []IssueCorrelation
	now := time.Now().Format("2006-01-02 15:04:05")

	// Check for temporal correlations within the same run
	for i := 0; i < len(fixes); i++ {
		for j := i + 1; j < len(fixes); j++ {
			// Check if issues might be related
			correlation := analyzeCorrelation(fixes[i], fixes[j])
			if correlation.Confidence > 0.5 {
				correlation.PrimaryFixID = fixes[i].ID
				correlation.SecondaryFixID = fixes[j].ID
				correlation.TimeWindowSec = timeWindowMinutes * 60
				correlations = append(correlations, correlation)

				// Record correlation
				db.conn.Exec(`
					INSERT INTO issue_correlations 
					(primary_fix_id, secondary_fix_id, correlation_type, confidence, time_window_sec, description, timestamp)
					VALUES (?, ?, ?, ?, ?, ?, ?)
				`, fixes[i].ID, fixes[j].ID, correlation.CorrelationType, correlation.Confidence,
					correlation.TimeWindowSec, correlation.Description, now)
			}
		}
	}

	return correlations, nil
}

// analyzeCorrelation determines if two issues are related
func analyzeCorrelation(fix1, fix2 Fix) IssueCorrelation {
	correlation := IssueCorrelation{
		Confidence: 0,
	}

	// Same pod - high correlation for cascade failures
	if fix1.PodName == fix2.PodName {
		correlation.CorrelationType = "same_pod"
		correlation.Confidence = 0.8
		correlation.Description = "Multiple issues in same pod suggest compound failure"
		return correlation
	}

	// Same namespace with similar error types
	if fix1.Namespace == fix2.Namespace && fix1.ErrorType == fix2.ErrorType {
		correlation.CorrelationType = "shared_pattern"
		correlation.Confidence = 0.7
		correlation.Description = "Similar errors in same namespace suggest common root cause"
		return correlation
	}

	// Check for cascade patterns (e.g., DB down -> API errors)
	if isCascadePattern(fix1.ErrorType, fix2.ErrorType) {
		correlation.CorrelationType = "cascade"
		correlation.Confidence = 0.75
		correlation.Description = "Error pattern suggests cascade failure"
		return correlation
	}

	// Same namespace, different errors - moderate correlation
	if fix1.Namespace == fix2.Namespace {
		correlation.CorrelationType = "temporal"
		correlation.Confidence = 0.5
		correlation.Description = "Issues occurred in same time window"
		return correlation
	}

	return correlation
}

// isCascadePattern checks if two error types form a known cascade pattern
func isCascadePattern(type1, type2 string) bool {
	cascadePatterns := map[string][]string{
		"CrashLoopBackOff": {"connection refused", "timeout", "service unavailable"},
		"OOMKilled":        {"memory allocation", "out of memory"},
		"connection":       {"timeout", "refused", "reset"},
		"database":         {"connection pool", "timeout", "deadlock"},
	}

	t1Lower := strings.ToLower(type1)
	t2Lower := strings.ToLower(type2)

	for trigger, effects := range cascadePatterns {
		if strings.Contains(t1Lower, strings.ToLower(trigger)) {
			for _, effect := range effects {
				if strings.Contains(t2Lower, effect) {
					return true
				}
			}
		}
	}

	return false
}

// GetCorrelatedIssuesForFix returns issues correlated with a specific fix
func (db *DB) GetCorrelatedIssuesForFix(fixID int) ([]IssueCorrelation, error) {
	rows, err := db.conn.Query(`
		SELECT id, primary_fix_id, secondary_fix_id, correlation_type, confidence, 
			   time_window_sec, COALESCE(description, ''), timestamp
		FROM issue_correlations 
		WHERE primary_fix_id = ? OR secondary_fix_id = ?
		ORDER BY confidence DESC
	`, fixID, fixID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var correlations []IssueCorrelation
	for rows.Next() {
		var c IssueCorrelation
		var ts string
		err := rows.Scan(&c.ID, &c.PrimaryFixID, &c.SecondaryFixID, &c.CorrelationType,
			&c.Confidence, &c.TimeWindowSec, &c.Description, &ts)
		if err != nil {
			continue
		}
		c.Timestamp, _ = time.Parse("2006-01-02 15:04:05", ts)
		correlations = append(correlations, c)
	}

	return correlations, nil
}

// === Runbook Generation ===

// GenerateRunbook creates or updates a runbook for a fingerprinted issue
func (db *DB) GenerateRunbook(fingerprintID int) (*Runbook, error) {
	// Get fingerprint details
	var fp IssueFingerprint
	err := db.conn.QueryRow(`
		SELECT id, error_type, COALESCE(error_pattern, ''), COALESCE(category, ''), 
			   best_fix, best_fix_rate, fix_success_count
		FROM issue_fingerprints WHERE id = ?
	`, fingerprintID).Scan(&fp.ID, &fp.ErrorType, &fp.ErrorPattern, &fp.Category,
		&fp.BestFix, &fp.BestFixRate, &fp.FixSuccessCount)

	if err != nil {
		return nil, err
	}

	// Generate runbook content
	title := generateRunbookTitle(fp.ErrorType, fp.Category)
	description := generateRunbookDescription(fp)
	steps := generateRunbookSteps(fp)
	prerequisites := generatePrerequisites(fp.Category)

	stepsJSON, _ := json.Marshal(steps)
	prereqJSON, _ := json.Marshal(prerequisites)
	now := time.Now().Format("2006-01-02 15:04:05")

	// Upsert runbook
	_, err = db.conn.Exec(`
		INSERT INTO runbooks (fingerprint_id, title, description, steps, prerequisites, success_rate, last_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(fingerprint_id) DO UPDATE SET
			title = excluded.title,
			description = excluded.description,
			steps = excluded.steps,
			prerequisites = excluded.prerequisites,
			success_rate = excluded.success_rate,
			last_updated = excluded.last_updated
	`, fingerprintID, title, description, string(stepsJSON), string(prereqJSON), fp.BestFixRate, now)

	if err != nil {
		return nil, err
	}

	return db.GetRunbook(fingerprintID)
}

func generateRunbookTitle(errorType, category string) string {
	return "Resolving " + errorType + " in " + category + " category"
}

func generateRunbookDescription(fp IssueFingerprint) string {
	desc := "This runbook addresses " + fp.ErrorType + " errors"
	if fp.Category != "" {
		desc += " in the " + fp.Category + " category"
	}
	if fp.FixSuccessCount > 0 {
		desc += ". Based on " + string(rune(fp.FixSuccessCount)) + " successful resolutions."
	}
	return desc
}

func generateRunbookSteps(fp IssueFingerprint) []RunbookStep {
	steps := []RunbookStep{
		{
			Order:       1,
			Action:      "diagnose",
			Command:     "kubectl describe pod <POD_NAME> -n <NAMESPACE>",
			Description: "Get detailed pod information",
			Expected:    "Identify the current pod state and recent events",
		},
		{
			Order:       2,
			Action:      "check_logs",
			Command:     "kubectl logs <POD_NAME> -n <NAMESPACE> --tail=100",
			Description: "Check recent logs for error details",
			Expected:    "Find specific error messages and stack traces",
		},
	}

	// Add category-specific steps
	switch fp.Category {
	case "application", "crash":
		steps = append(steps, RunbookStep{
			Order:       3,
			Action:      "check_previous",
			Command:     "kubectl logs <POD_NAME> -n <NAMESPACE> --previous --tail=100",
			Description: "Check logs from previous container instance",
			Expected:    "Find the error that caused the crash",
		})
	case "resources", "oom":
		steps = append(steps, RunbookStep{
			Order:       3,
			Action:      "check_resources",
			Command:     "kubectl top pod <POD_NAME> -n <NAMESPACE>",
			Description: "Check current resource usage",
			Expected:    "Identify if pod is hitting resource limits",
		})
	case "networking":
		steps = append(steps, RunbookStep{
			Order:       3,
			Action:      "check_services",
			Command:     "kubectl get svc,endpoints -n <NAMESPACE>",
			Description: "Check service and endpoint configuration",
			Expected:    "Verify services are properly configured",
		})
	}

	// Add best fix as a step if available
	if fp.BestFix != "" {
		steps = append(steps, RunbookStep{
			Order:       len(steps) + 1,
			Action:      "apply_fix",
			Command:     fp.BestFix,
			Description: "Apply recommended fix (success rate: " + string(rune(int(fp.BestFixRate*100))) + "%)",
			Expected:    "Issue should be resolved",
			Fallback:    "If this doesn't work, escalate to on-call engineer",
		})
	}

	return steps
}

func generatePrerequisites(category string) []string {
	prereqs := []string{
		"kubectl access to the cluster",
		"Appropriate RBAC permissions",
	}

	switch category {
	case "resources":
		prereqs = append(prereqs, "metrics-server installed for resource monitoring")
	case "networking":
		prereqs = append(prereqs, "Network policy access if applicable")
	case "security":
		prereqs = append(prereqs, "Security admin permissions may be required")
	}

	return prereqs
}

// GetRunbook retrieves a runbook by fingerprint ID
func (db *DB) GetRunbook(fingerprintID int) (*Runbook, error) {
	var rb Runbook
	var lastUpdated string

	err := db.conn.QueryRow(`
		SELECT id, fingerprint_id, title, COALESCE(description, ''), 
			   COALESCE(steps, '[]'), COALESCE(prerequisites, '[]'),
			   success_rate, avg_resolution_ms, last_updated, usage_count
		FROM runbooks WHERE fingerprint_id = ?
	`, fingerprintID).Scan(&rb.ID, &rb.FingerprintID, &rb.Title, &rb.Description,
		&rb.Steps, &rb.Prerequisites, &rb.SuccessRate, &rb.AvgResolutionMs,
		&lastUpdated, &rb.UsageCount)

	if err != nil {
		return nil, err
	}

	rb.LastUpdated, _ = time.Parse("2006-01-02 15:04:05", lastUpdated)
	return &rb, nil
}

// GetRunbookForIssue finds the most relevant runbook for an issue
func (db *DB) GetRunbookForIssue(errorType, category string) (*Runbook, error) {
	var fingerprintID int

	err := db.conn.QueryRow(`
		SELECT id FROM issue_fingerprints 
		WHERE error_type = ? AND category = ? 
		AND id IN (SELECT fingerprint_id FROM runbooks)
		ORDER BY fix_success_count DESC
		LIMIT 1
	`, errorType, category).Scan(&fingerprintID)

	if err != nil {
		return nil, err
	}

	return db.GetRunbook(fingerprintID)
}

// === Node Health ===

// RecordNodeHealth records node health status
func (db *DB) RecordNodeHealth(runID int, health NodeHealth) error {
	now := time.Now().Format("2006-01-02 15:04:05")

	conditionsJSON, _ := json.Marshal(health.Conditions)

	_, err := db.conn.Exec(`
		INSERT INTO node_health 
		(run_id, node_name, status, memory_pressure, disk_pressure, pid_pressure, 
		 network_unavailable, allocatable_cpu, allocatable_memory, used_cpu, used_memory, 
		 pod_count, conditions, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, runID, health.NodeName, health.Status, health.MemoryPressure, health.DiskPressure,
		health.PIDPressure, health.NetworkUnavail, health.AllocatableCPU, health.AllocatableMemory,
		health.UsedCPU, health.UsedMemory, health.PodCount, string(conditionsJSON), now)

	return err
}

// GetNodeHealthByRun returns node health data for a run
func (db *DB) GetNodeHealthByRun(runID int) ([]NodeHealth, error) {
	rows, err := db.conn.Query(`
		SELECT id, run_id, node_name, status, memory_pressure, disk_pressure, 
			   pid_pressure, network_unavailable, COALESCE(allocatable_cpu, ''),
			   COALESCE(allocatable_memory, ''), COALESCE(used_cpu, ''), COALESCE(used_memory, ''),
			   pod_count, COALESCE(conditions, '{}'), timestamp
		FROM node_health WHERE run_id = ?
		ORDER BY node_name
	`, runID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []NodeHealth
	for rows.Next() {
		var n NodeHealth
		var ts string
		err := rows.Scan(&n.ID, &n.RunID, &n.NodeName, &n.Status, &n.MemoryPressure,
			&n.DiskPressure, &n.PIDPressure, &n.NetworkUnavail, &n.AllocatableCPU,
			&n.AllocatableMemory, &n.UsedCPU, &n.UsedMemory, &n.PodCount, &n.Conditions, &ts)
		if err != nil {
			continue
		}
		n.Timestamp, _ = time.Parse("2006-01-02 15:04:05", ts)
		nodes = append(nodes, n)
	}

	return nodes, nil
}

// GetUnhealthyNodes returns nodes with issues
func (db *DB) GetUnhealthyNodes(days int) ([]NodeHealth, error) {
	rows, err := db.conn.Query(`
		SELECT id, run_id, node_name, status, memory_pressure, disk_pressure, 
			   pid_pressure, network_unavailable, COALESCE(allocatable_cpu, ''),
			   COALESCE(allocatable_memory, ''), COALESCE(used_cpu, ''), COALESCE(used_memory, ''),
			   pod_count, COALESCE(conditions, '{}'), timestamp
		FROM node_health 
		WHERE timestamp >= datetime('now', ? || ' days')
		AND (status != 'Ready' OR memory_pressure = 1 OR disk_pressure = 1 OR pid_pressure = 1 OR network_unavailable = 1)
		ORDER BY timestamp DESC
	`, -days)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []NodeHealth
	for rows.Next() {
		var n NodeHealth
		var ts string
		err := rows.Scan(&n.ID, &n.RunID, &n.NodeName, &n.Status, &n.MemoryPressure,
			&n.DiskPressure, &n.PIDPressure, &n.NetworkUnavail, &n.AllocatableCPU,
			&n.AllocatableMemory, &n.UsedCPU, &n.UsedMemory, &n.PodCount, &n.Conditions, &ts)
		if err != nil {
			continue
		}
		n.Timestamp, _ = time.Parse("2006-01-02 15:04:05", ts)
		nodes = append(nodes, n)
	}

	return nodes, nil
}

// GetLatestNodeHealth returns the most recent health status for each node
func (db *DB) GetLatestNodeHealth() ([]NodeHealth, error) {
	rows, err := db.conn.Query(`
		SELECT n.id, n.run_id, n.node_name, n.status, n.memory_pressure, n.disk_pressure, 
			   n.pid_pressure, n.network_unavailable, COALESCE(n.allocatable_cpu, ''),
			   COALESCE(n.allocatable_memory, ''), COALESCE(n.used_cpu, ''), COALESCE(n.used_memory, ''),
			   n.pod_count, COALESCE(n.conditions, '{}'), n.timestamp
		FROM node_health n
		INNER JOIN (
			SELECT node_name, MAX(timestamp) as max_ts
			FROM node_health
			GROUP BY node_name
		) latest ON n.node_name = latest.node_name AND n.timestamp = latest.max_ts
		ORDER BY n.node_name
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []NodeHealth
	for rows.Next() {
		var n NodeHealth
		var ts string
		err := rows.Scan(&n.ID, &n.RunID, &n.NodeName, &n.Status, &n.MemoryPressure,
			&n.DiskPressure, &n.PIDPressure, &n.NetworkUnavail, &n.AllocatableCPU,
			&n.AllocatableMemory, &n.UsedCPU, &n.UsedMemory, &n.PodCount, &n.Conditions, &ts)
		if err != nil {
			continue
		}
		n.Timestamp, _ = time.Parse("2006-01-02 15:04:05", ts)
		nodes = append(nodes, n)
	}

	return nodes, nil
}
