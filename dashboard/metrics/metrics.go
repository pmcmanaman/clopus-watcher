package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// RunsTotal counts the total number of watcher runs
	RunsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clopus_runs_total",
			Help: "Total number of watcher runs",
		},
		[]string{"namespace", "status", "mode"},
	)

	// ErrorsTotal counts the total number of errors detected
	ErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clopus_errors_total",
			Help: "Total number of errors detected",
		},
		[]string{"namespace", "category", "severity"},
	)

	// FixesTotal counts the total number of fixes attempted
	FixesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clopus_fixes_total",
			Help: "Total number of fixes attempted",
		},
		[]string{"namespace", "status"},
	)

	// RunDuration tracks the duration of watcher runs
	RunDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "clopus_run_duration_seconds",
			Help:    "Duration of watcher runs in seconds",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10), // 1s to ~17min
		},
		[]string{"namespace", "mode"},
	)

	// LastRunTimestamp tracks the timestamp of the last run
	LastRunTimestamp = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clopus_last_run_timestamp",
			Help: "Unix timestamp of the last watcher run",
		},
		[]string{"namespace"},
	)

	// PodsMonitored tracks the number of pods in the last run
	PodsMonitored = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clopus_pods_monitored",
			Help: "Number of pods monitored in the last run",
		},
		[]string{"namespace"},
	)

	// ActiveErrors tracks currently active errors
	ActiveErrors = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clopus_active_errors",
			Help: "Number of currently active errors",
		},
		[]string{"namespace"},
	)

	// RecurringIssues tracks issues that have occurred multiple times
	RecurringIssues = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clopus_recurring_issues",
			Help: "Number of recurring issues by type",
		},
		[]string{"error_type", "category"},
	)

	// AnomaliesDetected counts anomalies detected
	AnomaliesDetected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clopus_anomalies_total",
			Help: "Total number of anomalies detected",
		},
		[]string{"namespace", "anomaly_type", "severity"},
	)

	// FixSuccessRate tracks fix success rate
	FixSuccessRateGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clopus_fix_success_rate",
			Help: "Fix success rate by fix type (0-1)",
		},
		[]string{"fix_type"},
	)

	// NodeHealth tracks node health status
	NodeHealthStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clopus_node_health",
			Help: "Node health status (1=healthy, 0=unhealthy)",
		},
		[]string{"node"},
	)

	// NodePressure tracks node pressure conditions
	NodePressure = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clopus_node_pressure",
			Help: "Node pressure conditions (1=pressure, 0=ok)",
		},
		[]string{"node", "pressure_type"},
	)
)
