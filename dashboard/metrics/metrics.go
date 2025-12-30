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
)
