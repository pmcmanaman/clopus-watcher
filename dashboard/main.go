package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/kubeden/clopus-watcher/dashboard/db"
	"github.com/kubeden/clopus-watcher/dashboard/handlers"
	"github.com/kubeden/clopus-watcher/dashboard/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	sqlitePath := os.Getenv("SQLITE_PATH")
	if sqlitePath == "" {
		sqlitePath = "/data/watcher.db"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logPath := os.Getenv("LOG_PATH")
	if logPath == "" {
		logPath = "/data/watcher.log"
	}

	database, err := db.New(sqlitePath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()

	// Template functions
	funcMap := template.FuncMap{
		"dict": func(values ...interface{}) map[string]interface{} {
			m := make(map[string]interface{})
			for i := 0; i < len(values); i += 2 {
				if i+1 < len(values) {
					m[values[i].(string)] = values[i+1]
				}
			}
			return m
		},
	}

	// Parse all templates together
	tmpl, err := template.New("").Funcs(funcMap).ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	tmpl, err = tmpl.ParseGlob("templates/partials/*.html")
	if err != nil {
		log.Fatalf("Failed to parse partials: %v", err)
	}

	h := handlers.New(database, tmpl, logPath)

	// Start metrics updater goroutine
	go updateMetrics(database)

	// Page routes
	http.HandleFunc("/", h.Index)

	// HTMX partial routes
	http.HandleFunc("/partials/runs", h.RunsList)
	http.HandleFunc("/partials/run", h.RunDetail)
	http.HandleFunc("/partials/stats", h.Stats)
	http.HandleFunc("/partials/log", h.LiveLog)

	// API routes
	http.HandleFunc("/api/namespaces", h.APINamespaces)
	http.HandleFunc("/api/runs", h.APIRuns)
	http.HandleFunc("/api/run", h.APIRun)

	// Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	// Health check
	http.HandleFunc("/health", h.Health)

	log.Printf("Dashboard starting on port %s", port)
	log.Printf("Metrics available at /metrics")
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// updateMetrics periodically updates Prometheus metrics from the database
func updateMetrics(database *db.DB) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial update
	refreshMetrics(database)

	for range ticker.C {
		refreshMetrics(database)
	}
}

func refreshMetrics(database *db.DB) {
	// Get all namespaces
	namespaces, err := database.GetNamespaces()
	if err != nil {
		log.Printf("Error getting namespaces for metrics: %v", err)
		return
	}

	for _, ns := range namespaces {
		// Get recent runs for this namespace
		runs, err := database.GetRuns(ns, 100)
		if err != nil {
			log.Printf("Error getting runs for metrics: %v", err)
			continue
		}

		if len(runs) == 0 {
			continue
		}

		// Get the most recent run
		latestRun := runs[0]

		// Update last run timestamp
		if latestRun.EndedAt != "" {
			if t, err := time.Parse("2006-01-02 15:04:05", latestRun.EndedAt); err == nil {
				metrics.LastRunTimestamp.WithLabelValues(ns).Set(float64(t.Unix()))
			}
		}

		// Update pods monitored
		metrics.PodsMonitored.WithLabelValues(ns).Set(float64(latestRun.PodCount))

		// Update active errors (from most recent run)
		metrics.ActiveErrors.WithLabelValues(ns).Set(float64(latestRun.ErrorCount))

		// Process all runs for counters
		for _, run := range runs {
			// Parse namespace list (may be comma-separated)
			runNamespaces := strings.Split(run.Namespace, ",")
			for _, rns := range runNamespaces {
				rns = strings.TrimSpace(rns)
				if rns == "" {
					continue
				}

				// Only count if this run includes the current namespace
				if rns == ns || run.Namespace == ns {
					// Calculate run duration if both timestamps exist
					if run.StartedAt != "" && run.EndedAt != "" {
						start, err1 := time.Parse("2006-01-02 15:04:05", run.StartedAt)
						end, err2 := time.Parse("2006-01-02 15:04:05", run.EndedAt)
						if err1 == nil && err2 == nil {
							duration := end.Sub(start).Seconds()
							metrics.RunDuration.WithLabelValues(ns, run.Mode).Observe(duration)
						}
					}
					break
				}
			}
		}
	}
}
