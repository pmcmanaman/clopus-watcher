package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kubeden/clopus-watcher/dashboard/db"
	"github.com/kubeden/clopus-watcher/dashboard/handlers"
	"github.com/kubeden/clopus-watcher/dashboard/metrics"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// loggingMiddleware logs HTTP requests with method, path, status, and duration
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(lrw, r)

		duration := time.Since(start)

		// Skip logging for health checks and metrics to reduce noise
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			return
		}

		log.Printf("%s %s %d %v", r.Method, r.URL.Path, lrw.statusCode, duration)
	})
}

// loggingResponseWriter wraps http.ResponseWriter to capture status code
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

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

	// Database retention in days (default 30 days, 0 to disable)
	retentionDays := 30
	if retentionStr := os.Getenv("RETENTION_DAYS"); retentionStr != "" {
		if parsed, err := strconv.Atoi(retentionStr); err == nil && parsed >= 0 {
			retentionDays = parsed
		}
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
		"add": func(a, b int) int {
			return a + b
		},
		"subtract": func(a, b int) int {
			return a - b
		},
		"iterate": func(count int) []int {
			result := make([]int, count)
			for i := 0; i < count; i++ {
				result[i] = i + 1
			}
			return result
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

	// Start database retention cleanup goroutine (if enabled)
	if retentionDays > 0 {
		log.Printf("Database retention enabled: %d days", retentionDays)
		go runRetentionCleanup(database, retentionDays)
	}

	// Create a new mux for routing
	mux := http.NewServeMux()

	// Page routes
	mux.HandleFunc("/", h.Index)
	mux.HandleFunc("/compare", h.Compare)

	// HTMX partial routes
	mux.HandleFunc("/partials/runs", h.RunsList)
	mux.HandleFunc("/partials/run", h.RunDetail)
	mux.HandleFunc("/partials/stats", h.Stats)
	mux.HandleFunc("/partials/log", h.LiveLog)

	// API routes
	mux.HandleFunc("/api/namespaces", h.APINamespaces)
	mux.HandleFunc("/api/runs", h.APIRuns)
	mux.HandleFunc("/api/run", h.APIRun)

	// Export routes
	mux.HandleFunc("/api/export/runs", h.ExportRuns)
	mux.HandleFunc("/api/export/fixes", h.ExportFixes)

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Health check
	mux.HandleFunc("/health", h.Health)

	// Apply logging middleware
	handler := loggingMiddleware(mux)

	// Create HTTP server with timeouts
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to listen for shutdown signals
	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Goroutine to handle shutdown
	go func() {
		<-quit
		log.Println("Server is shutting down...")

		// Create context with timeout for shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		server.SetKeepAlivesEnabled(false)
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("Could not gracefully shutdown the server: %v", err)
		}
		close(done)
	}()

	log.Printf("Dashboard starting on port %s", port)
	log.Printf("Metrics available at /metrics")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Could not listen on port %s: %v", port, err)
	}

	<-done
	log.Println("Server stopped")
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
		nsName := ns.Namespace

		// Get recent runs for this namespace
		runs, err := database.GetRuns(nsName, 100)
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
				metrics.LastRunTimestamp.WithLabelValues(nsName).Set(float64(t.Unix()))
			}
		}

		// Update pods monitored
		metrics.PodsMonitored.WithLabelValues(nsName).Set(float64(latestRun.PodCount))

		// Update active errors (from most recent run)
		metrics.ActiveErrors.WithLabelValues(nsName).Set(float64(latestRun.ErrorCount))

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
				if rns == nsName || run.Namespace == nsName {
					// Calculate run duration if both timestamps exist
					if run.StartedAt != "" && run.EndedAt != "" {
						start, err1 := time.Parse("2006-01-02 15:04:05", run.StartedAt)
						end, err2 := time.Parse("2006-01-02 15:04:05", run.EndedAt)
						if err1 == nil && err2 == nil {
							duration := end.Sub(start).Seconds()
							metrics.RunDuration.WithLabelValues(nsName, run.Mode).Observe(duration)
						}
					}
					break
				}
			}
		}
	}
}

// runRetentionCleanup runs database cleanup periodically
func runRetentionCleanup(database *db.DB, retentionDays int) {
	// Run cleanup once at startup
	performCleanup(database, retentionDays)

	// Then run daily
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		performCleanup(database, retentionDays)
	}
}

func performCleanup(database *db.DB, retentionDays int) {
	deleted, err := database.CleanupOldRuns(retentionDays)
	if err != nil {
		log.Printf("Error during retention cleanup: %v", err)
		return
	}
	if deleted > 0 {
		log.Printf("Retention cleanup: deleted %d old runs (older than %d days)", deleted, retentionDays)
	}
}
