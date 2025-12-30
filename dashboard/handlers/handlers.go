package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/kubeden/clopus-watcher/dashboard/db"
)

const defaultPageSize = 20

// Validation patterns
var (
	// Namespace must be valid k8s namespace name (alphanumeric, dashes, commas for multi-ns)
	namespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9,]*[a-z0-9])?$`)
)

type Handler struct {
	db      *db.DB
	tmpl    *template.Template
	logPath string
}

func New(database *db.DB, tmpl *template.Template, logPath string) *Handler {
	return &Handler{
		db:      database,
		tmpl:    tmpl,
		logPath: logPath,
	}
}

// validateRunID validates and parses a run ID from string
func validateRunID(idStr string) (int, error) {
	if idStr == "" {
		return 0, nil // empty is valid (means no selection)
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return 0, err
	}
	if id < 0 {
		return 0, strconv.ErrRange
	}
	return id, nil
}

// validateNamespace validates a namespace string
func validateNamespace(ns string) bool {
	if ns == "" {
		return true // empty is valid (means all)
	}
	// Allow longer multi-namespace strings
	if len(ns) > 253 {
		return false
	}
	return namespacePattern.MatchString(ns)
}

// validatePage validates and parses a page number
func validatePage(pageStr string) int {
	if pageStr == "" {
		return 1
	}
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		return 1
	}
	return page
}

// validateStatus validates a status filter
func validateStatus(status string) string {
	valid := map[string]bool{
		"":        true,
		"ok":      true,
		"fixed":   true,
		"failed":  true,
		"issues":  true,
		"running": true,
	}
	if valid[status] {
		return status
	}
	return ""
}

// validateSearch sanitizes search input
func validateSearch(search string) string {
	// Limit length and remove dangerous characters
	if len(search) > 100 {
		search = search[:100]
	}
	// Remove SQL wildcards that could cause issues
	search = strings.ReplaceAll(search, "%", "")
	search = strings.ReplaceAll(search, "_", "")
	return strings.TrimSpace(search)
}

// ReportJSON represents the parsed report structure
type ReportJSON struct {
	PodCount   int            `json:"pod_count"`
	ErrorCount int            `json:"error_count"`
	FixCount   int            `json:"fix_count"`
	Status     string         `json:"status"`
	Summary    string         `json:"summary"`
	Details    []ReportDetail `json:"details"`
}

// ReportDetail represents a single issue detail from the report
type ReportDetail struct {
	Pod            string `json:"pod"`
	Issue          string `json:"issue"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Recommendation string `json:"recommendation"`
	Action         string `json:"action"`
	Result         string `json:"result"`
}

// FixWithRecommendation extends Fix with parsed recommendation data
type FixWithRecommendation struct {
	db.Fix
	Recommendation string
	Severity       string
	Category       string
	Issue          string
}

type PageData struct {
	Namespaces      []db.NamespaceStats
	CurrentNS       string
	Runs            []db.Run
	SelectedRun     *db.Run
	SelectedFixes   []FixWithRecommendation
	Stats           *db.NamespaceStats
	Log             string
	ReportSummary   string
	// Pagination
	CurrentPage     int
	TotalPages      int
	TotalRuns       int
	PageSize        int
	// Filters
	StatusFilter    string
	SearchQuery     string
}

func (h *Handler) readLog() string {
	data, err := os.ReadFile(h.logPath)
	if err != nil {
		return "No watcher log available yet. Waiting for first run..."
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	return strings.Join(lines, "\n")
}

// parseReportJSON extracts recommendation details from the report JSON
func parseReportJSON(report string) (*ReportJSON, map[string]ReportDetail) {
	if report == "" {
		return nil, nil
	}

	var parsed ReportJSON
	if err := json.Unmarshal([]byte(report), &parsed); err != nil {
		return nil, nil
	}

	// Build a map of pod name -> detail for quick lookup
	detailMap := make(map[string]ReportDetail)
	for _, detail := range parsed.Details {
		detailMap[detail.Pod] = detail
	}

	return &parsed, detailMap
}

// enrichFixesWithRecommendations adds recommendation data to fixes
func enrichFixesWithRecommendations(fixes []db.Fix, report string) []FixWithRecommendation {
	result := make([]FixWithRecommendation, len(fixes))
	_, detailMap := parseReportJSON(report)

	for i, fix := range fixes {
		result[i] = FixWithRecommendation{
			Fix:            fix,
			Recommendation: "",
			Severity:       "",
			Category:       "",
			Issue:          "",
		}

		if detailMap != nil {
			if detail, ok := detailMap[fix.PodName]; ok {
				result[i].Recommendation = detail.Recommendation
				result[i].Severity = detail.Severity
				result[i].Category = detail.Category
				result[i].Issue = detail.Issue
			}
		}
	}

	return result
}

// Main page
func (h *Handler) Index(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")
	runIDStr := r.URL.Query().Get("run")
	page := validatePage(r.URL.Query().Get("page"))
	statusFilter := validateStatus(r.URL.Query().Get("status"))
	searchQuery := validateSearch(r.URL.Query().Get("q"))

	// Validate inputs
	if !validateNamespace(namespace) {
		log.Printf("Invalid namespace parameter: %s", namespace)
		http.Error(w, "Invalid namespace parameter", http.StatusBadRequest)
		return
	}

	runID, err := validateRunID(runIDStr)
	if err != nil {
		log.Printf("Invalid run ID parameter: %s", runIDStr)
		http.Error(w, "Invalid run ID parameter", http.StatusBadRequest)
		return
	}

	namespaces, err := h.db.GetNamespaces()
	if err != nil {
		log.Printf("Error getting namespaces: %v", err)
		namespaces = []db.NamespaceStats{}
	}

	// If no namespace selected and we have namespaces, select first
	if namespace == "" && len(namespaces) > 0 {
		namespace = namespaces[0].Namespace
	}

	// Get total count for pagination
	totalRuns, err := h.db.CountRuns(namespace, statusFilter, searchQuery)
	if err != nil {
		log.Printf("Error counting runs: %v", err)
		totalRuns = 0
	}

	totalPages := (totalRuns + defaultPageSize - 1) / defaultPageSize
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	offset := (page - 1) * defaultPageSize
	runs, err := h.db.GetRunsPaginated(namespace, defaultPageSize, offset, statusFilter, searchQuery)
	if err != nil {
		log.Printf("Error getting runs for namespace %s: %v", namespace, err)
		runs = []db.Run{}
	}

	var selectedRun *db.Run
	var selectedFixes []FixWithRecommendation
	var reportSummary string

	// If run specified, get it; otherwise get latest
	if runID > 0 {
		selectedRun, err = h.db.GetRun(runID)
		if err != nil {
			log.Printf("Error getting run %d: %v", runID, err)
		}
		if selectedRun != nil {
			fixes, err := h.db.GetFixesByRun(runID)
			if err != nil {
				log.Printf("Error getting fixes for run %d: %v", runID, err)
			}
			selectedFixes = enrichFixesWithRecommendations(fixes, selectedRun.Report)
			if parsed, _ := parseReportJSON(selectedRun.Report); parsed != nil {
				reportSummary = parsed.Summary
			}
		}
	} else if len(runs) > 0 {
		selectedRun, err = h.db.GetRun(runs[0].ID)
		if err != nil {
			log.Printf("Error getting run %d: %v", runs[0].ID, err)
		}
		if selectedRun != nil {
			fixes, err := h.db.GetFixesByRun(runs[0].ID)
			if err != nil {
				log.Printf("Error getting fixes for run %d: %v", runs[0].ID, err)
			}
			selectedFixes = enrichFixesWithRecommendations(fixes, selectedRun.Report)
			if parsed, _ := parseReportJSON(selectedRun.Report); parsed != nil {
				reportSummary = parsed.Summary
			}
		}
	}

	var stats *db.NamespaceStats
	if namespace != "" {
		stats, err = h.db.GetNamespaceStats(namespace)
		if err != nil {
			log.Printf("Error getting stats for namespace %s: %v", namespace, err)
		}
	}

	data := PageData{
		Namespaces:    namespaces,
		CurrentNS:     namespace,
		Runs:          runs,
		SelectedRun:   selectedRun,
		SelectedFixes: selectedFixes,
		Stats:         stats,
		Log:           h.readLog(),
		ReportSummary: reportSummary,
		CurrentPage:   page,
		TotalPages:    totalPages,
		TotalRuns:     totalRuns,
		PageSize:      defaultPageSize,
		StatusFilter:  statusFilter,
		SearchQuery:   searchQuery,
	}

	if err := h.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HTMX partials
func (h *Handler) RunsList(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")

	if !validateNamespace(namespace) {
		log.Printf("Invalid namespace parameter in RunsList: %s", namespace)
		http.Error(w, "Invalid namespace parameter", http.StatusBadRequest)
		return
	}

	runs, err := h.db.GetRuns(namespace, 50)
	if err != nil {
		log.Printf("Error getting runs for namespace %s: %v", namespace, err)
		http.Error(w, "Error retrieving runs", http.StatusInternalServerError)
		return
	}

	data := struct {
		Runs      []db.Run
		CurrentNS string
	}{runs, namespace}

	if err := h.tmpl.ExecuteTemplate(w, "runs-list.html", data); err != nil {
		log.Printf("Error executing runs-list template: %v", err)
	}
}

func (h *Handler) RunDetail(w http.ResponseWriter, r *http.Request) {
	runIDStr := r.URL.Query().Get("id")

	runID, err := validateRunID(runIDStr)
	if err != nil || runID <= 0 {
		log.Printf("Invalid run ID parameter in RunDetail: %s", runIDStr)
		http.Error(w, "Invalid run ID", http.StatusBadRequest)
		return
	}

	run, err := h.db.GetRun(runID)
	if err != nil {
		log.Printf("Error getting run %d: %v", runID, err)
		http.Error(w, "Run not found", http.StatusNotFound)
		return
	}

	fixes, err := h.db.GetFixesByRun(runID)
	if err != nil {
		log.Printf("Error getting fixes for run %d: %v", runID, err)
		// Continue with empty fixes rather than failing
		fixes = []db.Fix{}
	}
	enrichedFixes := enrichFixesWithRecommendations(fixes, run.Report)

	var reportSummary string
	if parsed, _ := parseReportJSON(run.Report); parsed != nil {
		reportSummary = parsed.Summary
	}

	data := struct {
		Run           *db.Run
		Fixes         []FixWithRecommendation
		ReportSummary string
	}{run, enrichedFixes, reportSummary}

	if err := h.tmpl.ExecuteTemplate(w, "run-detail.html", data); err != nil {
		log.Printf("Error executing run-detail template: %v", err)
	}
}

func (h *Handler) Stats(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")

	if !validateNamespace(namespace) {
		log.Printf("Invalid namespace parameter in Stats: %s", namespace)
		http.Error(w, "Invalid namespace parameter", http.StatusBadRequest)
		return
	}

	stats, err := h.db.GetNamespaceStats(namespace)
	if err != nil {
		log.Printf("Error getting stats for namespace %s: %v", namespace, err)
		http.Error(w, "Error retrieving stats", http.StatusInternalServerError)
		return
	}

	if err := h.tmpl.ExecuteTemplate(w, "stats.html", stats); err != nil {
		log.Printf("Error executing stats template: %v", err)
	}
}

func (h *Handler) LiveLog(w http.ResponseWriter, r *http.Request) {
	log := h.readLog()
	w.Header().Set("Content-Type", "text/html")
	escaped := template.HTMLEscapeString(log)
	escaped = strings.ReplaceAll(escaped, "\n", "<br>")
	w.Write([]byte(escaped))
}

// API endpoints (JSON)
func (h *Handler) APINamespaces(w http.ResponseWriter, r *http.Request) {
	namespaces, err := h.db.GetNamespaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(namespaces)
}

func (h *Handler) APIRuns(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")

	if !validateNamespace(namespace) {
		log.Printf("Invalid namespace parameter in APIRuns: %s", namespace)
		http.Error(w, "Invalid namespace parameter", http.StatusBadRequest)
		return
	}

	runs, err := h.db.GetRuns(namespace, 100)
	if err != nil {
		log.Printf("Error getting runs for namespace %s: %v", namespace, err)
		http.Error(w, "Error retrieving runs", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(runs); err != nil {
		log.Printf("Error encoding runs JSON: %v", err)
	}
}

func (h *Handler) APIRun(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")

	id, err := validateRunID(idStr)
	if err != nil || id <= 0 {
		log.Printf("Invalid run ID parameter in APIRun: %s", idStr)
		http.Error(w, "Invalid run ID", http.StatusBadRequest)
		return
	}

	run, err := h.db.GetRun(id)
	if err != nil {
		log.Printf("Error getting run %d: %v", id, err)
		http.Error(w, "Run not found", http.StatusNotFound)
		return
	}

	fixes, err := h.db.GetFixesByRun(id)
	if err != nil {
		log.Printf("Error getting fixes for run %d: %v", id, err)
		fixes = []db.Fix{}
	}
	enrichedFixes := enrichFixesWithRecommendations(fixes, run.Report)

	result := struct {
		Run   *db.Run                 `json:"run"`
		Fixes []FixWithRecommendation `json:"fixes"`
	}{run, enrichedFixes}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("Error encoding run JSON: %v", err)
	}
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// Export endpoints
func (h *Handler) ExportRuns(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")
	format := r.URL.Query().Get("format")
	statusFilter := validateStatus(r.URL.Query().Get("status"))

	if !validateNamespace(namespace) {
		http.Error(w, "Invalid namespace parameter", http.StatusBadRequest)
		return
	}

	if format != "csv" && format != "json" {
		format = "json"
	}

	// Get all runs (no pagination for export)
	runs, err := h.db.GetRunsPaginated(namespace, 10000, 0, statusFilter, "")
	if err != nil {
		log.Printf("Error getting runs for export: %v", err)
		http.Error(w, "Error retrieving runs", http.StatusInternalServerError)
		return
	}

	filename := "clopus-runs"
	if namespace != "" {
		filename += "-" + namespace
	}

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.csv\"", filename))
		h.writeRunsCSV(w, runs)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.json\"", filename))
		json.NewEncoder(w).Encode(runs)
	}
}

func (h *Handler) writeRunsCSV(w http.ResponseWriter, runs []db.Run) {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Header
	writer.Write([]string{
		"ID", "Started At", "Ended At", "Namespace", "Mode", "Status",
		"Pod Count", "Error Count", "Fix Count",
	})

	// Data rows
	for _, run := range runs {
		writer.Write([]string{
			strconv.Itoa(run.ID),
			run.StartedAt,
			run.EndedAt,
			run.Namespace,
			run.Mode,
			run.Status,
			strconv.Itoa(run.PodCount),
			strconv.Itoa(run.ErrorCount),
			strconv.Itoa(run.FixCount),
		})
	}
}

func (h *Handler) ExportFixes(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")
	format := r.URL.Query().Get("format")

	if !validateNamespace(namespace) {
		http.Error(w, "Invalid namespace parameter", http.StatusBadRequest)
		return
	}

	if format != "csv" && format != "json" {
		format = "json"
	}

	// Get all fixes
	fixes, err := h.db.GetFixes(10000)
	if err != nil {
		log.Printf("Error getting fixes for export: %v", err)
		http.Error(w, "Error retrieving fixes", http.StatusInternalServerError)
		return
	}

	// Filter by namespace if specified
	if namespace != "" {
		filtered := []db.Fix{}
		for _, fix := range fixes {
			if fix.Namespace == namespace {
				filtered = append(filtered, fix)
			}
		}
		fixes = filtered
	}

	filename := "clopus-fixes"
	if namespace != "" {
		filename += "-" + namespace
	}

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.csv\"", filename))
		h.writeFixesCSV(w, fixes)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.json\"", filename))
		json.NewEncoder(w).Encode(fixes)
	}
}

func (h *Handler) writeFixesCSV(w http.ResponseWriter, fixes []db.Fix) {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Header
	writer.Write([]string{
		"ID", "Run ID", "Timestamp", "Namespace", "Pod Name",
		"Error Type", "Error Message", "Fix Applied", "Status",
	})

	// Data rows
	for _, fix := range fixes {
		writer.Write([]string{
			strconv.Itoa(fix.ID),
			strconv.Itoa(fix.RunID),
			fix.Timestamp,
			fix.Namespace,
			fix.PodName,
			fix.ErrorType,
			fix.ErrorMessage,
			fix.FixApplied,
			fix.Status,
		})
	}
}

// CompareData holds data for run comparison view
type CompareData struct {
	Run1          *db.Run
	Run2          *db.Run
	Fixes1        []FixWithRecommendation
	Fixes2        []FixWithRecommendation
	Report1       *ReportJSON
	Report2       *ReportJSON
	Namespaces    []db.NamespaceStats
	AvailableRuns []db.Run
}

// Compare shows two runs side by side
func (h *Handler) Compare(w http.ResponseWriter, r *http.Request) {
	run1Str := r.URL.Query().Get("run1")
	run2Str := r.URL.Query().Get("run2")

	run1ID, err := validateRunID(run1Str)
	if err != nil {
		log.Printf("Invalid run1 ID: %s", run1Str)
		http.Error(w, "Invalid run1 ID", http.StatusBadRequest)
		return
	}

	run2ID, err := validateRunID(run2Str)
	if err != nil {
		log.Printf("Invalid run2 ID: %s", run2Str)
		http.Error(w, "Invalid run2 ID", http.StatusBadRequest)
		return
	}

	namespaces, err := h.db.GetNamespaces()
	if err != nil {
		log.Printf("Error getting namespaces: %v", err)
		namespaces = []db.NamespaceStats{}
	}

	// Get available runs for selection dropdown
	availableRuns, err := h.db.GetRuns("", 100)
	if err != nil {
		log.Printf("Error getting available runs: %v", err)
		availableRuns = []db.Run{}
	}

	data := CompareData{
		Namespaces:    namespaces,
		AvailableRuns: availableRuns,
	}

	// Load run 1 if specified
	if run1ID > 0 {
		run1, err := h.db.GetRun(run1ID)
		if err != nil {
			log.Printf("Error getting run1 %d: %v", run1ID, err)
		} else {
			data.Run1 = run1
			fixes, _ := h.db.GetFixesByRun(run1ID)
			data.Fixes1 = enrichFixesWithRecommendations(fixes, run1.Report)
			data.Report1, _ = parseReportJSON(run1.Report)
		}
	}

	// Load run 2 if specified
	if run2ID > 0 {
		run2, err := h.db.GetRun(run2ID)
		if err != nil {
			log.Printf("Error getting run2 %d: %v", run2ID, err)
		} else {
			data.Run2 = run2
			fixes, _ := h.db.GetFixesByRun(run2ID)
			data.Fixes2 = enrichFixesWithRecommendations(fixes, run2.Report)
			data.Report2, _ = parseReportJSON(run2.Report)
		}
	}

	if err := h.tmpl.ExecuteTemplate(w, "compare.html", data); err != nil {
		log.Printf("Error executing compare template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
