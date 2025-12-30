package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/kubeden/clopus-watcher/dashboard/db"
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
	Recommendation string `json:"recommendation"`
}

// FixWithRecommendation extends Fix with parsed recommendation data
type FixWithRecommendation struct {
	db.Fix
	Recommendation string
	Severity       string
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
			Issue:          "",
		}

		if detailMap != nil {
			if detail, ok := detailMap[fix.PodName]; ok {
				result[i].Recommendation = detail.Recommendation
				result[i].Severity = detail.Severity
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

	namespaces, _ := h.db.GetNamespaces()

	// If no namespace selected and we have namespaces, select first
	if namespace == "" && len(namespaces) > 0 {
		namespace = namespaces[0].Namespace
	}

	runs, _ := h.db.GetRuns(namespace, 50)

	var selectedRun *db.Run
	var selectedFixes []FixWithRecommendation
	var reportSummary string

	// If run specified, get it; otherwise get latest
	if runIDStr != "" {
		runID, _ := strconv.Atoi(runIDStr)
		selectedRun, _ = h.db.GetRun(runID)
		if selectedRun != nil {
			fixes, _ := h.db.GetFixesByRun(runID)
			selectedFixes = enrichFixesWithRecommendations(fixes, selectedRun.Report)
			if parsed, _ := parseReportJSON(selectedRun.Report); parsed != nil {
				reportSummary = parsed.Summary
			}
		}
	} else if len(runs) > 0 {
		selectedRun, _ = h.db.GetRun(runs[0].ID)
		if selectedRun != nil {
			fixes, _ := h.db.GetFixesByRun(runs[0].ID)
			selectedFixes = enrichFixesWithRecommendations(fixes, selectedRun.Report)
			if parsed, _ := parseReportJSON(selectedRun.Report); parsed != nil {
				reportSummary = parsed.Summary
			}
		}
	}

	var stats *db.NamespaceStats
	if namespace != "" {
		stats, _ = h.db.GetNamespaceStats(namespace)
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
	}

	err := h.tmpl.ExecuteTemplate(w, "index.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// HTMX partials
func (h *Handler) RunsList(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")
	runs, _ := h.db.GetRuns(namespace, 50)

	data := struct {
		Runs      []db.Run
		CurrentNS string
	}{runs, namespace}

	h.tmpl.ExecuteTemplate(w, "runs-list.html", data)
}

func (h *Handler) RunDetail(w http.ResponseWriter, r *http.Request) {
	runIDStr := r.URL.Query().Get("id")
	if runIDStr == "" {
		http.Error(w, "Missing run id", http.StatusBadRequest)
		return
	}

	runID, _ := strconv.Atoi(runIDStr)
	run, err := h.db.GetRun(runID)
	if err != nil {
		http.Error(w, "Run not found", http.StatusNotFound)
		return
	}

	fixes, _ := h.db.GetFixesByRun(runID)
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

	h.tmpl.ExecuteTemplate(w, "run-detail.html", data)
}

func (h *Handler) Stats(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")
	stats, _ := h.db.GetNamespaceStats(namespace)
	h.tmpl.ExecuteTemplate(w, "stats.html", stats)
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
	runs, err := h.db.GetRuns(namespace, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(runs)
}

func (h *Handler) APIRun(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, _ := strconv.Atoi(idStr)

	run, err := h.db.GetRun(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	fixes, _ := h.db.GetFixesByRun(id)
	enrichedFixes := enrichFixesWithRecommendations(fixes, run.Report)

	result := struct {
		Run   *db.Run                 `json:"run"`
		Fixes []FixWithRecommendation `json:"fixes"`
	}{run, enrichedFixes}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}
