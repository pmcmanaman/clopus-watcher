package handlers

import (
	"context"
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
	"time"

	"github.com/kubeden/clopus-watcher/dashboard/db"
	"github.com/kubeden/clopus-watcher/dashboard/webhooks"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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
	Namespace      string `json:"namespace"`
	Pod            string `json:"pod"`
	Issue          string `json:"issue"`
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Recommendation string `json:"recommendation"`
	Action         string `json:"action"`
	Result         string `json:"result"`
}

// ReportDetailWithCommands extends ReportDetail with suggested kubectl commands
type ReportDetailWithCommands struct {
	ReportDetail
	Commands []string
}

// generateKubectlCommands generates helpful kubectl commands based on the issue
func generateKubectlCommands(detail ReportDetail) []string {
	var commands []string
	ns := detail.Namespace
	pod := detail.Pod

	if ns == "" {
		ns = "default"
	}

	switch detail.Category {
	case "scheduling":
		commands = append(commands,
			fmt.Sprintf("kubectl describe pod %s -n %s", pod, ns),
			fmt.Sprintf("kubectl get events -n %s --field-selector involvedObject.name=%s", ns, pod),
			"kubectl describe nodes | grep -A5 'Allocated resources'",
			"kubectl top nodes",
		)
		if strings.Contains(strings.ToLower(detail.Issue), "karpenter") {
			commands = append(commands,
				"kubectl get provisioners -A",
				"kubectl logs -n karpenter -l app.kubernetes.io/name=karpenter --tail=50",
			)
		}
	case "crash", "crashloop":
		commands = append(commands,
			fmt.Sprintf("kubectl logs %s -n %s --tail=100", pod, ns),
			fmt.Sprintf("kubectl logs %s -n %s --previous --tail=100", pod, ns),
			fmt.Sprintf("kubectl describe pod %s -n %s", pod, ns),
			fmt.Sprintf("kubectl get events -n %s --field-selector involvedObject.name=%s --sort-by='.lastTimestamp'", ns, pod),
		)
	case "oom", "memory":
		commands = append(commands,
			fmt.Sprintf("kubectl describe pod %s -n %s | grep -A10 'Containers:'", pod, ns),
			fmt.Sprintf("kubectl top pod %s -n %s", pod, ns),
			fmt.Sprintf("kubectl logs %s -n %s --tail=100", pod, ns),
		)
	case "image", "imagepull":
		commands = append(commands,
			fmt.Sprintf("kubectl describe pod %s -n %s | grep -A5 'Events:'", pod, ns),
			fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath='{.spec.containers[*].image}'", pod, ns),
		)
	case "network", "connectivity":
		commands = append(commands,
			fmt.Sprintf("kubectl exec -n %s %s -- ping -c 3 8.8.8.8", ns, pod),
			fmt.Sprintf("kubectl get svc -n %s", ns),
			fmt.Sprintf("kubectl get endpoints -n %s", ns),
		)
	case "config", "configuration":
		commands = append(commands,
			fmt.Sprintf("kubectl get pod %s -n %s -o yaml", pod, ns),
			fmt.Sprintf("kubectl get configmaps -n %s", ns),
			fmt.Sprintf("kubectl get secrets -n %s", ns),
		)
	default:
		// General debugging commands
		commands = append(commands,
			fmt.Sprintf("kubectl describe pod %s -n %s", pod, ns),
			fmt.Sprintf("kubectl logs %s -n %s --tail=100", pod, ns),
			fmt.Sprintf("kubectl get events -n %s --field-selector involvedObject.name=%s", ns, pod),
		)
	}

	return commands
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
	Namespaces        []db.NamespaceStats
	CurrentNS         string
	ShowAllNamespaces bool
	Runs              []db.Run
	SelectedRun       *db.Run
	SelectedFixes     []FixWithRecommendation
	Stats             *db.NamespaceStats
	Log               string
	ReportSummary     string
	ReportDetails     []ReportDetailWithCommands
	// Pagination
	CurrentPage int
	TotalPages  int
	TotalRuns   int
	PageSize    int
	// Filters
	StatusFilter string
	SearchQuery  string
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

	// Advanced filter parameters
	dateStart := r.URL.Query().Get("date_start")
	dateEnd := r.URL.Query().Get("date_end")
	podName := validateSearch(r.URL.Query().Get("pod"))

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

	// Empty namespace means "All Namespaces" - show runs from all namespaces

	// Build advanced filters
	filters := db.AdvancedFilters{
		Namespace: namespace,
		Status:    statusFilter,
		Search:    searchQuery,
		PodName:   podName,
	}
	if dateStart != "" || dateEnd != "" {
		filters.DateRange = &db.DateRange{
			Start: dateStart,
			End:   dateEnd,
		}
	}

	// Check if any advanced filters are active
	hasAdvancedFilters := dateStart != "" || dateEnd != "" || podName != ""

	var totalRuns int
	var runs []db.Run

	if hasAdvancedFilters {
		// Use advanced filter queries
		totalRuns, err = h.db.CountRunsWithAdvancedFilters(filters)
		if err != nil {
			log.Printf("Error counting runs with filters: %v", err)
			totalRuns = 0
		}
	} else {
		// Use simple queries
		totalRuns, err = h.db.CountRuns(namespace, statusFilter, searchQuery)
		if err != nil {
			log.Printf("Error counting runs: %v", err)
			totalRuns = 0
		}
	}

	totalPages := (totalRuns + defaultPageSize - 1) / defaultPageSize
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	offset := (page - 1) * defaultPageSize

	if hasAdvancedFilters {
		runs, err = h.db.GetRunsWithAdvancedFilters(filters, defaultPageSize, offset)
	} else {
		runs, err = h.db.GetRunsPaginated(namespace, defaultPageSize, offset, statusFilter, searchQuery)
	}
	if err != nil {
		log.Printf("Error getting runs for namespace %s: %v", namespace, err)
		runs = []db.Run{}
	}

	var selectedRun *db.Run
	var selectedFixes []FixWithRecommendation
	var reportSummary string
	var reportDetails []ReportDetailWithCommands

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
			// Filter fixes by namespace if a specific namespace is selected
			if namespace != "" {
				filteredFixes := []db.Fix{}
				for _, fix := range fixes {
					if fix.Namespace == namespace {
						filteredFixes = append(filteredFixes, fix)
					}
				}
				fixes = filteredFixes
			}
			selectedFixes = enrichFixesWithRecommendations(fixes, selectedRun.Report)
			if parsed, _ := parseReportJSON(selectedRun.Report); parsed != nil {
				reportSummary = parsed.Summary
				for _, detail := range parsed.Details {
					// Filter report details by namespace if a specific namespace is selected
					if namespace != "" && detail.Namespace != namespace {
						continue
					}
					reportDetails = append(reportDetails, ReportDetailWithCommands{
						ReportDetail: detail,
						Commands:     generateKubectlCommands(detail),
					})
				}
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
			// Filter fixes by namespace if a specific namespace is selected
			if namespace != "" {
				filteredFixes := []db.Fix{}
				for _, fix := range fixes {
					if fix.Namespace == namespace {
						filteredFixes = append(filteredFixes, fix)
					}
				}
				fixes = filteredFixes
			}
			selectedFixes = enrichFixesWithRecommendations(fixes, selectedRun.Report)
			if parsed, _ := parseReportJSON(selectedRun.Report); parsed != nil {
				reportSummary = parsed.Summary
				for _, detail := range parsed.Details {
					// Filter report details by namespace if a specific namespace is selected
					if namespace != "" && detail.Namespace != namespace {
						continue
					}
					reportDetails = append(reportDetails, ReportDetailWithCommands{
						ReportDetail: detail,
						Commands:     generateKubectlCommands(detail),
					})
				}
			}
		}
	}

	var stats *db.NamespaceStats
	if namespace != "" {
		stats, err = h.db.GetNamespaceStats(namespace)
		if err != nil {
			log.Printf("Error getting stats for namespace %s: %v", namespace, err)
		}
	} else {
		// Aggregate stats across all namespaces
		stats, err = h.db.GetAllNamespacesStats()
		if err != nil {
			log.Printf("Error getting all namespaces stats: %v", err)
		}
	}

	data := PageData{
		Namespaces:        namespaces,
		CurrentNS:         namespace,
		ShowAllNamespaces: namespace == "",
		Runs:              runs,
		SelectedRun:       selectedRun,
		SelectedFixes:     selectedFixes,
		Stats:             stats,
		Log:               h.readLog(),
		ReportSummary:     reportSummary,
		ReportDetails:     reportDetails,
		CurrentPage:       page,
		TotalPages:        totalPages,
		TotalRuns:         totalRuns,
		PageSize:          defaultPageSize,
		StatusFilter:      statusFilter,
		SearchQuery:       searchQuery,
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
		Runs              []db.Run
		CurrentNS         string
		ShowAllNamespaces bool
	}{runs, namespace, namespace == ""}

	if err := h.tmpl.ExecuteTemplate(w, "runs-list.html", data); err != nil {
		log.Printf("Error executing runs-list template: %v", err)
	}
}

func (h *Handler) RunDetail(w http.ResponseWriter, r *http.Request) {
	runIDStr := r.URL.Query().Get("id")
	namespace := r.URL.Query().Get("ns")

	runID, err := validateRunID(runIDStr)
	if err != nil || runID <= 0 {
		log.Printf("Invalid run ID parameter in RunDetail: %s", runIDStr)
		http.Error(w, "Invalid run ID", http.StatusBadRequest)
		return
	}

	if !validateNamespace(namespace) {
		namespace = ""
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

	// Filter fixes by namespace if a specific namespace is selected
	if namespace != "" {
		filteredFixes := []db.Fix{}
		for _, fix := range fixes {
			if fix.Namespace == namespace {
				filteredFixes = append(filteredFixes, fix)
			}
		}
		fixes = filteredFixes
	}
	enrichedFixes := enrichFixesWithRecommendations(fixes, run.Report)

	var reportSummary string
	var reportDetails []ReportDetailWithCommands
	if parsed, _ := parseReportJSON(run.Report); parsed != nil {
		reportSummary = parsed.Summary
		// Build details with commands
		for _, detail := range parsed.Details {
			// Filter report details by namespace if a specific namespace is selected
			if namespace != "" && detail.Namespace != namespace {
				continue
			}
			reportDetails = append(reportDetails, ReportDetailWithCommands{
				ReportDetail: detail,
				Commands:     generateKubectlCommands(detail),
			})
		}
	}

	data := struct {
		Run           *db.Run
		Fixes         []FixWithRecommendation
		ReportSummary string
		ReportDetails []ReportDetailWithCommands
		CurrentNS     string
	}{run, enrichedFixes, reportSummary, reportDetails, namespace}

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

	var stats *db.NamespaceStats
	var err error
	if namespace != "" {
		stats, err = h.db.GetNamespaceStats(namespace)
	} else {
		stats, err = h.db.GetAllNamespacesStats()
	}
	if err != nil {
		log.Printf("Error getting stats: %v", err)
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

// APIClusterNamespaces returns all namespaces from the Kubernetes cluster
func (h *Handler) APIClusterNamespaces(w http.ResponseWriter, r *http.Request) {
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to returning an error - likely running outside cluster
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      "Not running in cluster",
			"namespaces": []string{},
		})
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      fmt.Sprintf("Failed to create k8s client: %v", err),
			"namespaces": []string{},
		})
		return
	}

	ctx := context.Background()
	nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      fmt.Sprintf("Failed to list namespaces: %v", err),
			"namespaces": []string{},
		})
		return
	}

	namespaces := make([]string, 0, len(nsList.Items))
	for _, ns := range nsList.Items {
		namespaces = append(namespaces, ns.Name)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"namespaces": namespaces,
	})
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

// Analytics API endpoints

// APIErrorTrend returns daily error counts for charts
func (h *Handler) APIErrorTrend(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")
	daysStr := r.URL.Query().Get("days")

	if !validateNamespace(namespace) {
		http.Error(w, "Invalid namespace parameter", http.StatusBadRequest)
		return
	}

	days := 30
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	data, err := h.db.GetErrorTrendAggregated(namespace, days)
	if err != nil {
		log.Printf("Error getting error trend: %v", err)
		http.Error(w, "Error retrieving data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": data,
		"days": days,
	})
}

// APIFixRate returns fix success rate data
func (h *Handler) APIFixRate(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")
	daysStr := r.URL.Query().Get("days")

	if !validateNamespace(namespace) {
		http.Error(w, "Invalid namespace parameter", http.StatusBadRequest)
		return
	}

	days := 30
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	data, err := h.db.GetFixSuccessRate(namespace, days)
	if err != nil {
		log.Printf("Error getting fix success rate: %v", err)
		http.Error(w, "Error retrieving data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": data,
		"days": days,
	})
}

// APIProblematicPods returns most problematic pods ranking
func (h *Handler) APIProblematicPods(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")
	daysStr := r.URL.Query().Get("days")
	limitStr := r.URL.Query().Get("limit")

	if !validateNamespace(namespace) {
		http.Error(w, "Invalid namespace parameter", http.StatusBadRequest)
		return
	}

	days := 30
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 50 {
			limit = l
		}
	}

	data, err := h.db.GetMostProblematicPods(namespace, days, limit)
	if err != nil {
		log.Printf("Error getting problematic pods: %v", err)
		http.Error(w, "Error retrieving data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data":  data,
		"days":  days,
		"limit": limit,
	})
}

// APICategoryBreakdown returns error category distribution
func (h *Handler) APICategoryBreakdown(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")
	daysStr := r.URL.Query().Get("days")

	if !validateNamespace(namespace) {
		http.Error(w, "Invalid namespace parameter", http.StatusBadRequest)
		return
	}

	days := 30
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	data, err := h.db.GetCategoryBreakdown(namespace, days)
	if err != nil {
		log.Printf("Error getting category breakdown: %v", err)
		http.Error(w, "Error retrieving data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": data,
		"days": days,
	})
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

// DeleteRun deletes a specific run and its fixes
func (h *Handler) DeleteRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	runIDStr := r.URL.Query().Get("id")
	runID, err := validateRunID(runIDStr)
	if err != nil || runID <= 0 {
		log.Printf("Invalid run ID for delete: %s", runIDStr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid run ID",
		})
		return
	}

	err = h.db.DeleteRun(runID)
	if err != nil {
		log.Printf("Error deleting run %d: %v", runID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to delete run: %v", err),
		})
		return
	}

	log.Printf("Deleted run %d", runID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Run #%d deleted successfully", runID),
	})
}

// ResetDatabase clears all runs and fixes from the database
func (h *Handler) ResetDatabase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := h.db.ResetDatabase()
	if err != nil {
		log.Printf("Error resetting database: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to reset database: %v", err),
		})
		return
	}

	log.Printf("Database reset successfully")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Database reset successfully",
	})
}

// TriggerRun creates a new Job from the CronJob to trigger an immediate run
func (h *Handler) TriggerRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get parameters
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "report" // Default to report mode for safety
	}
	if mode != "report" && mode != "autonomous" {
		http.Error(w, "Invalid mode: use 'report' or 'autonomous'", http.StatusBadRequest)
		return
	}

	// Get optional namespace to target (overrides CronJob's TARGET_NAMESPACES)
	targetNamespace := r.URL.Query().Get("namespace")

	// Get cronjob name from environment or use default
	cronjobName := os.Getenv("CRONJOB_NAME")
	if cronjobName == "" {
		cronjobName = "clopus-watcher"
	}
	cronjobNamespace := os.Getenv("CRONJOB_NAMESPACE")
	if cronjobNamespace == "" {
		cronjobNamespace = "default"
	}

	// Create Kubernetes client using in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Printf("Error creating in-cluster config: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to create k8s config: %v", err),
		})
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("Error creating kubernetes client: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to create k8s client: %v", err),
		})
		return
	}

	ctx := context.Background()

	// Get the CronJob to use as template
	cronJob, err := clientset.BatchV1().CronJobs(cronjobNamespace).Get(ctx, cronjobName, metav1.GetOptions{})
	if err != nil {
		log.Printf("Error getting cronjob %s/%s: %v", cronjobNamespace, cronjobName, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to get CronJob: %v", err),
		})
		return
	}

	// Generate unique job name
	timestamp := time.Now().Unix()
	jobName := fmt.Sprintf("%s-manual-%d", cronjobName, timestamp)

	// Create Job from CronJob spec
	jobSpec := cronJob.Spec.JobTemplate.Spec.DeepCopy()

	// Override environment variables in the container
	for i := range jobSpec.Template.Spec.Containers {
		container := &jobSpec.Template.Spec.Containers[i]
		modeFound := false
		namespaceFound := false
		for j := range container.Env {
			if container.Env[j].Name == "MODE" {
				container.Env[j].Value = mode
				modeFound = true
			}
			// Override TARGET_NAMESPACES if a specific namespace was requested
			if container.Env[j].Name == "TARGET_NAMESPACES" && targetNamespace != "" {
				container.Env[j].Value = targetNamespace
				namespaceFound = true
			}
		}
		// If MODE env var doesn't exist, add it
		if !modeFound {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "MODE",
				Value: mode,
			})
		}
		// If TARGET_NAMESPACES doesn't exist but namespace was requested, add it
		if !namespaceFound && targetNamespace != "" {
			container.Env = append(container.Env, corev1.EnvVar{
				Name:  "TARGET_NAMESPACES",
				Value: targetNamespace,
			})
		}
	}

	jobLabels := map[string]string{
		"app":        "clopus-watcher",
		"created-by": "dashboard",
		"mode":       mode,
	}
	if targetNamespace != "" {
		jobLabels["target-namespace"] = targetNamespace
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: cronjobNamespace,
			Labels:    jobLabels,
			Annotations: map[string]string{
				"cronjob.kubernetes.io/instantiate": "manual",
			},
		},
		Spec: *jobSpec,
	}

	// Create the job
	createdJob, err := clientset.BatchV1().Jobs(cronjobNamespace).Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		log.Printf("Error creating job: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to create Job: %v", err),
		})
		return
	}

	if targetNamespace != "" {
		log.Printf("Triggered manual run: %s (namespace: %s)", createdJob.Name, targetNamespace)
	} else {
		log.Printf("Triggered manual run: %s", createdJob.Name)
	}

	response := map[string]interface{}{
		"success": true,
		"job":     createdJob.Name,
		"mode":    mode,
		"message": fmt.Sprintf("Run triggered successfully. Job: %s", createdJob.Name),
	}
	if targetNamespace != "" {
		response["namespace"] = targetNamespace
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// WebhookStatus returns the current webhook configuration status
func (h *Handler) WebhookStatus(w http.ResponseWriter, r *http.Request) {
	wm := webhooks.Get()
	config := wm.GetConfig()

	status := map[string]interface{}{
		"enabled": wm.IsEnabled(),
		"format":  config.Format,
		"events":  config.Events,
	}

	if config.LastError != "" {
		status["last_error"] = config.LastError
	}
	if !config.LastSuccess.IsZero() {
		status["last_success"] = config.LastSuccess.Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// WebhookTest sends a test notification
func (h *Handler) WebhookTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	wm := webhooks.Get()
	if !wm.IsEnabled() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Webhooks are not enabled. Set WEBHOOK_URL environment variable.",
		})
		return
	}

	err := wm.SendTest()
	if err != nil {
		log.Printf("Webhook test failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Webhook test failed: %v", err),
		})
		return
	}

	log.Printf("Webhook test sent successfully")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Test notification sent successfully",
	})
}

// === Intelligence Feature Handlers ===

// APIRecurringIssues returns issues that have occurred multiple times
func (h *Handler) APIRecurringIssues(w http.ResponseWriter, r *http.Request) {
	daysStr := r.URL.Query().Get("days")
	minOccStr := r.URL.Query().Get("min")

	days := 30
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	minOccurrences := 2
	if minOccStr != "" {
		if m, err := strconv.Atoi(minOccStr); err == nil && m > 0 && m <= 100 {
			minOccurrences = m
		}
	}

	issues, err := h.db.GetRecurringIssues(minOccurrences, days)
	if err != nil {
		log.Printf("Error getting recurring issues: %v", err)
		http.Error(w, "Error retrieving data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"issues":          issues,
		"days":            days,
		"min_occurrences": minOccurrences,
	})
}

// APISimilarIssues finds similar historical issues for a given error
func (h *Handler) APISimilarIssues(w http.ResponseWriter, r *http.Request) {
	errorType := r.URL.Query().Get("error_type")
	errorMessage := r.URL.Query().Get("error_message")
	category := r.URL.Query().Get("category")

	if errorType == "" {
		http.Error(w, "error_type parameter required", http.StatusBadRequest)
		return
	}

	issues, err := h.db.GetSimilarIssues(errorType, errorMessage, category, 10)
	if err != nil {
		log.Printf("Error getting similar issues: %v", err)
		// Return empty array instead of error
		issues = []db.IssueFingerprint{}
	}

	// Get recommended fix if available
	recommendedFix, successRate, _ := h.db.GetRecommendedFix(errorType, category)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"similar_issues":   issues,
		"recommended_fix":  recommendedFix,
		"fix_success_rate": successRate,
	})
}

// APIFixSuccessRates returns fix success rates by type
func (h *Handler) APIFixSuccessRates(w http.ResponseWriter, r *http.Request) {
	daysStr := r.URL.Query().Get("days")

	days := 30
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	rates, err := h.db.GetFixSuccessRateByType(days)
	if err != nil {
		log.Printf("Error getting fix success rates: %v", err)
		http.Error(w, "Error retrieving data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rates": rates,
		"days":  days,
	})
}

// APIAnomalies returns detected anomalies
func (h *Handler) APIAnomalies(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("ns")
	daysStr := r.URL.Query().Get("days")
	limitStr := r.URL.Query().Get("limit")

	if !validateNamespace(namespace) {
		http.Error(w, "Invalid namespace parameter", http.StatusBadRequest)
		return
	}

	days := 7
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 90 {
			days = d
		}
	}

	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 200 {
			limit = l
		}
	}

	anomalies, err := h.db.GetRecentAnomalies(namespace, days, limit)
	if err != nil {
		log.Printf("Error getting anomalies: %v", err)
		http.Error(w, "Error retrieving data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"anomalies": anomalies,
		"days":      days,
		"namespace": namespace,
	})
}

// APICorrelatedIssues returns correlated issues for a fix
func (h *Handler) APICorrelatedIssues(w http.ResponseWriter, r *http.Request) {
	fixIDStr := r.URL.Query().Get("fix_id")

	fixID, err := strconv.Atoi(fixIDStr)
	if err != nil || fixID <= 0 {
		http.Error(w, "Invalid fix_id parameter", http.StatusBadRequest)
		return
	}

	correlations, err := h.db.GetCorrelatedIssuesForFix(fixID)
	if err != nil {
		log.Printf("Error getting correlations: %v", err)
		http.Error(w, "Error retrieving data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"correlations": correlations,
		"fix_id":       fixID,
	})
}

// APIRunbook returns the runbook for an issue type
func (h *Handler) APIRunbook(w http.ResponseWriter, r *http.Request) {
	errorType := r.URL.Query().Get("error_type")
	category := r.URL.Query().Get("category")
	fingerprintIDStr := r.URL.Query().Get("fingerprint_id")

	var runbook *db.Runbook
	var err error

	if fingerprintIDStr != "" {
		fingerprintID, _ := strconv.Atoi(fingerprintIDStr)
		if fingerprintID > 0 {
			runbook, err = h.db.GetRunbook(fingerprintID)
		}
	} else if errorType != "" {
		runbook, err = h.db.GetRunbookForIssue(errorType, category)
	} else {
		http.Error(w, "error_type or fingerprint_id required", http.StatusBadRequest)
		return
	}

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"runbook": nil,
			"message": "No runbook found for this issue type",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"runbook": runbook,
	})
}

// === Node Health Handlers ===

// APINodeHealth returns node health data
func (h *Handler) APINodeHealth(w http.ResponseWriter, r *http.Request) {
	runIDStr := r.URL.Query().Get("run_id")

	if runIDStr != "" {
		runID, err := strconv.Atoi(runIDStr)
		if err != nil || runID <= 0 {
			http.Error(w, "Invalid run_id parameter", http.StatusBadRequest)
			return
		}

		nodes, err := h.db.GetNodeHealthByRun(runID)
		if err != nil {
			log.Printf("Error getting node health for run %d: %v", runID, err)
			http.Error(w, "Error retrieving data", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"nodes":  nodes,
			"run_id": runID,
		})
		return
	}

	// Return latest health for all nodes
	nodes, err := h.db.GetLatestNodeHealth()
	if err != nil {
		log.Printf("Error getting latest node health: %v", err)
		http.Error(w, "Error retrieving data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"nodes": nodes,
	})
}

// APIUnhealthyNodes returns nodes with issues
func (h *Handler) APIUnhealthyNodes(w http.ResponseWriter, r *http.Request) {
	daysStr := r.URL.Query().Get("days")

	days := 7
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 90 {
			days = d
		}
	}

	nodes, err := h.db.GetUnhealthyNodes(days)
	if err != nil {
		log.Printf("Error getting unhealthy nodes: %v", err)
		http.Error(w, "Error retrieving data", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"nodes": nodes,
		"days":  days,
	})
}

// APILiveNodeHealth fetches current node health from the cluster
func (h *Handler) APILiveNodeHealth(w http.ResponseWriter, r *http.Request) {
	config, err := rest.InClusterConfig()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Not running in cluster",
			"nodes": []interface{}{},
		})
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Failed to create k8s client: %v", err),
			"nodes": []interface{}{},
		})
		return
	}

	ctx := context.Background()
	nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Failed to list nodes: %v", err),
			"nodes": []interface{}{},
		})
		return
	}

	var nodes []map[string]interface{}
	for _, node := range nodeList.Items {
		nodeInfo := map[string]interface{}{
			"name":   node.Name,
			"status": "Unknown",
		}

		// Get status from conditions
		for _, condition := range node.Status.Conditions {
			if condition.Type == corev1.NodeReady {
				if condition.Status == corev1.ConditionTrue {
					nodeInfo["status"] = "Ready"
				} else {
					nodeInfo["status"] = "NotReady"
				}
			}
			if condition.Type == corev1.NodeMemoryPressure && condition.Status == corev1.ConditionTrue {
				nodeInfo["memory_pressure"] = true
			}
			if condition.Type == corev1.NodeDiskPressure && condition.Status == corev1.ConditionTrue {
				nodeInfo["disk_pressure"] = true
			}
			if condition.Type == corev1.NodePIDPressure && condition.Status == corev1.ConditionTrue {
				nodeInfo["pid_pressure"] = true
			}
			if condition.Type == corev1.NodeNetworkUnavailable && condition.Status == corev1.ConditionTrue {
				nodeInfo["network_unavailable"] = true
			}
		}

		// Get allocatable resources
		if cpu := node.Status.Allocatable.Cpu(); cpu != nil {
			nodeInfo["allocatable_cpu"] = cpu.String()
		}
		if mem := node.Status.Allocatable.Memory(); mem != nil {
			nodeInfo["allocatable_memory"] = mem.String()
		}

		// Get node info
		nodeInfo["os"] = node.Status.NodeInfo.OSImage
		nodeInfo["kernel"] = node.Status.NodeInfo.KernelVersion
		nodeInfo["container_runtime"] = node.Status.NodeInfo.ContainerRuntimeVersion
		nodeInfo["kubelet_version"] = node.Status.NodeInfo.KubeletVersion

		nodes = append(nodes, nodeInfo)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"nodes":     nodes,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// === Live Pod Logs Handler ===

// APIPodLogs streams pod logs
func (h *Handler) APIPodLogs(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	podName := r.URL.Query().Get("pod")
	container := r.URL.Query().Get("container")
	tailStr := r.URL.Query().Get("tail")
	previous := r.URL.Query().Get("previous") == "true"

	if namespace == "" || podName == "" {
		http.Error(w, "namespace and pod parameters required", http.StatusBadRequest)
		return
	}

	tail := int64(100)
	if tailStr != "" {
		if t, err := strconv.ParseInt(tailStr, 10, 64); err == nil && t > 0 && t <= 5000 {
			tail = t
		}
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Not running in cluster",
			"logs":  "",
		})
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Failed to create k8s client: %v", err),
			"logs":  "",
		})
		return
	}

	ctx := context.Background()

	podLogOpts := &corev1.PodLogOptions{
		TailLines:  &tail,
		Timestamps: true,
		Previous:   previous,
	}

	if container != "" {
		podLogOpts.Container = container
	}

	req := clientset.CoreV1().Pods(namespace).GetLogs(podName, podLogOpts)
	podLogs, err := req.Stream(ctx)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Failed to get logs: %v", err),
			"logs":  "",
		})
		return
	}
	defer podLogs.Close()

	// Read logs into buffer
	buf := new(strings.Builder)
	readBuf := make([]byte, 4096)
	for {
		n, readErr := podLogs.Read(readBuf)
		if n > 0 {
			buf.Write(readBuf[:n])
		}
		if readErr != nil {
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":      buf.String(),
		"namespace": namespace,
		"pod":       podName,
		"container": container,
		"tail":      tail,
		"previous":  previous,
	})
}

// APIPodLogsStream provides SSE streaming of pod logs
func (h *Handler) APIPodLogsStream(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	podName := r.URL.Query().Get("pod")
	container := r.URL.Query().Get("container")

	if namespace == "" || podName == "" {
		http.Error(w, "namespace and pod parameters required", http.StatusBadRequest)
		return
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		http.Error(w, "Not running in cluster", http.StatusServiceUnavailable)
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create k8s client: %v", err), http.StatusInternalServerError)
		return
	}

	ctx := r.Context()

	sinceSeconds := int64(1) // Start from 1 second ago
	podLogOpts := &corev1.PodLogOptions{
		Follow:       true,
		Timestamps:   true,
		SinceSeconds: &sinceSeconds,
	}

	if container != "" {
		podLogOpts.Container = container
	}

	req := clientset.CoreV1().Pods(namespace).GetLogs(podName, podLogOpts)
	podLogs, err := req.Stream(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to stream logs: %v", err), http.StatusInternalServerError)
		return
	}
	defer podLogs.Close()

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// Read and stream logs line by line
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := podLogs.Read(buf)
			if err != nil {
				// Send error event and close
				fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
				flusher.Flush()
				return
			}
			if n > 0 {
				// Send log data as SSE event
				lines := strings.Split(string(buf[:n]), "\n")
				for _, line := range lines {
					if line != "" {
						fmt.Fprintf(w, "data: %s\n\n", line)
					}
				}
				flusher.Flush()
			}
		}
	}
}

// APIPodContainers returns containers for a pod
func (h *Handler) APIPodContainers(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	podName := r.URL.Query().Get("pod")

	if namespace == "" || podName == "" {
		http.Error(w, "namespace and pod parameters required", http.StatusBadRequest)
		return
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      "Not running in cluster",
			"containers": []interface{}{},
		})
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      fmt.Sprintf("Failed to create k8s client: %v", err),
			"containers": []interface{}{},
		})
		return
	}

	ctx := context.Background()
	pod, err := clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":      fmt.Sprintf("Pod not found: %v", err),
			"containers": []interface{}{},
		})
		return
	}

	var containers []map[string]interface{}

	// Init containers
	for _, c := range pod.Spec.InitContainers {
		containerInfo := map[string]interface{}{
			"name":  c.Name,
			"type":  "init",
			"image": c.Image,
		}
		containers = append(containers, containerInfo)
	}

	// Regular containers
	for _, c := range pod.Spec.Containers {
		containerInfo := map[string]interface{}{
			"name":  c.Name,
			"type":  "container",
			"image": c.Image,
		}

		// Find status
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Name == c.Name {
				containerInfo["ready"] = cs.Ready
				containerInfo["restart_count"] = cs.RestartCount
				if cs.State.Running != nil {
					containerInfo["state"] = "running"
				} else if cs.State.Waiting != nil {
					containerInfo["state"] = "waiting"
					containerInfo["reason"] = cs.State.Waiting.Reason
				} else if cs.State.Terminated != nil {
					containerInfo["state"] = "terminated"
					containerInfo["reason"] = cs.State.Terminated.Reason
				}
				break
			}
		}

		containers = append(containers, containerInfo)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"containers": containers,
		"namespace":  namespace,
		"pod":        podName,
	})
}

// APIListPods returns pods in a namespace
func (h *Handler) APIListPods(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")

	if namespace == "" {
		http.Error(w, "namespace parameter required", http.StatusBadRequest)
		return
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Not running in cluster",
			"pods":  []interface{}{},
		})
		return
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Failed to create k8s client: %v", err),
			"pods":  []interface{}{},
		})
		return
	}

	ctx := context.Background()
	podList, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Failed to list pods: %v", err),
			"pods":  []interface{}{},
		})
		return
	}

	var pods []map[string]interface{}
	for _, pod := range podList.Items {
		podInfo := map[string]interface{}{
			"name":      pod.Name,
			"namespace": pod.Namespace,
			"status":    string(pod.Status.Phase),
			"node":      pod.Spec.NodeName,
		}

		// Get container count and ready count
		totalContainers := len(pod.Spec.Containers)
		readyContainers := 0
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Ready {
				readyContainers++
			}
		}
		podInfo["containers"] = fmt.Sprintf("%d/%d", readyContainers, totalContainers)

		// Get restarts
		restarts := 0
		for _, cs := range pod.Status.ContainerStatuses {
			restarts += int(cs.RestartCount)
		}
		podInfo["restarts"] = restarts

		// Get age
		if !pod.CreationTimestamp.IsZero() {
			podInfo["age"] = time.Since(pod.CreationTimestamp.Time).Round(time.Second).String()
		}

		pods = append(pods, podInfo)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"pods":      pods,
		"namespace": namespace,
	})
}
