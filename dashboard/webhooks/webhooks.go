package webhooks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// EventType represents the type of webhook event
type EventType string

const (
	EventRunStarted   EventType = "run_started"
	EventRunCompleted EventType = "run_completed"
	EventErrorFound   EventType = "error_found"
	EventFixApplied   EventType = "fix_applied"
)

// WebhookPayload is the standard payload sent to webhook endpoints
type WebhookPayload struct {
	Event     EventType              `json:"event"`
	Timestamp string                 `json:"timestamp"`
	RunID     int                    `json:"run_id,omitempty"`
	Namespace string                 `json:"namespace,omitempty"`
	Mode      string                 `json:"mode,omitempty"`
	Status    string                 `json:"status,omitempty"`
	Message   string                 `json:"message,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// SlackPayload formats the webhook for Slack compatibility
type SlackPayload struct {
	Text        string            `json:"text"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

// SlackAttachment represents a Slack message attachment
type SlackAttachment struct {
	Color  string `json:"color"`
	Title  string `json:"title"`
	Text   string `json:"text"`
	Footer string `json:"footer"`
}

// WebhookConfig holds the webhook configuration
type WebhookConfig struct {
	URL         string
	Format      string // "generic" or "slack"
	Events      []EventType
	Enabled     bool
	LastError   string
	LastSuccess time.Time
}

// Manager handles webhook notifications
type Manager struct {
	config  *WebhookConfig
	client  *http.Client
	mu      sync.RWMutex
	enabled bool
}

var (
	instance *Manager
	once     sync.Once
)

// Init initializes the webhook manager from environment variables
func Init() *Manager {
	once.Do(func() {
		instance = &Manager{
			client: &http.Client{
				Timeout: 10 * time.Second,
			},
			config: &WebhookConfig{},
		}

		// Load configuration from environment
		webhookURL := os.Getenv("WEBHOOK_URL")
		if webhookURL != "" {
			instance.config.URL = webhookURL
			instance.config.Enabled = true
			instance.enabled = true

			// Determine format (default to generic, auto-detect slack)
			format := os.Getenv("WEBHOOK_FORMAT")
			if format == "" {
				if strings.Contains(webhookURL, "slack.com") || strings.Contains(webhookURL, "hooks.slack.com") {
					format = "slack"
				} else if strings.Contains(webhookURL, "discord.com") {
					format = "slack" // Discord accepts Slack-format webhooks
				} else {
					format = "generic"
				}
			}
			instance.config.Format = format

			// Parse enabled events (default: all events)
			eventsStr := os.Getenv("WEBHOOK_EVENTS")
			if eventsStr == "" {
				instance.config.Events = []EventType{
					EventRunStarted,
					EventRunCompleted,
					EventErrorFound,
					EventFixApplied,
				}
			} else {
				events := strings.Split(eventsStr, ",")
				for _, e := range events {
					e = strings.TrimSpace(e)
					switch e {
					case "run_started":
						instance.config.Events = append(instance.config.Events, EventRunStarted)
					case "run_completed":
						instance.config.Events = append(instance.config.Events, EventRunCompleted)
					case "error_found":
						instance.config.Events = append(instance.config.Events, EventErrorFound)
					case "fix_applied":
						instance.config.Events = append(instance.config.Events, EventFixApplied)
					}
				}
			}

			log.Printf("Webhook notifications enabled: %s (format: %s, events: %v)",
				maskURL(webhookURL), format, instance.config.Events)
		} else {
			log.Println("Webhook notifications disabled (WEBHOOK_URL not set)")
		}
	})

	return instance
}

// Get returns the singleton webhook manager
func Get() *Manager {
	if instance == nil {
		return Init()
	}
	return instance
}

// IsEnabled returns whether webhooks are enabled
func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// GetConfig returns a copy of the current configuration
func (m *Manager) GetConfig() WebhookConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return *m.config
}

// SendRunStarted sends a notification when a run starts
func (m *Manager) SendRunStarted(runID int, namespace, mode string) {
	if !m.shouldSend(EventRunStarted) {
		return
	}

	payload := WebhookPayload{
		Event:     EventRunStarted,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RunID:     runID,
		Namespace: namespace,
		Mode:      mode,
		Status:    "running",
		Message:   fmt.Sprintf("Watcher run started for namespace '%s' in %s mode", namespace, mode),
	}

	go m.send(payload)
}

// SendRunCompleted sends a notification when a run completes
func (m *Manager) SendRunCompleted(runID int, namespace, mode, status string, errorCount, fixCount, podCount int, duration time.Duration) {
	if !m.shouldSend(EventRunCompleted) {
		return
	}

	payload := WebhookPayload{
		Event:     EventRunCompleted,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RunID:     runID,
		Namespace: namespace,
		Mode:      mode,
		Status:    status,
		Message:   fmt.Sprintf("Watcher run completed: %d errors found, %d fixes applied across %d pods", errorCount, fixCount, podCount),
		Data: map[string]interface{}{
			"error_count": errorCount,
			"fix_count":   fixCount,
			"pod_count":   podCount,
			"duration_ms": duration.Milliseconds(),
		},
	}

	go m.send(payload)
}

// SendErrorFound sends a notification when errors are found
func (m *Manager) SendErrorFound(runID int, namespace, podName string, errorCount int, categories []string) {
	if !m.shouldSend(EventErrorFound) {
		return
	}

	payload := WebhookPayload{
		Event:     EventErrorFound,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RunID:     runID,
		Namespace: namespace,
		Message:   fmt.Sprintf("Found %d error(s) in pod '%s'", errorCount, podName),
		Data: map[string]interface{}{
			"pod_name":    podName,
			"error_count": errorCount,
			"categories":  categories,
		},
	}

	go m.send(payload)
}

// SendFixApplied sends a notification when a fix is applied
func (m *Manager) SendFixApplied(runID int, namespace, podName, fixType string, success bool) {
	if !m.shouldSend(EventFixApplied) {
		return
	}

	status := "success"
	if !success {
		status = "failed"
	}

	payload := WebhookPayload{
		Event:     EventFixApplied,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RunID:     runID,
		Namespace: namespace,
		Status:    status,
		Message:   fmt.Sprintf("Fix '%s' applied to pod '%s': %s", fixType, podName, status),
		Data: map[string]interface{}{
			"pod_name": podName,
			"fix_type": fixType,
			"success":  success,
		},
	}

	go m.send(payload)
}

// SendTest sends a test notification
func (m *Manager) SendTest() error {
	if !m.enabled {
		return fmt.Errorf("webhooks are not enabled")
	}

	payload := WebhookPayload{
		Event:     "test",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   "This is a test notification from Clopus Watcher",
		Data: map[string]interface{}{
			"test": true,
		},
	}

	return m.sendSync(payload)
}

func (m *Manager) shouldSend(event EventType) bool {
	if !m.enabled {
		return false
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, e := range m.config.Events {
		if e == event {
			return true
		}
	}
	return false
}

func (m *Manager) send(payload WebhookPayload) {
	if err := m.sendSync(payload); err != nil {
		log.Printf("Webhook error: %v", err)
	}
}

func (m *Manager) sendSync(payload WebhookPayload) error {
	m.mu.RLock()
	url := m.config.URL
	format := m.config.Format
	m.mu.RUnlock()

	var body []byte
	var err error

	if format == "slack" {
		slackPayload := m.formatSlack(payload)
		body, err = json.Marshal(slackPayload)
	} else {
		body, err = json.Marshal(payload)
	}

	if err != nil {
		m.setError(err.Error())
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		m.setError(err.Error())
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Clopus-Watcher/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		m.setError(err.Error())
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errMsg := fmt.Sprintf("webhook returned status %d", resp.StatusCode)
		m.setError(errMsg)
		return fmt.Errorf(errMsg)
	}

	m.setSuccess()
	log.Printf("Webhook sent: %s", payload.Event)
	return nil
}

func (m *Manager) formatSlack(payload WebhookPayload) SlackPayload {
	// Choose color based on event/status
	color := "#36a64f" // green
	emoji := ":white_check_mark:"

	switch payload.Event {
	case EventRunStarted:
		color = "#439FE0" // blue
		emoji = ":rocket:"
	case EventRunCompleted:
		if payload.Status == "completed" {
			if data, ok := payload.Data["error_count"].(int); ok && data > 0 {
				color = "#FFA500" // orange
				emoji = ":warning:"
			}
		} else if payload.Status == "failed" {
			color = "#FF0000" // red
			emoji = ":x:"
		}
	case EventErrorFound:
		color = "#FF0000" // red
		emoji = ":rotating_light:"
	case EventFixApplied:
		if payload.Status == "failed" {
			color = "#FF0000"
			emoji = ":x:"
		} else {
			emoji = ":wrench:"
		}
	}

	// Build details text
	var details []string
	if payload.Namespace != "" {
		details = append(details, fmt.Sprintf("*Namespace:* %s", payload.Namespace))
	}
	if payload.Mode != "" {
		details = append(details, fmt.Sprintf("*Mode:* %s", payload.Mode))
	}
	if payload.RunID > 0 {
		details = append(details, fmt.Sprintf("*Run ID:* %d", payload.RunID))
	}

	// Add data fields
	if payload.Data != nil {
		if errorCount, ok := payload.Data["error_count"]; ok {
			details = append(details, fmt.Sprintf("*Errors:* %v", errorCount))
		}
		if fixCount, ok := payload.Data["fix_count"]; ok {
			details = append(details, fmt.Sprintf("*Fixes:* %v", fixCount))
		}
		if podName, ok := payload.Data["pod_name"]; ok {
			details = append(details, fmt.Sprintf("*Pod:* %s", podName))
		}
	}

	return SlackPayload{
		Text: fmt.Sprintf("%s %s", emoji, payload.Message),
		Attachments: []SlackAttachment{
			{
				Color:  color,
				Title:  string(payload.Event),
				Text:   strings.Join(details, "\n"),
				Footer: fmt.Sprintf("Clopus Watcher | %s", payload.Timestamp),
			},
		},
	}
}

func (m *Manager) setError(err string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.LastError = err
}

func (m *Manager) setSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.LastError = ""
	m.config.LastSuccess = time.Now()
}

// maskURL masks sensitive parts of the webhook URL for logging
func maskURL(url string) string {
	if len(url) < 20 {
		return "***"
	}
	// Show first 30 chars and last 10
	if len(url) > 50 {
		return url[:30] + "..." + url[len(url)-10:]
	}
	return url[:len(url)/2] + "***"
}
