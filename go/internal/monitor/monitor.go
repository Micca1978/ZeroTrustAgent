// Package monitor provides security monitoring for the Zero Trust Agent.
package monitor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/Micca1978/ZeroTrustAgent/go/internal/config"
	"github.com/Micca1978/ZeroTrustAgent/go/pkg/types"
)

// Monitor handles security event recording, rate limiting, and alerting.
type Monitor struct {
	config       *config.MonitoringConfig
	events       []types.SecurityEvent
	rateLimiter  map[string][]time.Time
	alertCount   int
	logger       *slog.Logger
	eventHandler func(types.SecurityEvent)
	mu           sync.RWMutex
}

// NewMonitor creates a new security monitor.
func NewMonitor(cfg *config.MonitoringConfig, logCfg *config.LoggingConfig) *Monitor {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level: parseLogLevel(logCfg.Level),
	}

	if logCfg.OutputPath != "" {
		file, err := os.OpenFile(logCfg.OutputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			if logCfg.Format == "json" {
				handler = slog.NewJSONHandler(file, opts)
			} else {
				handler = slog.NewTextHandler(file, opts)
			}
		}
	}

	if handler == nil {
		if logCfg.Format == "json" {
			handler = slog.NewJSONHandler(os.Stdout, opts)
		} else {
			handler = slog.NewTextHandler(os.Stdout, opts)
		}
	}

	return &Monitor{
		config:      cfg,
		events:      make([]types.SecurityEvent, 0),
		rateLimiter: make(map[string][]time.Time),
		logger:      slog.New(handler),
	}
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// RecordEvent records a security event.
func (m *Monitor) RecordEvent(event types.SecurityEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate ID if not set
	if event.ID == "" {
		event.ID = generateEventID()
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	m.events = append(m.events, event)

	// Log the event
	m.logEvent(event)

	// Check alert threshold
	if event.Severity == types.SeverityHigh || event.Severity == types.SeverityCritical {
		m.alertCount++
		if m.alertCount >= m.config.AlertThreshold {
			m.triggerAlert(event)
		}
	}

	// Call event handler if set
	if m.eventHandler != nil {
		m.eventHandler(event)
	}
}

func (m *Monitor) logEvent(event types.SecurityEvent) {
	attrs := []any{
		slog.String("event_id", event.ID),
		slog.String("event_type", string(event.EventType)),
		slog.String("severity", string(event.Severity)),
	}

	if event.Identity != "" {
		attrs = append(attrs, slog.String("identity", event.Identity))
	}
	if event.Action != "" {
		attrs = append(attrs, slog.String("action", event.Action))
	}
	if event.Resource != "" {
		attrs = append(attrs, slog.String("resource", event.Resource))
	}
	if event.IPAddress != "" {
		attrs = append(attrs, slog.String("ip_address", event.IPAddress))
	}

	switch event.Severity {
	case types.SeverityCritical:
		m.logger.Error("Security event", attrs...)
	case types.SeverityHigh:
		m.logger.Warn("Security event", attrs...)
	case types.SeverityMedium:
		m.logger.Info("Security event", attrs...)
	default:
		m.logger.Debug("Security event", attrs...)
	}
}

func (m *Monitor) triggerAlert(event types.SecurityEvent) {
	m.logger.Error("ALERT: Security threshold exceeded",
		slog.String("event_id", event.ID),
		slog.String("event_type", string(event.EventType)),
		slog.Int("alert_count", m.alertCount),
	)
}

// CheckRateLimit checks if the rate limit has been exceeded for a key.
func (m *Monitor) CheckRateLimit(key string) bool {
	if !m.config.Enabled {
		return true
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-m.config.RateLimitWindow)

	// Get existing timestamps and filter old ones
	timestamps := m.rateLimiter[key]
	validTimestamps := make([]time.Time, 0)
	for _, ts := range timestamps {
		if ts.After(windowStart) {
			validTimestamps = append(validTimestamps, ts)
		}
	}

	// Check if rate limit exceeded
	if len(validTimestamps) >= m.config.RateLimitMax {
		m.RecordEvent(types.SecurityEvent{
			EventType: types.EventTypeRateLimitHit,
			Severity:  types.SeverityMedium,
			Details:   map[string]interface{}{"key": key, "count": len(validTimestamps)},
		})
		return false
	}

	// Add current timestamp
	validTimestamps = append(validTimestamps, now)
	m.rateLimiter[key] = validTimestamps

	return true
}

// RecordAuthSuccess records a successful authentication event.
func (m *Monitor) RecordAuthSuccess(identity, ipAddress, userAgent string) {
	m.RecordEvent(types.SecurityEvent{
		EventType: types.EventTypeAuthSuccess,
		Severity:  types.SeverityLow,
		Identity:  identity,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Details:   map[string]interface{}{"status": "success"},
	})
}

// RecordAuthFailure records a failed authentication event.
func (m *Monitor) RecordAuthFailure(identity, ipAddress, userAgent, reason string) {
	m.RecordEvent(types.SecurityEvent{
		EventType: types.EventTypeAuthFailure,
		Severity:  types.SeverityMedium,
		Identity:  identity,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Details:   map[string]interface{}{"status": "failure", "reason": reason},
	})
}

// RecordPolicyDecision records a policy evaluation decision.
func (m *Monitor) RecordPolicyDecision(ctx *types.SecurityContext, decision *types.PolicyDecision) {
	eventType := types.EventTypePolicyAllow
	severity := types.SeverityLow
	if decision.Effect == types.PolicyEffectDeny {
		eventType = types.EventTypePolicyDeny
		severity = types.SeverityMedium
	}

	m.RecordEvent(types.SecurityEvent{
		EventType: eventType,
		Severity:  severity,
		Identity:  ctx.Identity,
		Action:    ctx.Action,
		Resource:  ctx.Resource,
		IPAddress: ctx.IPAddress,
		UserAgent: ctx.UserAgent,
		Details: map[string]interface{}{
			"policy_id":   decision.PolicyID,
			"policy_name": decision.PolicyName,
			"effect":      decision.Effect,
			"reason":      decision.Reason,
		},
	})
}

// RecordThreatDetected records a threat detection event.
func (m *Monitor) RecordThreatDetected(identity string, threat *types.ThreatIndicator, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["threat_id"] = threat.ID
	details["threat_type"] = threat.Type
	details["confidence"] = threat.Confidence

	m.RecordEvent(types.SecurityEvent{
		EventType: types.EventTypeThreatDetected,
		Severity:  types.SeverityHigh,
		Identity:  identity,
		Details:   details,
	})
}

// GetEvents returns all recorded events.
func (m *Monitor) GetEvents() []types.SecurityEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]types.SecurityEvent, len(m.events))
	copy(result, m.events)
	return result
}

// GetEventsByType returns events filtered by type.
func (m *Monitor) GetEventsByType(eventType types.EventType) []types.SecurityEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]types.SecurityEvent, 0)
	for _, event := range m.events {
		if event.EventType == eventType {
			result = append(result, event)
		}
	}
	return result
}

// GetEventsBySeverity returns events filtered by minimum severity.
func (m *Monitor) GetEventsBySeverity(minSeverity types.Severity) []types.SecurityEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	severityOrder := map[types.Severity]int{
		types.SeverityLow:      1,
		types.SeverityMedium:   2,
		types.SeverityHigh:     3,
		types.SeverityCritical: 4,
	}

	minLevel := severityOrder[minSeverity]
	result := make([]types.SecurityEvent, 0)
	for _, event := range m.events {
		if severityOrder[event.Severity] >= minLevel {
			result = append(result, event)
		}
	}
	return result
}

// SetEventHandler sets a callback function for new events.
func (m *Monitor) SetEventHandler(handler func(types.SecurityEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventHandler = handler
}

// ExportEvents exports events to JSON.
func (m *Monitor) ExportEvents() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return json.Marshal(m.events)
}

// ClearEvents clears all recorded events.
func (m *Monitor) ClearEvents() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = make([]types.SecurityEvent, 0)
	m.alertCount = 0
}

func generateEventID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
