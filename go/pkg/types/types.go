// Package types defines the core data types for the Zero Trust Agent.
package types

import (
	"time"
)

// Severity represents the severity level of a security event.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// EventType represents the type of security event.
type EventType string

const (
	EventTypeAuthSuccess    EventType = "auth_success"
	EventTypeAuthFailure    EventType = "auth_failure"
	EventTypePolicyDeny     EventType = "policy_deny"
	EventTypePolicyAllow    EventType = "policy_allow"
	EventTypeRateLimitHit   EventType = "rate_limit_hit"
	EventTypeThreatDetected EventType = "threat_detected"
	EventTypeAnomalyFound   EventType = "anomaly_found"
)

// PolicyEffect represents the effect of a policy decision.
type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
	PolicyEffectAudit PolicyEffect = "audit"
)

// Credentials represents user or agent identity credentials.
type Credentials struct {
	Identity          string     `json:"identity" yaml:"identity"`
	PasswordHash      string     `json:"password_hash,omitempty" yaml:"password_hash,omitempty"`
	FailedAttempts    int        `json:"failed_attempts" yaml:"failed_attempts"`
	IsLocked          bool       `json:"is_locked" yaml:"is_locked"`
	IsActive          bool       `json:"is_active" yaml:"is_active"`
	PasswordExpiresAt *time.Time `json:"password_expires_at,omitempty" yaml:"password_expires_at,omitempty"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty" yaml:"last_login_at,omitempty"`
	LastLoginIP       string     `json:"last_login_ip,omitempty" yaml:"last_login_ip,omitempty"`
	CreatedAt         time.Time  `json:"created_at" yaml:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" yaml:"updated_at"`
}

// Token represents a JWT authentication token.
type Token struct {
	JTI       string    `json:"jti" yaml:"jti"`
	TokenType string    `json:"token_type" yaml:"token_type"`
	Identity  string    `json:"identity" yaml:"identity"`
	Claims    Claims    `json:"claims" yaml:"claims"`
	IssuedAt  time.Time `json:"issued_at" yaml:"issued_at"`
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at"`
	IsRevoked bool      `json:"is_revoked" yaml:"is_revoked"`
	UserAgent string    `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`
	IPAddress string    `json:"ip_address,omitempty" yaml:"ip_address,omitempty"`
}

// Claims represents JWT token claims.
type Claims struct {
	Subject   string                 `json:"sub"`
	Issuer    string                 `json:"iss"`
	Audience  []string               `json:"aud,omitempty"`
	ExpiresAt int64                  `json:"exp"`
	IssuedAt  int64                  `json:"iat"`
	NotBefore int64                  `json:"nbf,omitempty"`
	JWTID     string                 `json:"jti,omitempty"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

// SecurityEvent represents a security-related event for logging and monitoring.
type SecurityEvent struct {
	ID        string                 `json:"id" yaml:"id"`
	EventType EventType              `json:"event_type" yaml:"event_type"`
	Severity  Severity               `json:"severity" yaml:"severity"`
	Identity  string                 `json:"identity,omitempty" yaml:"identity,omitempty"`
	Action    string                 `json:"action,omitempty" yaml:"action,omitempty"`
	Resource  string                 `json:"resource,omitempty" yaml:"resource,omitempty"`
	IPAddress string                 `json:"ip_address,omitempty" yaml:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty" yaml:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp" yaml:"timestamp"`
}

// Policy represents a security policy rule.
type Policy struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Priority    int               `json:"priority" yaml:"priority"`
	Conditions  []PolicyCondition `json:"conditions" yaml:"conditions"`
	Effect      PolicyEffect      `json:"effect" yaml:"effect"`
	Actions     []string          `json:"actions,omitempty" yaml:"actions,omitempty"`
}

// PolicyCondition represents a condition for policy evaluation.
type PolicyCondition struct {
	Field    string      `json:"field" yaml:"field"`
	Operator string      `json:"operator" yaml:"operator"`
	Value    interface{} `json:"value" yaml:"value"`
}

// SecurityContext represents the context for security evaluation.
type SecurityContext struct {
	Identity    string                 `json:"identity" yaml:"identity"`
	Action      string                 `json:"action" yaml:"action"`
	Resource    string                 `json:"resource" yaml:"resource"`
	IPAddress   string                 `json:"ip_address,omitempty" yaml:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty" yaml:"user_agent,omitempty"`
	Timestamp   time.Time              `json:"timestamp" yaml:"timestamp"`
	Attributes  map[string]interface{} `json:"attributes,omitempty" yaml:"attributes,omitempty"`
	Environment map[string]string      `json:"environment,omitempty" yaml:"environment,omitempty"`
}

// AuthResult represents the result of an authentication attempt.
type AuthResult struct {
	Success     bool       `json:"success"`
	Identity    string     `json:"identity,omitempty"`
	Token       *Token     `json:"token,omitempty"`
	Error       string     `json:"error,omitempty"`
	LockedUntil *time.Time `json:"locked_until,omitempty"`
}

// PolicyDecision represents the result of a policy evaluation.
type PolicyDecision struct {
	Effect     PolicyEffect `json:"effect"`
	PolicyID   string       `json:"policy_id,omitempty"`
	PolicyName string       `json:"policy_name,omitempty"`
	Reason     string       `json:"reason,omitempty"`
}

// ThreatIndicator represents an indicator of compromise (IOC).
type ThreatIndicator struct {
	ID         string    `json:"id" yaml:"id"`
	Type       string    `json:"type" yaml:"type"`
	Value      string    `json:"value" yaml:"value"`
	Confidence float64   `json:"confidence" yaml:"confidence"`
	Source     string    `json:"source,omitempty" yaml:"source,omitempty"`
	Tags       []string  `json:"tags,omitempty" yaml:"tags,omitempty"`
	ValidUntil time.Time `json:"valid_until,omitempty" yaml:"valid_until,omitempty"`
	CreatedAt  time.Time `json:"created_at" yaml:"created_at"`
}
