// Package config provides configuration loading and validation for the Zero Trust Agent.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure.
type Config struct {
	Auth       AuthConfig       `yaml:"auth"`
	Policies   []PolicyConfig   `yaml:"policies"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
	Logging    LoggingConfig    `yaml:"logging"`
}

// AuthConfig represents authentication configuration.
type AuthConfig struct {
	JWTSecret         string        `yaml:"jwt_secret"`
	TokenExpiration   time.Duration `yaml:"token_expiration"`
	RefreshExpiration time.Duration `yaml:"refresh_expiration"`
	MaxFailedAttempts int           `yaml:"max_failed_attempts"`
	LockoutDuration   time.Duration `yaml:"lockout_duration"`
	Providers         []string      `yaml:"providers"`
	OAuth             OAuthConfig   `yaml:"oauth,omitempty"`
}

// OAuthConfig represents OAuth provider configuration.
type OAuthConfig struct {
	Google GoogleOAuthConfig `yaml:"google,omitempty"`
	GitHub GitHubOAuthConfig `yaml:"github,omitempty"`
	Entra  EntraOAuthConfig  `yaml:"entra,omitempty"`
}

// GoogleOAuthConfig represents Google OAuth configuration.
type GoogleOAuthConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURI  string `yaml:"redirect_uri"`
	Scope        string `yaml:"scope"`
}

// GitHubOAuthConfig represents GitHub OAuth configuration.
type GitHubOAuthConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURI  string `yaml:"redirect_uri"`
	Scope        string `yaml:"scope"`
}

// EntraOAuthConfig represents Microsoft Entra ID configuration.
type EntraOAuthConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	TenantID     string `yaml:"tenant_id"`
	RedirectURI  string `yaml:"redirect_uri"`
	Scope        string `yaml:"scope"`
}

// PolicyConfig represents a policy configuration.
type PolicyConfig struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Priority    int               `yaml:"priority"`
	Conditions  []ConditionConfig `yaml:"conditions"`
	Effect      string            `yaml:"effect"`
	Actions     []string          `yaml:"actions,omitempty"`
}

// ConditionConfig represents a policy condition configuration.
type ConditionConfig struct {
	Field    string      `yaml:"field"`
	Operator string      `yaml:"operator"`
	Value    interface{} `yaml:"value"`
}

// MonitoringConfig represents monitoring configuration.
type MonitoringConfig struct {
	Enabled           bool          `yaml:"enabled"`
	RateLimitWindow   time.Duration `yaml:"rate_limit_window"`
	RateLimitMax      int           `yaml:"rate_limit_max"`
	AlertThreshold    int           `yaml:"alert_threshold"`
	GeoIPEnabled      bool          `yaml:"geoip_enabled"`
	GeoIPDatabasePath string        `yaml:"geoip_database_path,omitempty"`
}

// LoggingConfig represents logging configuration.
type LoggingConfig struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	OutputPath string `yaml:"output_path,omitempty"`
	MaxSize    int    `yaml:"max_size,omitempty"`
	MaxBackups int    `yaml:"max_backups,omitempty"`
	MaxAge     int    `yaml:"max_age,omitempty"`
}

// Load loads configuration from a YAML file and environment variables.
func Load(configPath string) (*Config, error) {
	// Load .env file if it exists
	_ = godotenv.Load()

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables in the config
	expandedData := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expandedData), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Load OAuth credentials from environment variables
	cfg.loadOAuthFromEnv()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// loadOAuthFromEnv loads OAuth configuration from environment variables.
func (c *Config) loadOAuthFromEnv() {
	// Google OAuth
	if clientID := os.Getenv("ZTA_GOOGLE_CLIENT_ID"); clientID != "" {
		c.Auth.OAuth.Google.ClientID = clientID
	}
	if clientSecret := os.Getenv("ZTA_GOOGLE_CLIENT_SECRET"); clientSecret != "" {
		c.Auth.OAuth.Google.ClientSecret = clientSecret
	}
	if redirectURI := os.Getenv("ZTA_GOOGLE_REDIRECT_URI"); redirectURI != "" {
		c.Auth.OAuth.Google.RedirectURI = redirectURI
	}
	if scope := os.Getenv("ZTA_GOOGLE_SCOPE"); scope != "" {
		c.Auth.OAuth.Google.Scope = scope
	}

	// GitHub OAuth
	if clientID := os.Getenv("ZTA_GITHUB_CLIENT_ID"); clientID != "" {
		c.Auth.OAuth.GitHub.ClientID = clientID
	}
	if clientSecret := os.Getenv("ZTA_GITHUB_CLIENT_SECRET"); clientSecret != "" {
		c.Auth.OAuth.GitHub.ClientSecret = clientSecret
	}
	if redirectURI := os.Getenv("ZTA_GITHUB_REDIRECT_URI"); redirectURI != "" {
		c.Auth.OAuth.GitHub.RedirectURI = redirectURI
	}
	if scope := os.Getenv("ZTA_GITHUB_SCOPE"); scope != "" {
		c.Auth.OAuth.GitHub.Scope = scope
	}

	// Microsoft Entra ID OAuth
	if clientID := os.Getenv("ZTA_ENTRA_CLIENT_ID"); clientID != "" {
		c.Auth.OAuth.Entra.ClientID = clientID
	}
	if clientSecret := os.Getenv("ZTA_ENTRA_CLIENT_SECRET"); clientSecret != "" {
		c.Auth.OAuth.Entra.ClientSecret = clientSecret
	}
	if tenantID := os.Getenv("ZTA_ENTRA_TENANT_ID"); tenantID != "" {
		c.Auth.OAuth.Entra.TenantID = tenantID
	}
	if redirectURI := os.Getenv("ZTA_ENTRA_REDIRECT_URI"); redirectURI != "" {
		c.Auth.OAuth.Entra.RedirectURI = redirectURI
	}
	if scope := os.Getenv("ZTA_ENTRA_SCOPE"); scope != "" {
		c.Auth.OAuth.Entra.Scope = scope
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.Auth.JWTSecret == "" {
		c.Auth.JWTSecret = os.Getenv("ZTA_JWT_SECRET")
		if c.Auth.JWTSecret == "" {
			c.Auth.JWTSecret = "default-dev-secret-change-in-production"
		}
	}

	if c.Auth.TokenExpiration == 0 {
		c.Auth.TokenExpiration = 1 * time.Hour
	}

	if c.Auth.RefreshExpiration == 0 {
		c.Auth.RefreshExpiration = 24 * time.Hour
	}

	if c.Auth.MaxFailedAttempts == 0 {
		c.Auth.MaxFailedAttempts = 5
	}

	if c.Auth.LockoutDuration == 0 {
		c.Auth.LockoutDuration = 15 * time.Minute
	}

	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}

	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}

	return nil
}

// GetEnv returns environment variable value or default.
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
