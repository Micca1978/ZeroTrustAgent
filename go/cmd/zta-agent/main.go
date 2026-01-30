// Package main provides the entry point for the Zero Trust Agent CLI.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Micca1978/ZeroTrustAgent/go/internal/auth"
	"github.com/Micca1978/ZeroTrustAgent/go/internal/config"
	"github.com/Micca1978/ZeroTrustAgent/go/internal/monitor"
	"github.com/Micca1978/ZeroTrustAgent/go/internal/policy"
	"github.com/Micca1978/ZeroTrustAgent/go/pkg/types"
)

func main() {
	configPath := flag.String("config", "config/policy.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Printf("Warning: Could not load config file: %v. Using defaults.", err)
		cfg = getDefaultConfig()
	}

	// Initialize components
	authManager := auth.NewManager(&cfg.Auth)
	policyEngine := policy.NewEngine(cfg.Policies)
	securityMonitor := monitor.NewMonitor(&cfg.Monitoring, &cfg.Logging)

	fmt.Println("Zero Trust Agent (Go) initialized successfully")
	fmt.Printf("  Policies loaded: %d\n", len(policyEngine.GetPolicies()))
	fmt.Printf("  Monitoring enabled: %v\n", cfg.Monitoring.Enabled)

	// Example: Create a test user and authenticate
	runExample(authManager, policyEngine, securityMonitor)
}

func getDefaultConfig() *config.Config {
	return &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:         "default-dev-secret-change-in-production",
			TokenExpiration:   1 * time.Hour,
			RefreshExpiration: 24 * time.Hour,
			MaxFailedAttempts: 5,
			LockoutDuration:   15 * time.Minute,
			Providers:         []string{"password"},
		},
		Policies: []config.PolicyConfig{
			{
				ID:          "allow-read",
				Name:        "Allow Read Operations",
				Description: "Allow read operations for authenticated users",
				Priority:    100,
				Conditions: []config.ConditionConfig{
					{Field: "action", Operator: "in", Value: []interface{}{"read", "list", "get"}},
				},
				Effect: "allow",
			},
			{
				ID:          "deny-admin",
				Name:        "Deny Admin Operations",
				Description: "Deny admin operations by default",
				Priority:    50,
				Conditions: []config.ConditionConfig{
					{Field: "action", Operator: "regex", Value: "^admin.*"},
				},
				Effect: "deny",
			},
			{
				ID:          "default-deny",
				Name:        "Default Deny",
				Description: "Deny all unmatched requests",
				Priority:    0,
				Conditions:  []config.ConditionConfig{},
				Effect:      "deny",
			},
		},
		Monitoring: config.MonitoringConfig{
			Enabled:         true,
			RateLimitWindow: 1 * time.Minute,
			RateLimitMax:    100,
			AlertThreshold:  10,
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
}

func runExample(authMgr *auth.Manager, policyEng *policy.Engine, monitor *monitor.Monitor) {
	fmt.Println("\n--- Running Example ---")

	// Create a test user
	creds, err := authMgr.CreateCredentials("testuser", "SecurePass123!")
	if err != nil {
		log.Fatalf("Failed to create credentials: %v", err)
	}
	fmt.Printf("Created user: %s\n", creds.Identity)

	// Authenticate
	result, err := authMgr.Authenticate("testuser", "SecurePass123!")
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}
	fmt.Printf("Authentication successful. Token JTI: %s\n", result.Token.JTI)

	// Record auth success
	monitor.RecordAuthSuccess("testuser", "127.0.0.1", "CLI/1.0")

	// Evaluate policies
	contexts := []types.SecurityContext{
		{
			Identity:  "testuser",
			Action:    "read",
			Resource:  "/api/data",
			IPAddress: "127.0.0.1",
			Timestamp: time.Now(),
		},
		{
			Identity:  "testuser",
			Action:    "admin_delete",
			Resource:  "/api/users",
			IPAddress: "127.0.0.1",
			Timestamp: time.Now(),
		},
		{
			Identity:  "testuser",
			Action:    "write",
			Resource:  "/api/data",
			IPAddress: "127.0.0.1",
			Timestamp: time.Now(),
		},
	}

	for _, ctx := range contexts {
		decision := policyEng.Evaluate(&ctx)
		fmt.Printf("Action '%s' on '%s': %s (%s)\n",
			ctx.Action, ctx.Resource, decision.Effect, decision.Reason)
		monitor.RecordPolicyDecision(&ctx, decision)
	}

	// Export events
	events := monitor.GetEvents()
	fmt.Printf("\nRecorded %d security events\n", len(events))

	fmt.Println("\n--- Example Complete ---")
	os.Exit(0)
}
