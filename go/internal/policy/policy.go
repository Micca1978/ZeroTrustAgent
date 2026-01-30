// Package policy provides policy evaluation for the Zero Trust Agent.
package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Micca1978/ZeroTrustAgent/go/internal/config"
	"github.com/Micca1978/ZeroTrustAgent/go/pkg/types"
)

// Engine evaluates security policies against security contexts.
type Engine struct {
	policies []types.Policy
	mu       sync.RWMutex
}

// NewEngine creates a new policy engine from configuration.
func NewEngine(configs []config.PolicyConfig) *Engine {
	engine := &Engine{
		policies: make([]types.Policy, 0, len(configs)),
	}

	for _, cfg := range configs {
		policy := types.Policy{
			ID:          cfg.ID,
			Name:        cfg.Name,
			Description: cfg.Description,
			Priority:    cfg.Priority,
			Effect:      types.PolicyEffect(cfg.Effect),
			Actions:     cfg.Actions,
			Conditions:  make([]types.PolicyCondition, 0, len(cfg.Conditions)),
		}

		for _, cond := range cfg.Conditions {
			policy.Conditions = append(policy.Conditions, types.PolicyCondition{
				Field:    cond.Field,
				Operator: cond.Operator,
				Value:    cond.Value,
			})
		}

		engine.policies = append(engine.policies, policy)
	}

	// Sort policies by priority (highest first)
	sort.Slice(engine.policies, func(i, j int) bool {
		return engine.policies[i].Priority > engine.policies[j].Priority
	})

	return engine
}

// Evaluate evaluates policies against the given security context.
func (e *Engine) Evaluate(ctx *types.SecurityContext) *types.PolicyDecision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, policy := range e.policies {
		if e.matchesPolicy(ctx, &policy) {
			return &types.PolicyDecision{
				Effect:     policy.Effect,
				PolicyID:   policy.ID,
				PolicyName: policy.Name,
				Reason:     fmt.Sprintf("Matched policy: %s", policy.Name),
			}
		}
	}

	// Default deny if no policy matches
	return &types.PolicyDecision{
		Effect: types.PolicyEffectDeny,
		Reason: "No matching policy found - default deny",
	}
}

// matchesPolicy checks if a security context matches a policy.
func (e *Engine) matchesPolicy(ctx *types.SecurityContext, policy *types.Policy) bool {
	for _, condition := range policy.Conditions {
		if !e.evaluateCondition(ctx, &condition) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single policy condition.
func (e *Engine) evaluateCondition(ctx *types.SecurityContext, condition *types.PolicyCondition) bool {
	value := e.getContextValue(ctx, condition.Field)

	switch condition.Operator {
	case "eq":
		return e.compareEqual(value, condition.Value)
	case "ne":
		return !e.compareEqual(value, condition.Value)
	case "gt":
		return e.compareGreaterThan(value, condition.Value)
	case "lt":
		return e.compareLessThan(value, condition.Value)
	case "gte":
		return e.compareGreaterThan(value, condition.Value) || e.compareEqual(value, condition.Value)
	case "lte":
		return e.compareLessThan(value, condition.Value) || e.compareEqual(value, condition.Value)
	case "in":
		return e.compareIn(value, condition.Value)
	case "not_in":
		return !e.compareIn(value, condition.Value)
	case "regex":
		return e.compareRegex(value, condition.Value)
	case "contains":
		return e.compareContains(value, condition.Value)
	case "starts_with":
		return e.compareStartsWith(value, condition.Value)
	case "ends_with":
		return e.compareEndsWith(value, condition.Value)
	default:
		return false
	}
}

// getContextValue extracts a value from the security context using dot notation.
func (e *Engine) getContextValue(ctx *types.SecurityContext, field string) interface{} {
	parts := strings.Split(field, ".")

	switch parts[0] {
	case "identity":
		return ctx.Identity
	case "action":
		return ctx.Action
	case "resource":
		return ctx.Resource
	case "ip_address":
		return ctx.IPAddress
	case "user_agent":
		return ctx.UserAgent
	case "attributes":
		if len(parts) > 1 && ctx.Attributes != nil {
			return e.getNestedValue(ctx.Attributes, parts[1:])
		}
		return ctx.Attributes
	case "environment":
		if len(parts) > 1 && ctx.Environment != nil {
			return ctx.Environment[parts[1]]
		}
		return ctx.Environment
	default:
		// Try attributes as fallback
		if ctx.Attributes != nil {
			return e.getNestedValue(ctx.Attributes, parts)
		}
		return nil
	}
}

// getNestedValue retrieves a nested value from a map using path parts.
func (e *Engine) getNestedValue(data map[string]interface{}, parts []string) interface{} {
	if len(parts) == 0 {
		return data
	}

	value, exists := data[parts[0]]
	if !exists {
		return nil
	}

	if len(parts) == 1 {
		return value
	}

	if nested, ok := value.(map[string]interface{}); ok {
		return e.getNestedValue(nested, parts[1:])
	}

	return nil
}

func (e *Engine) compareEqual(a, b interface{}) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

func (e *Engine) compareGreaterThan(a, b interface{}) bool {
	aFloat, aOk := toFloat64(a)
	bFloat, bOk := toFloat64(b)
	if aOk && bOk {
		return aFloat > bFloat
	}
	return fmt.Sprintf("%v", a) > fmt.Sprintf("%v", b)
}

func (e *Engine) compareLessThan(a, b interface{}) bool {
	aFloat, aOk := toFloat64(a)
	bFloat, bOk := toFloat64(b)
	if aOk && bOk {
		return aFloat < bFloat
	}
	return fmt.Sprintf("%v", a) < fmt.Sprintf("%v", b)
}

func (e *Engine) compareIn(value, list interface{}) bool {
	strValue := fmt.Sprintf("%v", value)

	switch v := list.(type) {
	case []interface{}:
		for _, item := range v {
			if fmt.Sprintf("%v", item) == strValue {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == strValue {
				return true
			}
		}
	}

	return false
}

func (e *Engine) compareRegex(value, pattern interface{}) bool {
	strValue := fmt.Sprintf("%v", value)
	strPattern := fmt.Sprintf("%v", pattern)

	re, err := regexp.Compile(strPattern)
	if err != nil {
		return false
	}

	return re.MatchString(strValue)
}

func (e *Engine) compareContains(value, substr interface{}) bool {
	strValue := fmt.Sprintf("%v", value)
	strSubstr := fmt.Sprintf("%v", substr)
	return strings.Contains(strValue, strSubstr)
}

func (e *Engine) compareStartsWith(value, prefix interface{}) bool {
	strValue := fmt.Sprintf("%v", value)
	strPrefix := fmt.Sprintf("%v", prefix)
	return strings.HasPrefix(strValue, strPrefix)
}

func (e *Engine) compareEndsWith(value, suffix interface{}) bool {
	strValue := fmt.Sprintf("%v", value)
	strSuffix := fmt.Sprintf("%v", suffix)
	return strings.HasSuffix(strValue, strSuffix)
}

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	default:
		return 0, false
	}
}

// AddPolicy adds a new policy to the engine.
func (e *Engine) AddPolicy(policy types.Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = append(e.policies, policy)

	// Re-sort by priority
	sort.Slice(e.policies, func(i, j int) bool {
		return e.policies[i].Priority > e.policies[j].Priority
	})
}

// RemovePolicy removes a policy by ID.
func (e *Engine) RemovePolicy(policyID string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	for i, p := range e.policies {
		if p.ID == policyID {
			e.policies = append(e.policies[:i], e.policies[i+1:]...)
			return true
		}
	}
	return false
}

// GetPolicies returns all policies.
func (e *Engine) GetPolicies() []types.Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]types.Policy, len(e.policies))
	copy(result, e.policies)
	return result
}
