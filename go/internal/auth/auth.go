// Package auth provides authentication management for the Zero Trust Agent.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/Micca1978/ZeroTrustAgent/go/internal/config"
	"github.com/Micca1978/ZeroTrustAgent/go/pkg/types"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account is locked")
	ErrAccountInactive    = errors.New("account is inactive")
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenRevoked       = errors.New("token has been revoked")
	ErrTokenInvalid       = errors.New("invalid token")
)

// AuthProvider defines the interface for authentication providers.
type AuthProvider interface {
	Authenticate(identity string, credentials interface{}) (*types.AuthResult, error)
	ValidateCredentials(identity string, credentials interface{}) error
	Name() string
}

// Manager handles authentication operations.
type Manager struct {
	config        *config.AuthConfig
	credentials   map[string]*types.Credentials
	tokens        map[string]*types.Token
	revokedTokens map[string]time.Time
	providers     map[string]AuthProvider
	mu            sync.RWMutex
}

// NewManager creates a new authentication manager.
func NewManager(cfg *config.AuthConfig) *Manager {
	m := &Manager{
		config:        cfg,
		credentials:   make(map[string]*types.Credentials),
		tokens:        make(map[string]*types.Token),
		revokedTokens: make(map[string]time.Time),
		providers:     make(map[string]AuthProvider),
	}

	// Register default password provider
	m.RegisterProvider(&PasswordProvider{manager: m})

	return m
}

// RegisterProvider registers an authentication provider.
func (m *Manager) RegisterProvider(provider AuthProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[provider.Name()] = provider
}

// CreateCredentials creates new credentials for an identity.
func (m *Manager) CreateCredentials(identity, password string) (*types.Credentials, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	creds := &types.Credentials{
		Identity:     identity,
		PasswordHash: string(hash),
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	m.mu.Lock()
	m.credentials[identity] = creds
	m.mu.Unlock()

	return creds, nil
}

// Authenticate attempts to authenticate with the given identity and password.
func (m *Manager) Authenticate(identity, password string) (*types.AuthResult, error) {
	m.mu.RLock()
	creds, exists := m.credentials[identity]
	m.mu.RUnlock()

	if !exists {
		return &types.AuthResult{
			Success: false,
			Error:   ErrInvalidCredentials.Error(),
		}, ErrInvalidCredentials
	}

	if !creds.IsActive {
		return &types.AuthResult{
			Success: false,
			Error:   ErrAccountInactive.Error(),
		}, ErrAccountInactive
	}

	if creds.IsLocked {
		return &types.AuthResult{
			Success:  false,
			Error:    ErrAccountLocked.Error(),
			Identity: identity,
		}, ErrAccountLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(password)); err != nil {
		m.recordFailedAttempt(identity)
		return &types.AuthResult{
			Success: false,
			Error:   ErrInvalidCredentials.Error(),
		}, ErrInvalidCredentials
	}

	// Reset failed attempts on successful login
	m.mu.Lock()
	creds.FailedAttempts = 0
	now := time.Now()
	creds.LastLoginAt = &now
	m.mu.Unlock()

	// Generate token
	token, err := m.GenerateToken(identity)
	if err != nil {
		return &types.AuthResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	return &types.AuthResult{
		Success:  true,
		Identity: identity,
		Token:    token,
	}, nil
}

// recordFailedAttempt records a failed authentication attempt.
func (m *Manager) recordFailedAttempt(identity string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	creds, exists := m.credentials[identity]
	if !exists {
		return
	}

	creds.FailedAttempts++
	if creds.FailedAttempts >= m.config.MaxFailedAttempts {
		creds.IsLocked = true
	}
}

// GenerateToken generates a new JWT token for the given identity.
func (m *Manager) GenerateToken(identity string) (*types.Token, error) {
	jti := generateJTI()
	now := time.Now()
	expiresAt := now.Add(m.config.TokenExpiration)

	claims := jwt.MapClaims{
		"sub": identity,
		"iss": "zta-agent",
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
		"jti": jti,
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString([]byte(m.config.JWTSecret))
	if err != nil {
		return nil, err
	}

	token := &types.Token{
		JTI:       jti,
		TokenType: "access",
		Identity:  identity,
		Claims: types.Claims{
			Subject:   identity,
			Issuer:    "zta-agent",
			IssuedAt:  now.Unix(),
			ExpiresAt: expiresAt.Unix(),
			JWTID:     jti,
			Extra:     map[string]interface{}{"token": tokenString},
		},
		IssuedAt:  now,
		ExpiresAt: expiresAt,
	}

	m.mu.Lock()
	m.tokens[jti] = token
	m.mu.Unlock()

	return token, nil
}

// ValidateToken validates a JWT token and returns the associated token info.
func (m *Manager) ValidateToken(tokenString string) (*types.Token, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalid
		}
		return []byte(m.config.JWTSecret), nil
	})

	if err != nil {
		return nil, ErrTokenInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrTokenInvalid
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, ErrTokenInvalid
	}

	// Check if token is revoked
	m.mu.RLock()
	_, revoked := m.revokedTokens[jti]
	storedToken := m.tokens[jti]
	m.mu.RUnlock()

	if revoked {
		return nil, ErrTokenRevoked
	}

	if storedToken != nil && storedToken.IsRevoked {
		return nil, ErrTokenRevoked
	}

	// Check expiration
	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().Unix() > int64(exp) {
		return nil, ErrTokenExpired
	}

	return storedToken, nil
}

// RevokeToken revokes a token by its JTI.
func (m *Manager) RevokeToken(jti string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.revokedTokens[jti] = time.Now()
	if token, exists := m.tokens[jti]; exists {
		token.IsRevoked = true
	}

	return nil
}

// GetCredentials returns credentials for an identity.
func (m *Manager) GetCredentials(identity string) (*types.Credentials, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	creds, exists := m.credentials[identity]
	return creds, exists
}

// UnlockAccount unlocks a locked account.
func (m *Manager) UnlockAccount(identity string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	creds, exists := m.credentials[identity]
	if !exists {
		return ErrInvalidCredentials
	}

	creds.IsLocked = false
	creds.FailedAttempts = 0
	return nil
}

// generateJTI generates a unique JWT ID.
func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// PasswordProvider implements password-based authentication.
type PasswordProvider struct {
	manager *Manager
}

func (p *PasswordProvider) Name() string {
	return "password"
}

func (p *PasswordProvider) Authenticate(identity string, credentials interface{}) (*types.AuthResult, error) {
	password, ok := credentials.(string)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	return p.manager.Authenticate(identity, password)
}

func (p *PasswordProvider) ValidateCredentials(identity string, credentials interface{}) error {
	password, ok := credentials.(string)
	if !ok {
		return ErrInvalidCredentials
	}

	creds, exists := p.manager.GetCredentials(identity)
	if !exists {
		return ErrInvalidCredentials
	}

	return bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(password))
}
