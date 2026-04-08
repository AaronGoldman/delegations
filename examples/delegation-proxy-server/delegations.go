package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// Delegation represents an authorization grant from a user to a specific agent+session pair.
// It doubles as the JWT payload: approval-time fields are omitted from the token via omitempty.
type Delegation struct {
	// Set at approval time; absent from the JWT payload.
	DelegationID string `json:"delegation_id,omitempty"`
	PrincipalID  string `json:"principal_id,omitempty"`
	Duration     string `json:"duration,omitempty"` // "once" | "session" | "agent"

	// JWT claims (spec §5.1).
	AgentID     string   `json:"agent_id"`
	SessionID   string   `json:"session_id"`
	HostPattern string   `json:"host"`    // "api.example.com" or "*.example.com"
	PathPattern string   `json:"path"`    // "/users/123/messages" or "/users/*"
	Methods     []string `json:"methods"`
	Scopes      []string `json:"scopes"`
	ExpiresAt   string   `json:"expires_at,omitempty"` // ISO 8601 / RFC 3339
	IssuedAt    int64    `json:"iat,omitempty"`
}

// jwtHeader is the base64url-encoded JWT header {"alg":"HS256","typ":"JWT"}.
var jwtHeader = base64.RawURLEncoding.EncodeToString(
	[]byte(`{"alg":"HS256","typ":"JWT"}`),
)

// jwtHeaderEdDSA is the base64url-encoded JWT header {"alg":"EdDSA","typ":"JWT"}.
var jwtHeaderEdDSA = base64.RawURLEncoding.EncodeToString(
	[]byte(`{"alg":"EdDSA","typ":"JWT"}`),
)

// JWT creates a compact serialized HS256 JWT from the delegation.
func (d Delegation) JWT(secret []byte) (string, error) {
	payload, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("JWT: marshal: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := jwtHeader + "." + encodedPayload

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// DelegationFromJWT verifies the signature of a compact JWT and returns the delegation.
// Returns an error if the signature is invalid or the token is expired.
func DelegationFromJWT(secret []byte, token string) (*Delegation, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("DelegationFromJWT: malformed token (expected 3 parts)")
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Use hmac.Equal for constant-time comparison to prevent timing attacks.
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, fmt.Errorf("DelegationFromJWT: invalid signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("DelegationFromJWT: decode payload: %w", err)
	}

	var d Delegation
	if err := json.Unmarshal(payload, &d); err != nil {
		return nil, fmt.Errorf("DelegationFromJWT: unmarshal: %w", err)
	}

	if d.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, d.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("DelegationFromJWT: parse expires_at: %w", err)
		}
		if time.Now().After(exp) {
			return nil, fmt.Errorf("DelegationFromJWT: token expired at %s", d.ExpiresAt)
		}
	}

	return &d, nil
}

// SignedJWT creates a compact serialized EdDSA (Ed25519) JWT from the delegation.
// Used by authMiddlewareMux to set the X-Delegation header on authenticated requests.
func (d Delegation) SignedJWT(privKey ed25519.PrivateKey) (string, error) {
	payload, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("SignedJWT: marshal: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := jwtHeaderEdDSA + "." + encodedPayload
	sig := ed25519.Sign(privKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// DelegationFromSignedJWT verifies the Ed25519 signature of a compact JWT and
// returns the delegation. Used by GetAuthInfo to read the X-Delegation header.
func DelegationFromSignedJWT(pubKey ed25519.PublicKey, token string) (*Delegation, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("DelegationFromSignedJWT: malformed token (expected 3 parts)")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("DelegationFromSignedJWT: decode signature: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pubKey, []byte(signingInput), sig) {
		return nil, fmt.Errorf("DelegationFromSignedJWT: invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("DelegationFromSignedJWT: decode payload: %w", err)
	}
	var d Delegation
	if err := json.Unmarshal(payload, &d); err != nil {
		return nil, fmt.Errorf("DelegationFromSignedJWT: unmarshal: %w", err)
	}
	return &d, nil
}

// matches checks all four conditions from spec §6.2.
func (d Delegation) matches(host, path, method string, requiredScopes []string) bool {
	if !matchPattern(d.HostPattern, host) || !matchPattern(d.PathPattern, path) {
		return false
	}
	if !slices.ContainsFunc(d.Methods, func(m string) bool { return strings.EqualFold(m, method) }) {
		return false
	}
	for _, req := range requiredScopes {
		if !slices.Contains(d.Scopes, req) {
			return false
		}
	}
	return true
}

// DelegationStore is the persistence interface for delegations.
// Swap in a database-backed implementation (e.g. database/sql + PostgreSQL) for production.
type DelegationStore interface {
	FindMatching(agentID, sessionID, host, path, method string, scopes []string) (Delegation, bool, error)
	ListDelegations() ([]Delegation, error)
	AddDelegation(d Delegation) error
	RevokeDelegation(delegationID string) error
}

// InMemoryDelegationStore is a thread-safe in-memory DelegationStore for development/testing.
type InMemoryDelegationStore struct {
	mu          sync.RWMutex
	delegations map[string]Delegation
	revoked     map[string]time.Time
}

// NewInMemoryDelegationStore creates a new empty in-memory delegation store.
func NewInMemoryDelegationStore() *InMemoryDelegationStore {
	return &InMemoryDelegationStore{
		delegations: make(map[string]Delegation),
		revoked:     make(map[string]time.Time),
	}
}

// FindMatching returns the first active delegation that fully authorizes the request.
// "agent" delegations match on agentID alone; "once" and "session" require both.
func (s *InMemoryDelegationStore) FindMatching(agentID, sessionID, host, path, method string, scopes []string) (Delegation, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id, d := range s.delegations {
		if _, isRevoked := s.revoked[id]; isRevoked {
			continue
		}
		if d.AgentID != agentID {
			continue
		}
		if d.Duration != "agent" && d.SessionID != sessionID {
			continue
		}
		if d.matches(host, path, method, scopes) {
			return d, true, nil
		}
	}
	return Delegation{}, false, nil
}

// ListDelegations returns all non-revoked delegations across all agents.
func (s *InMemoryDelegationStore) ListDelegations() ([]Delegation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var active []Delegation
	for id, d := range s.delegations {
		if _, isRevoked := s.revoked[id]; isRevoked {
			continue
		}
		active = append(active, d)
	}
	return active, nil
}

// AddDelegation stores a new delegation.
func (s *InMemoryDelegationStore) AddDelegation(d Delegation) error {
	if d.DelegationID == "" {
		return fmt.Errorf("AddDelegation: delegation must have a non-empty DelegationID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delegations[d.DelegationID] = d
	return nil
}

// RevokeDelegation marks an existing delegation as revoked.
func (s *InMemoryDelegationStore) RevokeDelegation(delegationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.delegations[delegationID]; !ok {
		return fmt.Errorf("RevokeDelegation: delegation %q not found", delegationID)
	}
	s.revoked[delegationID] = time.Now()
	return nil
}

// matchPattern reports whether value matches pattern.
//
// Host patterns (spec §6.3):
//
//	"api.example.com"  exact match only
//	"*.example.com"    matches any subdomain (api.example.com, cdn.example.com, …)
//
// Path patterns (spec §6.3):
//
//	"/users/123/messages"  exact match only
//	"/users/123/*"         matches /users/123/messages, /users/123/profile, …
//	"/users/*"             matches /users/123/messages, /users/456/posts, …
func matchPattern(pattern, value string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}

	// Host wildcard: "*.example.com"
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		// Value must end with ".example.com" and have at least one char before the dot.
		return strings.HasSuffix(value, suffix) && len(value) > len(suffix)
	}

	// Path wildcard: "/prefix/*" — the "*" must be the final segment.
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-2] // strip "/*"
		// Allow "/prefix/anything" (note: this covers multi-segment too, per spec examples)
		return strings.HasPrefix(value, prefix+"/")
	}

	// Any other wildcard placement is unsupported → no match.
	return false
}
