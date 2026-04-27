package delegation

import (
	"fmt"
	"slices"
	"sync"
	"time"
)

// PrincipalScopeStore persists did:key scopes that a principal has proven
// ownership of via a self-signed scope claim JWT.
type PrincipalScopeStore interface {
	GetPrincipalScopes(principalID string) ([]string, error)
	AddPrincipalScope(principalID, scope string) error
}

// InMemoryPrincipalScopeStore is a thread-safe in-memory PrincipalScopeStore.
type InMemoryPrincipalScopeStore struct {
	mu     sync.RWMutex
	scopes map[string][]string // principalID → []scope
}

// NewInMemoryPrincipalScopeStore creates a new empty in-memory scope store.
func NewInMemoryPrincipalScopeStore() *InMemoryPrincipalScopeStore {
	return &InMemoryPrincipalScopeStore{
		scopes: make(map[string][]string),
	}
}

// GetPrincipalScopes returns all scopes registered for a principal.
func (s *InMemoryPrincipalScopeStore) GetPrincipalScopes(principalID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	existing := s.scopes[principalID]
	out := make([]string, len(existing))
	copy(out, existing)
	return out, nil
}

// AddPrincipalScope adds a scope to a principal's scope set (idempotent).
func (s *InMemoryPrincipalScopeStore) AddPrincipalScope(principalID, scope string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Contains(s.scopes[principalID], scope) {
		return nil // already present, no-op
	}
	s.scopes[principalID] = append(s.scopes[principalID], scope)
	return nil
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
		if d.Breadth != "agent" && d.SessionID != sessionID {
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
