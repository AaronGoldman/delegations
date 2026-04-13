package delegation

import (
	"fmt"
	"sync"
	"time"
)

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
