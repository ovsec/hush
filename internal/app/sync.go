package app

import (
	"crypto/ed25519"
	"time"

	"github.com/ovsec/hush/internal/oplog"
)

// Presence is what the sync layer knows about a member right now.
type Presence struct {
	State    string    // "direct", "relay" or "offline"
	LastSeen time.Time // when anyone last saw them online
}

// SetPresence installs the sync layer's view of who is online; nil clears it.
// fn must not call back into the Service.
func (s *Service) SetPresence(fn func() map[string]Presence) {
	s.mu.Lock()
	s.presence = fn
	s.mu.Unlock()
}

// SyncState is what a peer needs to start a sync: the vault ID, our member
// ID, and the IDs of every op we hold.
func (s *Service) SyncState() (vaultID, me string, ids []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.me == nil {
		return "", "", nil, ErrLocked
	}
	return s.state.VaultID, s.me.ID(), s.state.IDs(), nil
}

// OpsByID returns the ops we hold with these IDs.
func (s *Service) OpsByID(ids []string) []*oplog.Op {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil
	}
	return s.state.OpsByID(ids)
}

// Member reports a current member's name by ID.
func (s *Service) Member(id string) (name string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return "", false
	}
	m, ok := s.state.Members[id]
	return m.Name, ok
}

// MemberIDs lists current members.
func (s *Service) MemberIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil
	}
	out := make([]string, 0, len(s.state.Members))
	for id := range s.state.Members {
		out = append(out, id)
	}
	return out
}

// NetKey is our Ed25519 key for the network layer, while unlocked.
func (s *Service) NetKey() (ed25519.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.me == nil {
		return nil, ErrLocked
	}
	return s.me.SignKey(), nil
}
