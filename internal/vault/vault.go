// Package vault turns a log of ops into vault state and enforces the rules:
// who may change membership, which key epoch is current, and which write
// wins when two members edit the same secret.
package vault

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/ovsec/hush/internal/oplog"
)

// Op kinds.
const (
	KindGenesis  = "genesis"
	KindKeyEpoch = "key.epoch"
	KindPut      = "secret.put"
	KindDelete   = "secret.delete"
	KindAdd      = "member.add"
	KindRemove   = "member.remove"
	KindSSO      = "policy.sso"
)

// Roles.
const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

var errNotAdmin = errors.New("only an admin may do this")
var errNotMember = errors.New("author is not a member")

// Member is a person in the vault, named by their Ed25519 key.
type Member struct {
	ID   string `json:"id"`
	Box  string `json:"box"`
	Name string `json:"name"`
	Role string `json:"role"`
	// SSO is the company login the admin verified when adding them.
	SSO *SSOIdentity `json:"sso,omitempty"`
}

// SSOIdentity is a verified OIDC identity bound to a member's keys.
type SSOIdentity struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	Email   string `json:"email,omitempty"`
}

// SSOPolicy says which company login new members may prove.
type SSOPolicy struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Allow    []string `json:"allow,omitempty"`
	Require  bool     `json:"require"`
}

// Genesis founds a vault and names its first admin.
type Genesis struct {
	VaultID string `json:"vault_id"`
	Name    string `json:"name"`
	Admin   Member `json:"admin"`
}

// KeyEpoch introduces a new vault key, sealed to each member.
type KeyEpoch struct {
	Epoch   int               `json:"epoch"`
	Wrapped map[string][]byte `json:"wrapped"`
}

// AddMember admits someone and seals every existing epoch key to them.
type AddMember struct {
	Member  Member         `json:"member"`
	Wrapped map[int][]byte `json:"wrapped"`
}

// RemoveMember revokes a member's key. A new KeyEpoch should follow.
type RemoveMember struct {
	ID string `json:"id"`
}

// SecretPut stores a new version of a secret, encrypted with an epoch key.
type SecretPut struct {
	Entry string `json:"entry"`
	Epoch int    `json:"epoch"`
	Nonce []byte `json:"nonce"`
	CT    []byte `json:"ct"`
	// Rekey marks a re-encryption of an unchanged value under a new epoch.
	Rekey bool `json:"rekey,omitempty"`
}

// SecretDelete tombstones a secret.
type SecretDelete struct {
	Entry string `json:"entry"`
}

// Record is the current (winning) version of one secret.
type Record struct {
	Entry   string
	Epoch   int
	Nonce   []byte
	CT      []byte
	Deleted bool
	Version int
	Head    *oplog.Op
	// Exposed names removed members who could read the current value.
	Exposed []string
}

// State is everything derived from the log.
type State struct {
	VaultID string
	Name    string
	Members map[string]Member
	Removed map[string]Member
	Epochs  map[int]map[string][]byte
	Epoch   int
	Records map[string]*Record
	Clock   uint64

	// SSO is the vault's company-login policy, if the admin set one.
	SSO *SSOPolicy
	// Stale means a removal arrived after ops it revokes were applied; the
	// state must be rebuilt with Replay.
	Stale bool

	ops     map[string]*oplog.Op
	order   []*oplog.Op
	heads   map[string]struct{}
	ignored map[string]bool
	// revoked maps a removed member to the ops the admin had seen when
	// removing them. Their other ops are ignored.
	revoked map[string]map[string]bool
}

// New returns an empty state.
func New() *State {
	return &State{
		Members: map[string]Member{},
		Removed: map[string]Member{},
		Epochs:  map[int]map[string][]byte{},
		Records: map[string]*Record{},
		ops:     map[string]*oplog.Op{},
		heads:   map[string]struct{}{},
		ignored: map[string]bool{},
		revoked: map[string]map[string]bool{},
	}
}

// Replay builds state from a whole log. Ops a removed member signed that the
// admin had not seen when removing them are ignored, so every peer ends up
// with the same state whatever order ops arrived in.
func Replay(ops []*oplog.Op) (*State, error) {
	st := New()
	st.revoked = revocations(ops)
	for _, op := range ops {
		if err := st.Apply(op); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func revocations(ops []*oplog.Op) map[string]map[string]bool {
	byID := map[string]*oplog.Op{}
	admin := ""
	for _, op := range ops {
		byID[op.ID] = op
		if op.Kind == KindGenesis && admin == "" {
			var g Genesis
			if json.Unmarshal(op.Body, &g) == nil {
				admin = g.Admin.ID
			}
		}
	}
	out := map[string]map[string]bool{}
	for _, op := range ops {
		if op.Kind != KindRemove || op.Author != admin || op.Verify() != nil {
			continue
		}
		var r RemoveMember
		if json.Unmarshal(op.Body, &r) == nil {
			out[r.ID] = ancestors(byID, op)
		}
	}
	return out
}

// ancestors is every op reachable from op's parents.
func ancestors(byID map[string]*oplog.Op, op *oplog.Op) map[string]bool {
	seen := map[string]bool{}
	stack := append([]string(nil), op.Parents...)
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		if p, ok := byID[id]; ok {
			stack = append(stack, p.Parents...)
		}
	}
	return seen
}

// Ignored is how many ops were kept in the log but given no effect.
func (s *State) Ignored() int { return len(s.ignored) }

// OpsByID returns the ops with these IDs that the state holds.
func (s *State) OpsByID(ids []string) []*oplog.Op {
	var out []*oplog.Op
	for _, id := range ids {
		if op, ok := s.ops[id]; ok {
			out = append(out, op)
		}
	}
	return out
}

// IDs returns every op ID, in applied order.
func (s *State) IDs() []string {
	out := make([]string, len(s.order))
	for i, op := range s.order {
		out[i] = op.ID
	}
	return out
}

// Ops returns ops in the order they were applied.
func (s *State) Ops() []*oplog.Op { return s.order }

// Heads returns the IDs of ops nothing points to yet, sorted.
func (s *State) Heads() []string {
	out := make([]string, 0, len(s.heads))
	for id := range s.heads {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Apply verifies op and folds it into the state. Re-applying is a no-op.
func (s *State) Apply(op *oplog.Op) error {
	if _, ok := s.ops[op.ID]; ok {
		return nil
	}
	if err := op.Verify(); err != nil {
		return err
	}
	if op.V != 1 {
		return fmt.Errorf("op %s: unsupported version %d", op.Short(), op.V)
	}
	if len(s.ops) == 0 && op.Kind != KindGenesis {
		return errors.New("log must start with a genesis op")
	}
	for _, p := range op.Parents {
		if _, ok := s.ops[p]; !ok {
			return fmt.Errorf("op %s: unknown parent %.8s", op.Short(), p)
		}
	}
	if s.revokedOp(op) {
		s.ignored[op.ID] = true
	} else if err := s.apply(op); err != nil {
		return fmt.Errorf("op %s (%s): %w", op.Short(), op.Kind, err)
	}
	s.ops[op.ID] = op
	s.order = append(s.order, op)
	for _, p := range op.Parents {
		delete(s.heads, p)
	}
	s.heads[op.ID] = struct{}{}
	if op.Clock > s.Clock {
		s.Clock = op.Clock
	}
	return nil
}

// revokedOp reports whether op was signed by a removed member without the
// admin having seen it before the removal.
func (s *State) revokedOp(op *oplog.Op) bool {
	if _, gone := s.Removed[op.Author]; gone {
		return true // causally after or concurrent with the removal
	}
	allowed, ok := s.revoked[op.Author]
	return ok && !allowed[op.ID]
}

func (s *State) apply(op *oplog.Op) error {
	switch op.Kind {
	case KindGenesis:
		if len(s.ops) != 0 {
			return errors.New("vault already has a genesis")
		}
		if len(op.Parents) != 0 {
			return errors.New("genesis cannot have parents")
		}
		var g Genesis
		if err := json.Unmarshal(op.Body, &g); err != nil {
			return err
		}
		if g.VaultID == "" || g.Admin.ID != op.Author {
			return errors.New("genesis must name a vault and be signed by its admin")
		}
		g.Admin.Role = RoleAdmin
		s.VaultID, s.Name = g.VaultID, g.Name
		s.Members[g.Admin.ID] = g.Admin

	case KindKeyEpoch:
		if !s.IsAdmin(op.Author) {
			return errNotAdmin
		}
		var k KeyEpoch
		if err := json.Unmarshal(op.Body, &k); err != nil {
			return err
		}
		if k.Epoch != s.Epoch+1 {
			return fmt.Errorf("expected epoch %d, got %d", s.Epoch+1, k.Epoch)
		}
		for id := range k.Wrapped {
			if _, ok := s.Members[id]; !ok {
				return fmt.Errorf("key sealed to non-member %.8s", id)
			}
		}
		if len(k.Wrapped) != len(s.Members) {
			return errors.New("key must be sealed to every member")
		}
		s.Epochs[k.Epoch] = k.Wrapped
		s.Epoch = k.Epoch

	case KindPut:
		if !s.IsMember(op.Author) {
			return errNotMember
		}
		var p SecretPut
		if err := json.Unmarshal(op.Body, &p); err != nil {
			return err
		}
		if p.Entry == "" {
			return errors.New("missing entry id")
		}
		if _, ok := s.Epochs[p.Epoch]; !ok {
			return fmt.Errorf("unknown key epoch %d", p.Epoch)
		}
		rec := s.record(p.Entry)
		if !p.Rekey {
			rec.Version++
		}
		if wins(op, rec.Head) {
			rec.Epoch, rec.Nonce, rec.CT, rec.Deleted, rec.Head = p.Epoch, p.Nonce, p.CT, false, op
			if !p.Rekey {
				rec.Exposed = nil
			}
		}

	case KindDelete:
		if !s.IsMember(op.Author) {
			return errNotMember
		}
		var d SecretDelete
		if err := json.Unmarshal(op.Body, &d); err != nil {
			return err
		}
		rec := s.record(d.Entry)
		if wins(op, rec.Head) {
			rec.Deleted, rec.Head = true, op
		}

	case KindAdd:
		if !s.IsAdmin(op.Author) {
			return errNotAdmin
		}
		var a AddMember
		if err := json.Unmarshal(op.Body, &a); err != nil {
			return err
		}
		m := a.Member
		if !isKey(m.ID) || !isKey(m.Box) {
			return errors.New("member keys are malformed")
		}
		if s.IsMember(m.ID) {
			return fmt.Errorf("%s is already a member", m.Name)
		}
		if _, gone := s.Removed[m.ID]; gone {
			return errors.New("a removed key cannot rejoin; they need a new identity")
		}
		if len(a.Wrapped) != len(s.Epochs) {
			return errors.New("every epoch key must be sealed to the new member")
		}
		for e := range a.Wrapped {
			if _, ok := s.Epochs[e]; !ok {
				return fmt.Errorf("unknown key epoch %d", e)
			}
		}
		m.Role = RoleMember
		s.Members[m.ID] = m
		for e, w := range a.Wrapped {
			s.Epochs[e][m.ID] = w
		}

	case KindRemove:
		if !s.IsAdmin(op.Author) {
			return errNotAdmin
		}
		var r RemoveMember
		if err := json.Unmarshal(op.Body, &r); err != nil {
			return err
		}
		m, ok := s.Members[r.ID]
		if !ok {
			return errors.New("not a member")
		}
		if m.Role == RoleAdmin {
			return errors.New("the admin cannot be removed")
		}
		delete(s.Members, r.ID)
		s.Removed[r.ID] = m
		seen := ancestors(s.ops, op)
		s.revoked[r.ID] = seen
		for _, o := range s.order {
			if o.Author == r.ID && !seen[o.ID] && !s.ignored[o.ID] {
				s.Stale = true // applied a write the admin never saw
			}
		}
		for _, rec := range s.Records {
			if !rec.Deleted {
				rec.Exposed = append(rec.Exposed, m.Name)
			}
		}

	case KindSSO:
		if !s.IsAdmin(op.Author) {
			return errNotAdmin
		}
		var p SSOPolicy
		if err := json.Unmarshal(op.Body, &p); err != nil {
			return err
		}
		if p.Issuer == "" {
			s.SSO = nil
		} else {
			s.SSO = &p
		}

	default:
		return fmt.Errorf("unknown op kind %q", op.Kind)
	}
	return nil
}

// Has reports whether the op is already applied.
func (s *State) Has(id string) bool { _, ok := s.ops[id]; return ok }

// Merge applies ops from elsewhere in causal order, whatever order they come
// in. Ops that fail verification, and anything built on them, are rejected.
func (s *State) Merge(ops []*oplog.Op) (added []*oplog.Op, rejected []error) {
	var pending []*oplog.Op
	for _, op := range ops {
		if !s.Has(op.ID) {
			pending = append(pending, op)
		}
	}
	for progress := true; progress && len(pending) > 0; {
		progress = false
		var next []*oplog.Op
		for _, op := range pending {
			if s.Has(op.ID) {
				continue
			}
			if !s.parentsKnown(op) {
				next = append(next, op)
				continue
			}
			if err := s.Apply(op); err != nil {
				rejected = append(rejected, err)
			} else {
				added = append(added, op)
			}
			progress = true
		}
		pending = next
	}
	for _, op := range pending {
		rejected = append(rejected, fmt.Errorf("op %s: depends on ops that are missing or were rejected", op.Short()))
	}
	return added, rejected
}

func (s *State) parentsKnown(op *oplog.Op) bool {
	for _, p := range op.Parents {
		if !s.Has(p) {
			return false
		}
	}
	return true
}

func isKey(h string) bool {
	b, err := hex.DecodeString(h)
	return err == nil && len(b) == 32
}

func (s *State) record(entry string) *Record {
	rec, ok := s.Records[entry]
	if !ok {
		rec = &Record{Entry: entry}
		s.Records[entry] = rec
	}
	return rec
}

// IsMember reports whether id is a current member.
func (s *State) IsMember(id string) bool { _, ok := s.Members[id]; return ok }

// IsAdmin reports whether id is a current admin.
func (s *State) IsAdmin(id string) bool { return s.Members[id].Role == RoleAdmin }

// wins is last-writer-wins on (Lamport clock, op ID), so every peer picks the
// same winner regardless of the order ops arrive in.
func wins(op, cur *oplog.Op) bool {
	if cur == nil {
		return true
	}
	if op.Clock != cur.Clock {
		return op.Clock > cur.Clock
	}
	return op.ID > cur.ID
}

// SecretAAD binds a secret's ciphertext to its vault, entry and epoch, so it
// cannot be moved to another entry without failing to decrypt.
func SecretAAD(vaultID, entry string, epoch int) []byte {
	return fmt.Appendf(nil, "hush/secret/v1|%s|%s|%d", vaultID, entry, epoch)
}
