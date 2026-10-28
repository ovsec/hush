package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ovsec/hush/internal/crypt"
	"github.com/ovsec/hush/internal/oplog"
	"github.com/ovsec/hush/internal/vault"
)

// Status is where this machine stands with its vault.
type Status int

const (
	StatusNone    Status = iota // no identity yet
	StatusPending               // identity exists, waiting to be added
	StatusReady                 // a member: unlock to use
	StatusRemoved               // was a member, has been removed
)

// Status reports where this machine stands, without the passphrase.
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	disk, err := s.readIdentity()
	if err != nil {
		return StatusNone
	}
	st, err := s.load(false)
	if errors.Is(err, ErrNoVault) {
		return StatusPending
	}
	if err != nil {
		return StatusReady // let unlock surface the error
	}
	if st.IsMember(disk.Sign) {
		return StatusReady
	}
	if _, gone := st.Removed[disk.Sign]; gone {
		return StatusRemoved
	}
	return StatusPending
}

// Join creates an identity on this machine so an admin can add it to their
// vault. It does not create a vault.
func (s *Service) Join(me string, pass []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Exists() {
		return fmt.Errorf("an identity already exists in %s", s.dir)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	id, err := crypt.NewIdentity()
	if err != nil {
		return err
	}
	defer id.Wipe()
	s.feed.Emit("keygen", "ed25519 signing key + x25519 encryption key generated")
	s.feed.Emit("keygen", "your safety number is %s", id.Fingerprint())
	if err := s.writeIdentity(id, me, pass); err != nil {
		os.Remove(filepath.Join(s.dir, IdentityFile))
		return err
	}
	s.feed.Emit("ready", "identity ready · send your join code to the vault admin")
	return nil
}

const joinPrefix = "hush1:"

// JoinRequest is what a join code carries: a name and two public keys,
// signed with the matching private key.
type JoinRequest struct {
	Name string `json:"n"`
	Sign string `json:"s"`
	Box  string `json:"b"`
	Sig  []byte `json:"sig"`
	// Tok is an OIDC ID token whose nonce binds it to Sign and Box.
	Tok string `json:"tok,omitempty"`
}

// Safety is the safety number both sides compare.
func (r JoinRequest) Safety() string { return crypt.FingerprintHex(r.Sign, r.Box) }

func joinBytes(name, sign, box string) []byte {
	return []byte("hush/join/v1|" + name + "|" + sign + "|" + box)
}

// JoinCode is this identity's join code and safety number. Both are public.
func (s *Service) JoinCode() (code, safety string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	disk, err := s.readIdentity()
	if err != nil {
		return "", "", err
	}
	b, err := json.Marshal(JoinRequest{Name: disk.Name, Sign: disk.Sign, Box: disk.Box, Sig: disk.JoinSig, Tok: disk.IDToken})
	if err != nil {
		return "", "", err
	}
	return joinPrefix + base64.RawURLEncoding.EncodeToString(b), crypt.FingerprintHex(disk.Sign, disk.Box), nil
}

// ParseJoinCode decodes a join code and checks its self-signature.
func ParseJoinCode(code string) (JoinRequest, error) {
	code = strings.Join(strings.Fields(code), "")
	raw, ok := strings.CutPrefix(code, joinPrefix)
	if !ok {
		return JoinRequest{}, errors.New("not a hush join code (they start with " + joinPrefix + ")")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return JoinRequest{}, errors.New("join code is damaged; ask for it again")
	}
	var r JoinRequest
	if err := json.Unmarshal(b, &r); err != nil {
		return JoinRequest{}, errors.New("join code is damaged; ask for it again")
	}
	pub, err := hex.DecodeString(r.Sign)
	if err != nil || len(pub) != ed25519.PublicKeySize || crypt.FingerprintHex(r.Sign, r.Box) == "" {
		return JoinRequest{}, errors.New("join code has malformed keys")
	}
	if !ed25519.Verify(pub, joinBytes(r.Name, r.Sign, r.Box), r.Sig) {
		return JoinRequest{}, errors.New("join code signature does not verify")
	}
	return r, nil
}

// MemberInfo is a member as UIs show them.
type MemberInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Role    string `json:"role"`
	Safety  string `json:"safety"`
	You     bool   `json:"you"`
	Removed bool   `json:"removed"`
	// LastActive is the member's latest signed op.
	LastActive time.Time `json:"last_active"`
	// Presence is "direct", "relay" or "offline" while sync runs, else "".
	Presence string             `json:"presence"`
	LastSeen time.Time          `json:"last_seen"`
	SSO      *vault.SSOIdentity `json:"sso,omitempty"`
}

// Members lists current members (admin first) then removed ones. Works locked.
func (s *Service) Members() ([]MemberInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	disk, err := s.readIdentity()
	if err != nil {
		return nil, err
	}
	st := s.state
	if st == nil {
		if st, err = s.load(false); err != nil {
			return nil, err
		}
	}
	last := map[string]int64{}
	for _, op := range st.Ops() {
		last[op.Author] = max(last[op.Author], op.Time)
	}
	var live map[string]Presence
	if s.presence != nil {
		live = s.presence()
	}
	var out []MemberInfo
	add := func(m vault.Member, removed bool) {
		mi := MemberInfo{
			ID: m.ID, Name: m.Name, Role: m.Role, Safety: crypt.FingerprintHex(m.ID, m.Box),
			You: m.ID == disk.Sign, Removed: removed, SSO: m.SSO,
		}
		if p, ok := live[m.ID]; ok && !removed {
			mi.Presence, mi.LastSeen = p.State, p.LastSeen
		}
		if t, ok := last[m.ID]; ok {
			mi.LastActive = time.UnixMilli(t)
		}
		out = append(out, mi)
	}
	for _, m := range st.Members {
		add(m, false)
	}
	for _, m := range st.Removed {
		add(m, true)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Removed != b.Removed {
			return !a.Removed
		}
		if (a.Role == vault.RoleAdmin) != (b.Role == vault.RoleAdmin) {
			return a.Role == vault.RoleAdmin
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return out, nil
}

// AddMember admits the holder of a join code and seals every vault key to
// them. The caller must have compared safety numbers first. If the vault has
// a login policy, the code's company login is verified against it.
func (s *Service) AddMember(code string) (MemberInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	check, err := s.CheckJoin(ctx, code)
	if err != nil {
		return MemberInfo{}, err
	}
	r, _ := ParseJoinCode(code)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.me == nil {
		return MemberInfo{}, ErrLocked
	}
	if !s.state.IsAdmin(s.me.ID()) {
		return MemberInfo{}, ErrNotAdmin
	}
	if check.SSO != nil {
		for _, m := range s.state.Members {
			if m.SSO != nil && m.SSO.Issuer == check.SSO.Issuer && m.SSO.Subject == check.SSO.Subject {
				return MemberInfo{}, fmt.Errorf("%s is already a member as %s", check.SSO.Email, m.Name)
			}
		}
	}

	var box [32]byte
	b, _ := hex.DecodeString(r.Box)
	copy(box[:], b)
	wrapped := map[int][]byte{}
	for epoch, key := range s.keys {
		if wrapped[epoch], err = crypt.Wrap(key, box); err != nil {
			return MemberInfo{}, err
		}
	}
	s.feed.Emit("wrap", "%d vault key(s) sealed to %s's x25519 key", len(wrapped), r.Name)

	m := vault.Member{ID: r.Sign, Box: r.Box, Name: r.Name, Role: vault.RoleMember, SSO: check.SSO}
	if _, err := s.commit(vault.KindAdd, vault.AddMember{Member: m, Wrapped: wrapped}); err != nil {
		return MemberInfo{}, err
	}
	s.feed.Emit("member", "%s added · they receive the vault on the next sync or bundle", r.Name)
	return MemberInfo{ID: m.ID, Name: m.Name, Role: m.Role, Safety: r.Safety(), SSO: m.SSO}, nil
}

// RemoveMember revokes a member, seals a fresh vault key to everyone else and
// re-encrypts every secret with it. It returns how many secrets the removed
// member could have read; those values should be changed.
func (s *Service) RemoveMember(id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.me == nil {
		return 0, ErrLocked
	}
	if !s.state.IsAdmin(s.me.ID()) {
		return 0, ErrNotAdmin
	}
	gone, ok := s.state.Members[id]
	if !ok {
		return 0, errors.New("not a member")
	}
	if id == s.me.ID() {
		return 0, errors.New("you cannot remove yourself")
	}
	if _, err := s.commit(vault.KindRemove, vault.RemoveMember{ID: id}); err != nil {
		return 0, err
	}
	s.feed.Emit("member", "%s removed · their key is no longer accepted", gone.Name)

	epoch := s.state.Epoch + 1
	vk := crypt.Random(crypt.KeySize)
	s.feed.Emit("keygen", "vault key epoch %d · 256-bit random", epoch)
	wrapped := map[string][]byte{}
	for mid, m := range s.state.Members {
		var box [32]byte
		b, _ := hex.DecodeString(m.Box)
		copy(box[:], b)
		w, err := crypt.Wrap(vk, box)
		if err != nil {
			return 0, err
		}
		wrapped[mid] = w
	}
	s.feed.Emit("wrap", "epoch %d key sealed to %d remaining member(s), not to %s", epoch, len(wrapped), gone.Name)
	if _, err := s.commit(vault.KindKeyEpoch, vault.KeyEpoch{Epoch: epoch, Wrapped: wrapped}); err != nil {
		return 0, err
	}
	s.keys[epoch] = vk

	ids := make([]string, 0, len(s.state.Records))
	for eid, rec := range s.state.Records {
		if !rec.Deleted {
			ids = append(ids, eid)
		}
	}
	sort.Strings(ids)
	for _, eid := range ids {
		e, err := s.decrypt(s.state.Records[eid])
		if err != nil {
			return 0, err
		}
		put, err := s.seal(eid, e)
		if err != nil {
			return 0, err
		}
		put.Rekey = true
		if _, err := s.commit(vault.KindPut, put); err != nil {
			return 0, err
		}
	}
	s.feed.Emit("rekey", "%d secret(s) re-encrypted under epoch %d · %s may still hold old values", len(ids), epoch, gone.Name)
	s.reindex()
	return len(ids), nil
}

// Export writes the whole signed log to path, for teammates to import. It
// holds ciphertext and public metadata only.
func (s *Service) Export(path string) (int, error) {
	b, n, err := s.Bundle(path)
	if err != nil {
		return 0, err
	}
	return n, writeFileAtomic(path, b, 0o600)
}

// Bundle returns the whole signed log as bundle bytes; dest only labels the
// activity event.
func (s *Service) Bundle(dest string) ([]byte, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ops, err := s.ops().Load()
	if err != nil {
		return nil, 0, err
	}
	if len(ops) == 0 {
		return nil, 0, ErrNoVault
	}
	var b []byte
	for _, op := range ops {
		line, err := json.Marshal(op)
		if err != nil {
			return nil, 0, err
		}
		b = append(append(b, line...), '\n')
	}
	s.feed.Emit("export", "%d ops → %s · ciphertext and public metadata only", len(ops), dest)
	return b, len(ops), nil
}

// ImportResult says what a bundle contributed.
type ImportResult struct {
	Added    int      `json:"added"`
	Known    int      `json:"known"`
	Rejected []string `json:"rejected"`
}

// Import merges a bundle file. See MergeOps.
func (s *Service) Import(path string) (ImportResult, error) {
	incoming, err := oplog.File{Path: path}.Load()
	if err != nil {
		return ImportResult{}, err
	}
	if len(incoming) == 0 {
		return ImportResult{}, fmt.Errorf("%s holds no ops", path)
	}
	return s.MergeOps(incoming, filepath.Base(path))
}

// MergeOps verifies ops from elsewhere (a bundle or a peer), applies them in
// causal order and appends them to the local log. Works locked or unlocked.
func (s *Service) MergeOps(incoming []*oplog.Op, from string) (ImportResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res ImportResult
	disk, err := s.readIdentity()
	if err != nil {
		return res, err
	}
	st := s.state
	if st == nil {
		if st, err = s.load(false); errors.Is(err, ErrNoVault) {
			st, err = vault.New(), nil
		}
		if err != nil {
			return res, err
		}
	}
	if theirs := bundleVault(incoming); st.VaultID != "" && theirs != "" && theirs != st.VaultID {
		return res, errors.New("those ops belong to a different vault")
	}

	added, rejected := st.Merge(incoming)
	for _, op := range added {
		if _, err := s.ops().Append(op); err != nil {
			s.wipe()
			return res, fmt.Errorf("writing %s: %w", OpsFile, err)
		}
	}
	res.Added, res.Known = len(added), len(incoming)-len(added)-len(rejected)
	if res.Added > 0 || len(rejected) > 0 {
		s.feed.Emit("merge", "%d new op(s) from %s verified and merged · %d already known", res.Added, from, res.Known)
	}
	for _, err := range rejected {
		res.Rejected = append(res.Rejected, err.Error())
		s.feed.Emit("deny", "%v", err)
	}
	if st.Stale {
		if st, err = vault.Replay(st.Ops()); err != nil {
			s.wipe()
			return res, err
		}
		s.feed.Emit("verify", "a removal arrived late · state rebuilt · %d op(s) by removed members ignored", st.Ignored())
		if s.state != nil {
			s.state = st
		}
	}

	if s.me != nil && res.Added > 0 {
		if !st.IsMember(disk.Sign) {
			s.wipe()
			s.feed.Emit("lock", "you are no longer a member · keys wiped")
			return res, ErrRemoved
		}
		if err := s.unwrapKeys(); err != nil {
			return res, err
		}
		s.reindex()
	}
	return res, nil
}

func bundleVault(ops []*oplog.Op) string {
	for _, op := range ops {
		if op.Kind == vault.KindGenesis {
			var g vault.Genesis
			if json.Unmarshal(op.Body, &g) == nil {
				return g.VaultID
			}
		}
	}
	return ""
}
