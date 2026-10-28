// Package app is the service layer every hush interface talks to. It owns
// the unlocked keys, turns user actions into signed ops, and narrates each
// step on its Feed so nothing happens out of sight.
package app

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ovsec/hush/internal/crypt"
	"github.com/ovsec/hush/internal/oplog"
	"github.com/ovsec/hush/internal/vault"
)

// Files in a vault directory.
const (
	IdentityFile = "identity.json"
	OpsFile      = "ops.jsonl"
)

var (
	ErrLocked        = errors.New("vault is locked")
	ErrNoVault       = errors.New("no vault here yet; run hush to create one")
	ErrBadPassphrase = errors.New("wrong passphrase")
	ErrNotFound      = errors.New("no such secret")
	ErrNotMember     = errors.New("you are not a member of this vault yet")
	ErrRemoved       = errors.New("you were removed from this vault")
	ErrNotAdmin      = errors.New("only the vault admin can do that")
)

// Entry is a secret's plaintext. It only exists in memory.
type Entry struct {
	Title    string `json:"title"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	URL      string `json:"url,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// Item is what lists show: no password, no notes.
type Item struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Username string    `json:"username"`
	URL      string    `json:"url"`
	Updated  time.Time `json:"updated"`
	Author   string    `json:"author"`
	Version  int       `json:"version"`
	Epoch    int       `json:"epoch"`
	Size     int       `json:"size"`
	Op       string    `json:"op"`
	Exposed  []string  `json:"exposed"`
}

// Info describes the vault and who is using it.
type Info struct {
	Dir         string `json:"dir"`
	Vault       string `json:"vault"`
	Me          string `json:"me"`
	Fingerprint string `json:"safety"`
	Ops         int    `json:"ops"`
	Epoch       int    `json:"epoch"`
	Members     int    `json:"members"`
	Secrets     int    `json:"secrets"`
	Unlocked    bool   `json:"unlocked"`
	Admin       string `json:"admin"`
	AdminSafety string `json:"admin_safety"`
	IsAdmin     bool   `json:"is_admin"`
}

type identityDisk struct {
	V      int             `json:"v"`
	Name   string          `json:"name"`
	Sign   string          `json:"sign_pub"`
	Box    string          `json:"box_pub"`
	KDF    crypt.KDFParams `json:"kdf"`
	Nonce  []byte          `json:"nonce"`
	Sealed []byte          `json:"sealed"`
	// JoinSig signs the join code, made while the private key was at hand.
	JoinSig []byte `json:"join_sig"`
	// IDToken is a company login bound to these keys, if the member made one.
	IDToken string `json:"id_token,omitempty"`
}

// Service is one vault directory.
type Service struct {
	dir  string
	feed *Feed

	mu       sync.Mutex
	onChange func()
	presence func() map[string]Presence
	state    *vault.State
	me       *crypt.Identity
	keys     map[int][]byte
	index    map[string]Item
}

// New opens (but does not unlock) the vault in dir.
func New(dir string) *Service { return &Service{dir: dir, feed: newFeed()} }

// Feed is where the service narrates what it does.
func (s *Service) Feed() *Feed { return s.feed }

// Dir is the vault directory.
func (s *Service) Dir() string { return s.dir }

// Exists reports whether a vault has been created in Dir.
func (s *Service) Exists() bool {
	_, err := os.Stat(filepath.Join(s.dir, IdentityFile))
	return err == nil
}

// Unlocked reports whether keys are in memory.
func (s *Service) Unlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.me != nil
}

// Create makes a new vault with the caller as its admin, and leaves it unlocked.
func (s *Service) Create(vaultName, me string, pass []byte) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Exists() {
		return fmt.Errorf("a vault already exists in %s", s.dir)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			s.wipe()
			os.Remove(filepath.Join(s.dir, IdentityFile))
			os.Remove(filepath.Join(s.dir, OpsFile))
		}
	}()

	id, err := crypt.NewIdentity()
	if err != nil {
		return err
	}
	s.feed.Emit("keygen", "ed25519 signing key + x25519 encryption key generated")
	s.feed.Emit("keygen", "your safety number is %s", id.Fingerprint())
	if err := s.writeIdentity(id, me, pass); err != nil {
		return err
	}

	s.state, s.me, s.keys, s.index = vault.New(), id, map[int][]byte{}, map[string]Item{}
	gen := vault.Genesis{
		VaultID: hex.EncodeToString(crypt.Random(16)),
		Name:    vaultName,
		Admin:   vault.Member{ID: id.ID(), Box: id.BoxID(), Name: me, Role: vault.RoleAdmin},
	}
	if _, err := s.commit(vault.KindGenesis, gen); err != nil {
		return err
	}

	vk := crypt.Random(crypt.KeySize)
	s.feed.Emit("keygen", "vault key epoch 1 · 256-bit random")
	wrapped, err := crypt.Wrap(vk, id.BoxPub)
	if err != nil {
		return err
	}
	s.feed.Emit("wrap", "vault key sealed to your x25519 key · %d B", len(wrapped))
	ke := vault.KeyEpoch{Epoch: 1, Wrapped: map[string][]byte{id.ID(): wrapped}}
	if _, err := s.commit(vault.KindKeyEpoch, ke); err != nil {
		return err
	}
	s.keys[1] = vk
	s.feed.Emit("ready", "vault %q created and unlocked", vaultName)
	s.changed()
	return nil
}

// Unlock derives the passphrase key, opens the identity, verifies the whole
// log and unwraps the vault keys.
func (s *Service) Unlock(pass []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.me != nil {
		return nil
	}
	disk, err := s.readIdentity()
	if err != nil {
		return err
	}

	t := time.Now()
	k, err := crypt.DeriveKey(pass, disk.KDF)
	if err != nil {
		return err
	}
	defer crypt.Wipe(k)
	s.feed.Emit("kdf", "%s → 256-bit key · %s", disk.KDF, ms(time.Since(t)))

	secret, err := crypt.Open(k, disk.Nonce, disk.Sealed, identityAAD(disk.Sign))
	if err != nil {
		s.feed.Emit("deny", "identity.json did not decrypt · authentication tag mismatch")
		return ErrBadPassphrase
	}
	defer crypt.Wipe(secret)
	id, err := crypt.IdentityFromSecret(secret)
	if err != nil {
		return err
	}
	if id.ID() != disk.Sign {
		id.Wipe()
		return errors.New("identity.json is inconsistent")
	}
	s.feed.Emit("open", "private keys decrypted · xchacha20-poly1305 · safety number %s", id.Fingerprint())

	st, err := s.load(true)
	if err != nil {
		id.Wipe()
		return err
	}
	if !st.IsMember(id.ID()) {
		id.Wipe()
		if _, gone := st.Removed[id.ID()]; gone {
			return ErrRemoved
		}
		return ErrNotMember
	}
	s.state, s.me, s.keys = st, id, map[int][]byte{}
	if err := s.unwrapKeys(); err != nil {
		s.wipe()
		return err
	}
	s.reindex()
	s.changed()
	return nil
}

// Lock forgets every key.
func (s *Service) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.me == nil {
		return
	}
	s.wipe()
	s.feed.Emit("lock", "keys wiped from memory · vault locked")
}

func (s *Service) wipe() {
	if s.me != nil {
		s.changed()
		s.me.Wipe()
	}
	for _, k := range s.keys {
		crypt.Wipe(k)
	}
	s.me, s.keys, s.index, s.state = nil, nil, nil, nil
}

// OnChange calls fn, on its own goroutine, whenever the vault is unlocked or
// locked. fn should check Unlocked to see which.
func (s *Service) OnChange(fn func()) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

// changed must be called with s.mu held.
func (s *Service) changed() {
	if fn := s.onChange; fn != nil {
		go fn()
	}
}

// Info describes the vault. It works while locked, reading only what is
// stored in the clear.
func (s *Service) Info() (Info, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info := Info{Dir: s.dir}
	disk, err := s.readIdentity()
	if err != nil {
		return info, err
	}
	info.Me, info.Fingerprint = disk.Name, crypt.FingerprintHex(disk.Sign, disk.Box)
	st := s.state
	if st == nil {
		if st, err = s.load(false); err != nil {
			return info, err
		}
	}
	info.Vault, info.Ops, info.Epoch, info.Members = st.Name, len(st.Ops()), st.Epoch, len(st.Members)
	for _, r := range st.Records {
		if !r.Deleted {
			info.Secrets++
		}
	}
	info.Unlocked = s.me != nil
	for _, m := range st.Members {
		if m.Role == vault.RoleAdmin {
			info.Admin, info.AdminSafety = m.Name, crypt.FingerprintHex(m.ID, m.Box)
			info.IsAdmin = info.IsAdmin || m.ID == disk.Sign
		}
	}
	return info, nil
}

// PublicState verifies and returns the log without any keys: exactly what
// someone who copied ops.jsonl could learn.
func (s *Service) PublicState() (*vault.State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load(false)
}

// Items lists secrets, sorted by title.
func (s *Service) Items() []Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Item, 0, len(s.index))
	for _, it := range s.index {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Title), strings.ToLower(out[j].Title)
		if a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Reveal decrypts one secret in full.
func (s *Service) Reveal(id string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.me == nil {
		return Entry{}, ErrLocked
	}
	rec, ok := s.state.Records[id]
	if !ok || rec.Deleted {
		return Entry{}, ErrNotFound
	}
	e, err := s.decrypt(rec)
	if err != nil {
		return Entry{}, err
	}
	s.feed.Emit("decrypt", "%q · %d B ciphertext → plaintext, in memory only", e.Title, len(rec.CT))
	return e, nil
}

// Save encrypts e and records it. An empty id creates a new secret.
func (s *Service) Save(id string, e Entry) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.me == nil {
		return "", ErrLocked
	}
	e.Title = strings.TrimSpace(e.Title)
	if e.Title == "" {
		return "", errors.New("a secret needs a title")
	}
	if id == "" {
		id = hex.EncodeToString(crypt.Random(16))
	} else if rec, ok := s.state.Records[id]; !ok || rec.Deleted {
		return "", ErrNotFound
	}

	put, err := s.seal(id, e)
	if err != nil {
		return "", err
	}
	s.feed.Emit("seal", "%q · xchacha20-poly1305 · epoch %d key · nonce %s · %d B", e.Title, put.Epoch, crypt.Short(put.Nonce), len(put.CT))
	if _, err := s.commit(vault.KindPut, put); err != nil {
		return "", err
	}
	s.index[id] = s.item(s.state.Records[id], e)
	return id, nil
}

// Delete tombstones a secret.
func (s *Service) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.me == nil {
		return ErrLocked
	}
	it, ok := s.index[id]
	if !ok {
		return ErrNotFound
	}
	if _, err := s.commit(vault.KindDelete, vault.SecretDelete{Entry: id}); err != nil {
		return err
	}
	delete(s.index, id)
	s.feed.Emit("delete", "%q tombstoned · older encrypted versions remain in the log", it.Title)
	return nil
}

// Raw returns the exact op stored on disk for a secret, pretty-printed.
func (s *Service) Raw(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.me == nil {
		return "", ErrLocked
	}
	rec, ok := s.state.Records[id]
	if !ok {
		return "", ErrNotFound
	}
	b, err := json.MarshalIndent(rec.Head, "", "  ")
	return string(b), err
}

// Passwords are drawn uniformly from this set.
const passwordChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!@#%+="

// GeneratePassword returns n random characters from crypto/rand.
func (s *Service) GeneratePassword(n int) string {
	var b strings.Builder
	max := big.NewInt(int64(len(passwordChars)))
	for range n {
		i, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b.WriteByte(passwordChars[i.Int64()])
	}
	bits := float64(n) * math.Log2(float64(len(passwordChars)))
	s.feed.Emit("gen", "%d-char password from crypto/rand · ~%.0f bits of entropy", n, bits)
	return b.String()
}

// commit signs an op over the current heads, applies it and appends it.
func (s *Service) commit(kind string, body any) (*oplog.Op, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	op := &oplog.Op{
		V:       1,
		Parents: s.state.Heads(),
		Author:  s.me.ID(),
		Clock:   s.state.Clock + 1,
		Time:    time.Now().UnixMilli(),
		Kind:    kind,
		Body:    b,
	}
	if err := op.Sign(s.me); err != nil {
		return nil, err
	}
	if err := s.state.Apply(op); err != nil {
		return nil, err
	}
	s.feed.Emit("sign", "op %s · %s · ed25519 · clock %d", op.Short(), kind, op.Clock)
	n, err := s.ops().Append(op)
	if err != nil {
		// Memory is now ahead of disk; force a fresh unlock from disk.
		s.wipe()
		return nil, fmt.Errorf("writing %s: %w", OpsFile, err)
	}
	s.feed.Emit("write", "%s +1 op · %d B · fsync", OpsFile, n)
	return op, nil
}

func (s *Service) load(narrate bool) (*vault.State, error) {
	ops, err := s.ops().Load()
	if err != nil {
		return nil, err
	}
	if len(ops) == 0 {
		return nil, ErrNoVault
	}
	t := time.Now()
	st, err := vault.Replay(ops)
	if err != nil {
		if narrate {
			s.feed.Emit("deny", "log verification failed: %v", err)
		}
		return nil, fmt.Errorf("log verification failed: %w", err)
	}
	if narrate {
		s.feed.Emit("verify", "%d ops · ed25519 signatures + hash links ok · %s", len(ops), ms(time.Since(t)))
		if n := st.Ignored(); n > 0 {
			s.feed.Emit("verify", "%d op(s) by removed members ignored: signed after the admin removed them", n)
		}
	}
	return st, nil
}

// unwrapKeys opens every epoch key sealed to us that is not open yet.
func (s *Service) unwrapKeys() error {
	epochs := make([]int, 0, len(s.state.Epochs))
	for e := range s.state.Epochs {
		epochs = append(epochs, e)
	}
	sort.Ints(epochs)
	for _, epoch := range epochs {
		w, ok := s.state.Epochs[epoch][s.me.ID()]
		if _, have := s.keys[epoch]; !ok || have {
			continue
		}
		vk, err := s.me.Unwrap(w)
		if err != nil {
			return fmt.Errorf("vault key epoch %d: %w", epoch, err)
		}
		s.keys[epoch] = vk
		s.feed.Emit("unwrap", "vault key epoch %d opened · x25519 sealed box", epoch)
	}
	return nil
}

func (s *Service) reindex() {
	s.index = map[string]Item{}
	n, size := 0, 0
	for id, rec := range s.state.Records {
		if rec.Deleted {
			continue
		}
		e, err := s.decrypt(rec)
		if err != nil {
			s.feed.Emit("deny", "entry %.8s: %v", id, err)
			continue
		}
		s.index[id] = s.item(rec, e)
		n++
		size += len(rec.CT)
	}
	s.feed.Emit("index", "%d secrets decrypted to build the list (%d B) · passwords dropped until revealed", n, size)
}

// seal encrypts an entry with the current epoch key.
func (s *Service) seal(id string, e Entry) (vault.SecretPut, error) {
	pt, err := json.Marshal(e)
	if err != nil {
		return vault.SecretPut{}, err
	}
	defer crypt.Wipe(pt)
	epoch := s.state.Epoch
	nonce, ct, err := crypt.Seal(s.keys[epoch], pt, vault.SecretAAD(s.state.VaultID, id, epoch))
	if err != nil {
		return vault.SecretPut{}, err
	}
	return vault.SecretPut{Entry: id, Epoch: epoch, Nonce: nonce, CT: ct}, nil
}

func (s *Service) decrypt(rec *vault.Record) (Entry, error) {
	key, ok := s.keys[rec.Epoch]
	if !ok {
		return Entry{}, fmt.Errorf("no key for epoch %d", rec.Epoch)
	}
	pt, err := crypt.Open(key, rec.Nonce, rec.CT, vault.SecretAAD(s.state.VaultID, rec.Entry, rec.Epoch))
	if err != nil {
		return Entry{}, err
	}
	defer crypt.Wipe(pt)
	var e Entry
	if err := json.Unmarshal(pt, &e); err != nil {
		return Entry{}, err
	}
	return e, nil
}

func (s *Service) item(rec *vault.Record, e Entry) Item {
	author := s.state.Members[rec.Head.Author].Name
	if rec.Head.Author == s.me.ID() {
		author = "you"
	}
	return Item{
		ID: rec.Entry, Title: e.Title, Username: e.Username, URL: e.URL,
		Updated: time.UnixMilli(rec.Head.Time), Author: author,
		Version: rec.Version, Epoch: rec.Epoch, Size: len(rec.CT), Op: rec.Head.Short(),
		Exposed: rec.Exposed,
	}
}

func (s *Service) writeIdentity(id *crypt.Identity, name string, pass []byte) error {
	kdf := crypt.NewKDF()
	t := time.Now()
	k, err := crypt.DeriveKey(pass, kdf)
	if err != nil {
		return err
	}
	defer crypt.Wipe(k)
	s.feed.Emit("kdf", "%s → 256-bit key · %s", kdf, ms(time.Since(t)))

	secret := id.Secret()
	defer crypt.Wipe(secret)
	nonce, ct, err := crypt.Seal(k, secret, identityAAD(id.ID()))
	if err != nil {
		return err
	}
	s.feed.Emit("seal", "private keys encrypted · xchacha20-poly1305 · nonce %s", crypt.Short(nonce))

	b, err := json.MarshalIndent(identityDisk{
		V: 1, Name: name, Sign: id.ID(), Box: id.BoxID(), KDF: kdf, Nonce: nonce, Sealed: ct,
		JoinSig: id.Sign(joinBytes(name, id.ID(), id.BoxID())),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(s.dir, IdentityFile), b, 0o600); err != nil {
		return err
	}
	s.feed.Emit("write", "%s · %d B · mode 0600", IdentityFile, len(b))
	return nil
}

func (s *Service) readIdentity() (*identityDisk, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, IdentityFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoVault
	}
	if err != nil {
		return nil, err
	}
	var d identityDisk
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", IdentityFile, err)
	}
	return &d, nil
}

func (s *Service) ops() oplog.File { return oplog.File{Path: filepath.Join(s.dir, OpsFile)} }

func identityAAD(signPub string) []byte { return []byte("hush/identity/v1|" + signPub) }

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func ms(d time.Duration) string {
	if d < time.Millisecond {
		return "<1ms"
	}
	return d.Round(time.Millisecond).String()
}
