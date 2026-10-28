// Package crypt holds hush's cryptographic primitives. Nothing here is novel:
// argon2id stretches passphrases, XChaCha20-Poly1305 encrypts data, Ed25519
// signs operations and X25519 sealed boxes share the vault key with members.
package crypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// KeySize is the size of every symmetric key hush uses.
const KeySize = 32

// ErrDecrypt hides whether a key was wrong or data was tampered with.
var ErrDecrypt = errors.New("decryption failed: wrong key or tampered data")

// KDFParams describes how a passphrase was stretched. Stored next to the
// ciphertext so parameters can be raised later without breaking old files.
type KDFParams struct {
	Alg     string `json:"alg"`
	Salt    []byte `json:"salt"`
	Time    uint32 `json:"t"`
	MemKiB  uint32 `json:"m_kib"`
	Threads uint8  `json:"p"`
}

// DefaultKDF follows the RFC 9106 second recommended option.
var DefaultKDF = KDFParams{Alg: "argon2id", Time: 3, MemKiB: 64 * 1024, Threads: 4}

// NewKDF returns DefaultKDF with a fresh random salt.
func NewKDF() KDFParams {
	p := DefaultKDF
	p.Salt = Random(16)
	return p
}

func (p KDFParams) String() string {
	return fmt.Sprintf("%s · %d MiB · t=%d · p=%d", p.Alg, p.MemKiB/1024, p.Time, p.Threads)
}

// DeriveKey stretches a passphrase into a KeySize key.
func DeriveKey(pass []byte, p KDFParams) ([]byte, error) {
	if p.Alg != "argon2id" {
		return nil, fmt.Errorf("unsupported kdf %q", p.Alg)
	}
	if len(p.Salt) < 16 {
		return nil, errors.New("kdf salt too short")
	}
	return argon2.IDKey(pass, p.Salt, p.Time, p.MemKiB, p.Threads, KeySize), nil
}

// Random returns n bytes from the OS CSPRNG.
func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypt: no randomness: " + err.Error())
	}
	return b
}

// Seal encrypts plaintext with a random 192-bit nonce. aad is authenticated
// but not encrypted; it binds the ciphertext to where it belongs.
func Seal(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = Random(chacha20poly1305.NonceSizeX)
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open reverses Seal.
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ErrDecrypt
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Wipe zeroes b. Best effort: the Go runtime may have copied it elsewhere.
func Wipe(b []byte) { clear(b) }

// Identity is a member's key pair: Ed25519 to sign, X25519 to receive keys.
type Identity struct {
	SignPub  ed25519.PublicKey
	BoxPub   [32]byte
	signPriv ed25519.PrivateKey
	boxPriv  [32]byte
}

// NewIdentity generates fresh keys.
func NewIdentity() (*Identity, error) {
	spub, spriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	bpub, bpriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{SignPub: spub, BoxPub: *bpub, signPriv: spriv, boxPriv: *bpriv}, nil
}

// Secret returns the 64 private bytes (ed25519 seed ‖ x25519 key).
// The caller must Wipe it.
func (id *Identity) Secret() []byte {
	out := make([]byte, 0, 64)
	out = append(out, id.signPriv.Seed()...)
	return append(out, id.boxPriv[:]...)
}

// IdentityFromSecret rebuilds an Identity from Secret's output.
func IdentityFromSecret(secret []byte) (*Identity, error) {
	if len(secret) != 64 {
		return nil, errors.New("identity: bad secret length")
	}
	spriv := ed25519.NewKeyFromSeed(secret[:32])
	id := &Identity{SignPub: spriv.Public().(ed25519.PublicKey), signPriv: spriv}
	copy(id.boxPriv[:], secret[32:])
	pub, err := curve25519.X25519(id.boxPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(id.BoxPub[:], pub)
	return id, nil
}

// ID is the hex Ed25519 public key; it names the member everywhere.
func (id *Identity) ID() string { return hex.EncodeToString(id.SignPub) }

// BoxID is the hex X25519 public key.
func (id *Identity) BoxID() string { return hex.EncodeToString(id.BoxPub[:]) }

// Sign signs msg with the member's Ed25519 key.
func (id *Identity) Sign(msg []byte) []byte { return ed25519.Sign(id.signPriv, msg) }

// SignKey exposes the Ed25519 private key so the network layer can use it as
// its peer identity. Do not store or log it.
func (id *Identity) SignKey() ed25519.PrivateKey { return id.signPriv }

// Unwrap opens a key sealed to this identity with Wrap.
func (id *Identity) Unwrap(sealed []byte) ([]byte, error) {
	out, ok := box.OpenAnonymous(nil, sealed, &id.BoxPub, &id.boxPriv)
	if !ok {
		return nil, ErrDecrypt
	}
	return out, nil
}

// Wipe zeroes the private keys.
func (id *Identity) Wipe() {
	clear(id.signPriv)
	clear(id.boxPriv[:])
}

// Wrap seals key so only the holder of recipient's private key can open it.
func Wrap(key []byte, recipient [32]byte) ([]byte, error) {
	return box.SealAnonymous(nil, key, &recipient, rand.Reader)
}

// Fingerprint is a member's safety number: 20 digits over both public keys,
// easy to read aloud. Covering both keys stops anyone pairing a victim's
// signing key with their own encryption key.
func Fingerprint(signPub, boxPub []byte) string {
	h := sha256.New()
	h.Write([]byte("hush/safety/v1"))
	h.Write(signPub)
	h.Write(boxPub)
	sum := h.Sum(nil)
	parts := make([]string, 4)
	for i := range parts {
		parts[i] = fmt.Sprintf("%05d", binary.BigEndian.Uint64(sum[i*8:])%100000)
	}
	return strings.Join(parts, " ")
}

// FingerprintHex is Fingerprint for hex-encoded keys; "" if malformed.
func FingerprintHex(signPub, boxPub string) string {
	a, err1 := hex.DecodeString(signPub)
	b, err2 := hex.DecodeString(boxPub)
	if err1 != nil || err2 != nil {
		return ""
	}
	return Fingerprint(a, b)
}

// Fingerprint is the identity's safety number.
func (id *Identity) Fingerprint() string { return Fingerprint(id.SignPub, id.BoxPub[:]) }

// Short renders the first bytes of b for display.
func Short(b []byte) string {
	if len(b) > 4 {
		b = b[:4]
	}
	return hex.EncodeToString(b) + "…"
}
