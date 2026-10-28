package crypt

import (
	"bytes"
	"testing"
)

func TestSealOpen(t *testing.T) {
	key := Random(KeySize)
	nonce, ct, err := Seal(key, []byte("hunter2"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(key, nonce, ct, []byte("aad"))
	if err != nil || string(pt) != "hunter2" {
		t.Fatalf("got %q, %v", pt, err)
	}
	if _, err := Open(key, nonce, ct, []byte("other")); err != ErrDecrypt {
		t.Fatal("wrong aad must fail")
	}
	ct[0] ^= 1
	if _, err := Open(key, nonce, ct, []byte("aad")); err != ErrDecrypt {
		t.Fatal("tampered ciphertext must fail")
	}
	if _, err := Open(Random(KeySize), nonce, ct, []byte("aad")); err != ErrDecrypt {
		t.Fatal("wrong key must fail")
	}
}

func TestIdentityRoundTripAndWrap(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	back, err := IdentityFromSecret(id.Secret())
	if err != nil {
		t.Fatal(err)
	}
	if back.ID() != id.ID() || back.BoxID() != id.BoxID() {
		t.Fatal("identity did not round-trip")
	}

	vk := Random(KeySize)
	sealed, err := Wrap(vk, id.BoxPub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := back.Unwrap(sealed)
	if err != nil || !bytes.Equal(got, vk) {
		t.Fatal("unwrap failed")
	}
	other, _ := NewIdentity()
	if _, err := other.Unwrap(sealed); err == nil {
		t.Fatal("another identity must not unwrap")
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	p := KDFParams{Alg: "argon2id", Salt: Random(16), Time: 1, MemKiB: 1024, Threads: 1}
	a, _ := DeriveKey([]byte("pass"), p)
	b, _ := DeriveKey([]byte("pass"), p)
	c, _ := DeriveKey([]byte("Pass"), p)
	if !bytes.Equal(a, b) || bytes.Equal(a, c) {
		t.Fatal("kdf must be deterministic and passphrase-sensitive")
	}
}
