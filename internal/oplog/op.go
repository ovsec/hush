// Package oplog is hush's append-only log of signed operations. Every change
// to a vault is one Op; an Op's ID is the hash of its contents and it names
// its parents, so the log is a tamper-evident hash DAG.
package oplog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const domain = "hush/op/v1\n"

// Op is one signed change. Body is kind-specific JSON; secret contents in it
// are already encrypted.
type Op struct {
	V       int             `json:"v"`
	ID      string          `json:"id,omitempty"`
	Parents []string        `json:"parents"`
	Author  string          `json:"author"`
	Clock   uint64          `json:"clock"`
	Time    int64           `json:"time"`
	Kind    string          `json:"kind"`
	Body    json.RawMessage `json:"body"`
	Sig     string          `json:"sig,omitempty"`
}

// Signer signs bytes; *crypt.Identity satisfies it.
type Signer interface{ Sign([]byte) []byte }

// SigningBytes is what the ID hashes and the signature covers: everything
// except ID and Sig, behind a domain separator.
func (o *Op) SigningBytes() ([]byte, error) {
	c := *o
	c.ID, c.Sig = "", ""
	b, err := json.Marshal(&c)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), b...), nil
}

// Sign fills in ID and Sig.
func (o *Op) Sign(s Signer) error {
	b, err := o.SigningBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	o.ID = hex.EncodeToString(sum[:])
	o.Sig = base64.StdEncoding.EncodeToString(s.Sign(b))
	return nil
}

// Verify checks that ID matches the contents and Sig was made by Author.
func (o *Op) Verify() error {
	pub, err := hex.DecodeString(o.Author)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("op %s: bad author key", o.Short())
	}
	b, err := o.SigningBytes()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != o.ID {
		return fmt.Errorf("op %s: id does not match contents", o.Short())
	}
	sig, err := base64.StdEncoding.DecodeString(o.Sig)
	if err != nil || !ed25519.Verify(pub, b, sig) {
		return fmt.Errorf("op %s: bad signature", o.Short())
	}
	return nil
}

// Short is the first 8 hex chars of the ID.
func (o *Op) Short() string {
	if len(o.ID) < 8 {
		return o.ID
	}
	return o.ID[:8]
}
