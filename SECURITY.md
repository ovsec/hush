# Security

hush holds secrets, so security reports get priority.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub security advisories](https://github.com/ovsec/hush/security/advisories/new).
Include what you found, how to reproduce it, and the impact you expect. You
should hear back within a few days.

## Status

hush has **not been independently audited**. It uses well-known primitives
(argon2id, XChaCha20-Poly1305, Ed25519, X25519 sealed boxes) from Go's standard
library and `golang.org/x/crypto`, and nothing custom, but the protocol around
them is new.

## What hush protects against

- **A copied vault directory or bundle:** without the passphrase, it reveals only
  the vault name, member names, timestamps and sizes, never secret contents.
- **Tampering:** edited or forged ops fail signature, hash-link or permission
  checks and are rejected.
- **Non-members on the network:** they cannot open the sync protocol.
- **Removed members:** they lose access to new secrets and later changes. Values
  they could already read are flagged so you can rotate them.
- **Other websites:** they cannot drive `hush web` (localhost binding, session
  cookie, Host, Origin and custom-header checks, strict CSP).

## What it does not protect against

- **A compromised machine while the vault is unlocked:** keys are in memory, and
  wiping memory in Go is best effort.
- **A removed member's copies:** anything they had already decrypted stays with
  them. Change those secrets.
- **Network metadata in internet sync mode:** the public DHT sees your IP
  addresses and a rendezvous key, which it cannot link to a vault.
