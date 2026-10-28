<div align="center">

# hush

**A peer-to-peer secrets vault for small teams.**
One binary. No server. Nothing hidden: hush shows you every key derivation, decryption, signature and disk write as it happens.

[![CI](https://github.com/ovsec/hush/actions/workflows/ci.yml/badge.svg)](https://github.com/ovsec/hush/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ovsec/hush.svg)](https://pkg.go.dev/github.com/ovsec/hush)
[![Go Report Card](https://goreportcard.com/badge/github.com/ovsec/hush)](https://goreportcard.com/report/github.com/ovsec/hush)
[![Go version](https://img.shields.io/github/go-mod/go-version/ovsec/hush)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)
![Status](https://img.shields.io/badge/status-experimental-orange)

</div>

```
hush  /  team-infra                                  ● unlocked  2 secrets  ·  1/1 online

▍ github                ovsec-bot │ github
  postgres prod            app_rw │ v1 · updated just now by you
                                  │
                                  │ username   ovsec-bot
                                  │ password   ••••••••••••
                                  │
                                  │ under the hood ─────────────────────────────
                                  │ stored as  secret.put op 99aec4ed
                                  │ cipher     xchacha20-poly1305 · epoch 1 key

activity ──────────────────────────────────────────────────────────────────────
23:14:04  found   carol found on the local network (mDNS)
23:14:04  online  carol connected · direct · quic
23:14:08  sync    with carol · ↓ 0 op(s) · ↑ 1 op(s) · 1ms
```

> [!WARNING]
> hush is young and has **not been independently audited**. Its cryptography is standard and conservative, but treat it as experimental before trusting it with production secrets. See [SECURITY.md](SECURITY.md).

## Features

- **No server.** Members sync directly: mDNS on the LAN; on the internet, the public libp2p DHT, NAT hole punching and member-run relays.
- **End-to-end encrypted.** Only ciphertext touches the disk or the network. Peers verify every change before merging it.
- **Signed, tamper-evident log.** Every change is an Ed25519-signed op in a hash-linked log. A hand-edited log refuses to open.
- **Admin-controlled membership.** Invite people with join codes and 20-digit safety numbers. Removing someone rotates the vault key, re-encrypts everything, and flags the values they could have seen.
- **Optional company login.** OIDC (authorization code + PKCE), with the login cryptographically bound to the member's keys.
- **Live presence.** See who is online (directly or via relay) and when everyone was last seen.
- **Transparent.** An activity panel narrates every step, and you can view the raw encrypted record behind any secret.
- **TUI, web UI and CLI** on one service layer. The web UI is served on `127.0.0.1` only.

## Install

```sh
go install github.com/ovsec/hush/cmd/hush@latest
```

Or build from source:

```sh
git clone https://github.com/ovsec/hush && cd hush
go build -o hush ./cmd/hush
```

Requires Go 1.27+. Builds as a single static binary for macOS, Linux and Windows.

## Quick start

```sh
hush            # first run: create a vault, or join a team's
hush web        # the same vault in your browser
```

To bring in a teammate:

1. They run `hush`, pick **Join a team vault**, and send you their join code.
2. You press `m` → `a` and paste it. Both of you see a **safety number**. Read them to each other, and add them only if every digit matches.
3. You press `s` to export a bundle and send it any way you like. They import it and unlock.

From then on, sync keeps everyone current while hush is unlocked.

## Usage

| Command | |
|---|---|
| `hush` | open the TUI |
| `hush web` | open the vault in your browser (local only) |
| `hush daemon` | stay unlocked and keep syncing: an always-on peer |
| `hush ls` · `hush get github -f username` | for scripts; add `-v` to narrate each step on stderr |
| `hush log` | the signed log: exactly what someone holding the file could see |
| `hush code` · `members` · `add` · `remove` · `export` · `import` | team management |
| `hush login` · `hush sso set` · `hush sso off` | company login |

`-sync internet|lan|off` (or `HUSH_SYNC`) controls peer-to-peer sync; the default is `internet`. `HUSH_HOME` moves the vault from `~/.hush`.

TUI keys: `↑↓` move · `/` find · `enter` decrypt · `p` show · `c` copy (clears after 30s) · `n` new · `e` edit · `d` delete · `x` raw record on disk · `m` members · `a` activity · `l` lock. It locks itself after 5 idle minutes.

## How it works

```
passphrase ──argon2id──► key ──decrypts──► identity.json   (your ed25519 + x25519 private keys)
                                                │
ops.jsonl  ◄── every change is a signed op ─────┤ ed25519 signs; op id = sha-256 of the op
  genesis        vault founded, you are admin   │
  key.epoch      vault key, sealed to each member's x25519 key
  member.add     newcomer + every epoch key sealed to them
  member.remove  key revoked; a new key.epoch follows
  secret.put     entry encrypted with the vault key (xchacha20-poly1305, bound to vault+entry+epoch)
  secret.delete  tombstone
```

- On unlock, every op's signature, hash link and permission is checked.
- Concurrent edits resolve by last-writer-wins on a Lamport clock, so every peer reaches the same result.
- A removed member's writes count only if the admin had seen them before removing them. Every device converges, whatever order ops arrive in.
- On disk you'll find only ciphertext, plus the vault name, member names, timestamps and sizes. `hush log` shows exactly that.

### Sync and presence

- **Finding peers:** mDNS on the LAN. On the internet, the public libp2p DHT under a rendezvous key derived from the vault ID, which only members know. Peers also gossip the last addresses they saw for every member.
- **Connecting:** QUIC or TCP, NAT hole punching, or a reachable member acting as relay. A peer's libp2p ID *is* its Ed25519 vault key, so only members can open the sync protocol. `-sync lan` also refuses non-members at the connection level.
- **Syncing:** peers swap op IDs and send what the other lacks. Local changes are pushed at once.
- **Presence:** `● online · direct`, `◐ online · via relay` or `○ offline · seen 2h ago`. "Seen" times are gossiped, so you learn when someone was last online even if you never overlap.

### Company login (OIDC)

1. The admin registers hush as a **public client** (no secret) allowing `http://127.0.0.1` redirects, then runs `hush sso set -issuer <url> -client-id <id> -allow @co.com [-require]`.
2. A joiner runs `hush login -issuer <url> -client-id <id>` (authorization code + PKCE, loopback redirect). The **nonce is a hash of their public keys**, so the ID token proves this login asked for these keys.
3. When adding them, the admin's hush verifies the token's signature, issuer, audience, nonce, age (7 days at most) and the allow list, then records the verified identity in the signed `member.add` op.

### Web UI

`hush web` prints a one-time link. The server:

- binds to `127.0.0.1` only
- swaps the link token for an HttpOnly, SameSite=Strict session cookie
- rejects foreign `Host` headers (DNS rebinding) and cross-site changes (CSRF)
- serves a strict CSP with no third-party scripts
- locks after 5 idle minutes

## Project layout

```
cmd/hush         CLI, TUI launcher, sync controller
internal/crypt   primitives (argon2id, xchacha20-poly1305, ed25519, x25519)
internal/oplog   signed ops and the append-only file
internal/vault   rules: who may do what, epochs, conflict resolution, replay
internal/app     the service layer every UI uses, plus the activity feed
internal/tui     Bubble Tea interface
internal/web     local web UI: server + embedded static page
internal/p2p     libp2p node: discovery, sync protocol, presence, peer book
internal/sso     OIDC login and token verification; ssotest is a mock IdP
```

## Roadmap

- [x] Local vault, signed log, CLI
- [x] TUI with activity panel · local web UI
- [x] Members: invite, safety numbers, remove, key rotation
- [x] Peer-to-peer sync with live presence
- [x] OIDC identity binding
- [ ] Join over the network (no first bundle), sync status page
- [ ] Hardening: memguard, fuzzing, written threat model, signed releases
- [ ] Independent security review

## Known limitations

- Don't run the TUI and `hush web` against the same vault at once: each keeps its own view of the log.
- Internet sync makes your IP address and an unlinkable rendezvous key visible to the public DHT. Use `-sync lan` to avoid that.
- OIDC binds identity at join time only. Disabling someone at your IdP does not remove them from the vault.
- Go's garbage collector can copy memory, so wiping keys is best effort. Don't use hush where an attacker can read the memory of your unlocked process.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Please report security problems privately, as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
