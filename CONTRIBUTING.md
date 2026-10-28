# Contributing

Thanks for helping. Issues, ideas and pull requests are all welcome.

## Development

```sh
go build ./cmd/hush
go vet ./...
go test -race ./...
```

Tests never touch the internet. P2P tests run real libp2p nodes on
`127.0.0.1`, and OIDC tests use the mock provider in `internal/sso/ssotest`.

## Guidelines

- Keep changes focused, and add a test for any behaviour you change.
- Run `gofmt`; CI checks it.
- Anything touching `internal/crypt`, `internal/vault` or the sync protocol needs
  a clear explanation of why it stays safe. Never add custom cryptography.
- New background work should narrate itself on the activity feed (`Feed().Emit`),
  so hush stays transparent about what it does.

Report security issues privately; see [SECURITY.md](SECURITY.md).
