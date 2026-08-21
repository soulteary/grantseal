# Contributing to grantseal

Related: [Code of Conduct](CODE_OF_CONDUCT.md) | [Security Policy](SECURITY.md) | [Docs: English](docs/enUS/README.md) · [中文文档](docs/zhCN/README.md)

Thanks for your interest in improving grantseal.

## Ground rules

- **Go 1.26, standard library only.** Do not add third-party dependencies. The
  crypto surface is intentionally limited to `crypto/ed25519`, `crypto/rand`,
  `crypto/sha256`, `crypto/hmac`, `crypto/subtle`, and `encoding/json`.
- **Never commit private keys** or any secret. Tests must generate ephemeral
  Ed25519 keys at runtime; `testdata/` may contain generated public keys or
  fixtures produced by test code only.
- **Respect the isolation boundary.** Client-facing code lives in `pkg/`.
  Private-key/signing logic lives in `internal/issuer` so it cannot be imported
  by clients. Do not move signing into `pkg/`.
- **Keep the verifier fail-closed and panic-free.** Any new parsing/validation
  path must return a stable `license.Code` error, never panic.

## Development workflow

```bash
gofmt -l .                 # must print nothing
go vet ./...
go build ./...
go test ./... -race
go test ./pkg/license -run=Fuzz -fuzz=Fuzz -fuzztime=20s
```

All of the above must pass before opening a PR.

## Coding conventions

- Follow the sibling projects' layout: `main.go` + `internal/` + `pkg/` +
  `cmd/` + `docs/`.
- Add stable error codes to `pkg/license/errors.go`; do not reuse a code with a
  different meaning.
- Comments explain intent/trade-offs, not the obvious mechanics of the code.

## Tests

- Add coverage for every new validation branch and every new error code.
- Prefer table-driven tests. Use `-race` for anything touching shared state.
- Keep the fuzz corpus meaningful; malformed input must never panic.
