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

## Branch protection / PR flow

`main` is the protected, release-bearing branch. The following are the project's
governance expectations (a solo maintainer enforces them by convention where a
GitHub setting is unavailable):

- **Required checks.** A PR may only merge once the CI checks pass: `test`
  (with `-race`), `vet`, `vuln` (`govulncheck`), `lint` (`golangci-lint`), and
  the coverage gate (total ≥ 93 / per-package ≥ 88). Do not lower these gates to
  make a PR green.
- **No direct pushes, no force-pushes to `main`.** All changes land through a
  PR from a feature/fix branch. History on `main` is never rewritten.
- **At least one review.** Every PR needs ≥ 1 approving review before merge.
  For this solo project the maintainer may self-merge in an emergency, but must
  leave an audit note on the PR explaining the bypass.
- **Squash merge.** Merge PRs with *squash and merge* so `main` keeps one commit
  per change with a descriptive message; delete the branch after merge.
- **Feature/fix via PR.** Use short-lived `feat/…` or `fix/…` branches; keep PRs
  focused and small enough to review.
- **Report write-back is out-of-tree.** Generated artifacts (coverage reports,
  quality dashboards, badges) are published via a dedicated report branch/PR or
  an external artifact/badge service — never committed onto `main`'s source
  history from CI.

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
