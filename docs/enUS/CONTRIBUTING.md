# Contributing (English)

See the root [`CONTRIBUTING.md`](../../CONTRIBUTING.md) for the full guide.

Key rules: Go 1.26 standard library only; never commit private keys; keep signing
logic in `internal/issuer`; keep the verifier fail-closed and panic-free; run
`gofmt`, `go vet`, `go build`, `go test -race`, and the fuzz target before a PR.

Branch protection / PR flow: `main` is protected — land changes via a
feature/fix PR (no direct or force pushes), get ≥ 1 review (solo-maintainer
emergency self-merge allowed with an audit note), require the CI checks
(`test`/`vet`/`vuln`/`lint` + coverage gate) to pass, squash-merge, and publish
generated reports out-of-tree rather than committing them to `main`. See the
root guide for details.
