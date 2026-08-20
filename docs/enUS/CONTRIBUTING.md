# Contributing (English)

See the root [`CONTRIBUTING.md`](../../CONTRIBUTING.md) for the full guide.

Key rules: Go 1.26 standard library only; never commit private keys; keep signing
logic in `internal/issuer`; keep the verifier fail-closed and panic-free; run
`gofmt`, `go vet`, `go build`, `go test -race`, and the fuzz target before a PR.
