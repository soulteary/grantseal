<!--
Thanks for contributing to grantseal. Please keep the runtime dependency-free
(standard library only) and preserve the stable LICENSE_* error codes.
-->

## Summary

<!-- What does this change do, and why? -->

## Type of change

- [ ] Bug fix (no API/behavior break)
- [ ] New feature (backward compatible)
- [ ] Breaking change (schema / error code / CLI / Go API)
- [ ] Docs / tooling / CI only

## Compatibility

<!-- See COMPATIBILITY.md. Fill in anything that changed. -->

- [ ] No change to `schema_version` or on-disk formats
- [ ] No stable `LICENSE_*` error code was renamed, removed, or repurposed
- [ ] No exported Go API in `pkg/*` was removed or changed incompatibly
- [ ] No CLI flag/subcommand was removed or repurposed

## Checklist

- [ ] `gofmt`, `go vet ./...` clean
- [ ] `go test ./...` and `go test ./... -race` pass
- [ ] New exported APIs have Go doc comments
- [ ] English and Chinese docs kept in sync (if docs changed)
- [ ] No private keys / license files / rollback state / fuzz crash corpus / build
      artifacts committed
- [ ] `CHANGELOG.md` updated for user-visible changes
