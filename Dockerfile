# Multi-stage Dockerfile for manual `docker build`.
#
# This file compiles license-tool from source. It is intended for local /
# CI `docker build` usage. goreleaser uses docker/Dockerfile.goreleaser
# instead, which copies a pre-built binary.
#
# SECURITY: this image never contains private keys. Private keys stay on the
# host and are mounted at runtime (e.g. `-v $PWD/keys:/keys:ro`). See
# .dockerignore for the build-context exclusions that keep keys/*.key out of
# the image.

# ---- builder ----
# Pinned by digest for reproducible, tamper-evident builds. Tag: golang:1.27.2
FROM golang:1.27.2@sha256:5bc7f572bbaa98885a3a1fd9c0aa76b59e3e14e8628bfc316bbfd0c701e4818c AS builder

WORKDIR /src

# grantseal has zero third-party dependencies, so there is no module download
# step; copy sources and build a fully static binary.
COPY . .

ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/license-tool ./cmd/license-tool

# ---- runtime ----
# Pinned by digest. Tag: gcr.io/distroless/static-debian13:nonroot
# See docker/Dockerfile.goreleaser and the ci-recipes archive allowlist: the
# base allowlist is scoped to exactly this digest and MUST be re-reviewed on any
# base bump.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY --from=builder /out/license-tool /license-tool

ENTRYPOINT ["/license-tool"]
CMD ["--help"]
