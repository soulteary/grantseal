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
# Pinned by digest for reproducible, tamper-evident builds. Tag: golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666
FROM golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS builder

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
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5

COPY --from=builder /out/license-tool /license-tool

ENTRYPOINT ["/license-tool"]
CMD ["--help"]
