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
# Pinned by digest for reproducible, tamper-evident builds. Tag: golang:1.26
FROM golang:1.26@sha256:45a5f7a810238aabcbad211d70b9ae082022d96f7c7259e94041ad1b933575ac AS builder

WORKDIR /src

# grantseal has zero third-party dependencies, so there is no module download
# step; copy sources and build a fully static binary.
COPY . .

ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/license-tool ./cmd/license-tool

# ---- runtime ----
# Pinned by digest. Tag: gcr.io/distroless/static:nonroot
FROM gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

COPY --from=builder /out/license-tool /license-tool

ENTRYPOINT ["/license-tool"]
CMD ["--help"]
