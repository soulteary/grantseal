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
FROM golang:1.26 AS builder

WORKDIR /src

# grantseal has zero third-party dependencies, so there is no module download
# step; copy sources and build a fully static binary.
COPY . .

ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/license-tool ./cmd/license-tool

# ---- runtime ----
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /out/license-tool /license-tool

ENTRYPOINT ["/license-tool"]
CMD ["--help"]
