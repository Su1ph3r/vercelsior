# Standalone build (docker build -t vercelsior .). For released images pulled
# from GHCR, see `docker pull ghcr.io/su1ph3r/vercelsior` — those are produced
# by goreleaser via Dockerfile.goreleaser.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# Stamp a version so `vercelsior --version` is meaningful even for local
# source builds. Overridable: --build-arg VERSION=v1.0.0
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" \
    -o /bin/vercelsior ./cmd/vercelsior

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /bin/vercelsior /usr/local/bin/vercelsior
ENTRYPOINT ["vercelsior"]
