# syntax=docker/dockerfile:1.7
FROM golang:1.25.0-bookworm AS build
ARG VERSION
ARG REVISION
ARG CREATED
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ENV GOFLAGS=-trimpath\ -buildvcs=false\ -mod=readonly
ENV CGO_ENABLED=1 GOOS=linux
RUN test -n "$VERSION" && test -n "$REVISION" && test -n "$CREATED"
RUN GOARCH="${TARGETARCH:-amd64}" go build -trimpath -buildvcs=false -mod=readonly \
    -ldflags "-s -w -linkmode external -extldflags '-static' -X github.com/catgirl-systems/codex-sub-proxy/internal/version.Version=$VERSION -X github.com/catgirl-systems/codex-sub-proxy/internal/version.Commit=$REVISION -X github.com/catgirl-systems/codex-sub-proxy/internal/version.BuildTime=$CREATED" \
    -o /out/codex-sub-proxy ./cmd/codex-sub-proxy

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION
ARG REVISION
ARG CREATED
LABEL org.opencontainers.image.title="codex-sub-proxy" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.created="$CREATED" \
      org.opencontainers.image.description="OpenAI-compatible Codex proxy"
COPY --from=build /out/codex-sub-proxy /usr/local/bin/codex-sub-proxy
USER 65532:65532
WORKDIR /var/lib/codex-sub-proxy
VOLUME ["/var/lib/codex-sub-proxy"]
ENTRYPOINT ["/usr/local/bin/codex-sub-proxy"]
