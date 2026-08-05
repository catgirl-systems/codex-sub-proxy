# syntax=docker/dockerfile:1.7
FROM golang:1.25.0-bookworm@sha256:81dc45d05a7444ead8c92a389621fafabc8e40f8fd1a19d7e5df14e61e98bc1a AS build
ARG VERSION
ARG REVISION
ARG CREATED
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ENV GOFLAGS=-trimpath\ -buildvcs=false\ -mod=readonly
ENV CGO_ENABLED=1 GOOS=linux GODEBUG=netdns=go
RUN install -d -m 700 -o 65532 -g 65532 /var/lib/codex-sub-proxy
RUN test -n "$VERSION" && test -n "$REVISION" && test -n "$CREATED"
RUN GOARCH="${TARGETARCH:-amd64}" go build -tags netgo -trimpath -buildvcs=false -mod=readonly \
    -ldflags "-s -w -linkmode external -extldflags '-static' -X github.com/catgirl-systems/codex-sub-proxy/internal/version.Version=$VERSION -X github.com/catgirl-systems/codex-sub-proxy/internal/version.Commit=$REVISION -X github.com/catgirl-systems/codex-sub-proxy/internal/version.BuildTime=$CREATED" \
    -o /out/codex-sub-proxy ./cmd/codex-sub-proxy

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
ARG VERSION
ARG REVISION
ARG CREATED
LABEL org.opencontainers.image.title="codex-sub-proxy" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.created="$CREATED" \
      org.opencontainers.image.description="OpenAI-compatible Codex proxy"
COPY --from=build /out/codex-sub-proxy /usr/local/bin/codex-sub-proxy
COPY --from=build --chown=65532:65532 /var/lib/codex-sub-proxy /var/lib/codex-sub-proxy
ENV HOME=/var/lib/codex-sub-proxy \
    CSP_STORAGE_SQLITE_PATH=/var/lib/codex-sub-proxy/csp.sqlite3 \
    CSP_STORAGE_ARTIFACT_ROOT=/var/lib/codex-sub-proxy/artifacts \
    CSP_CODEX_CREDENTIAL_FILE=/var/lib/codex-sub-proxy/credential.enc \
    GODEBUG=netdns=go
USER 65532:65532
WORKDIR /var/lib/codex-sub-proxy
VOLUME ["/var/lib/codex-sub-proxy"]
ENTRYPOINT ["/usr/local/bin/codex-sub-proxy"]
