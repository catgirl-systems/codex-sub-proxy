#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=${VERSION-}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH-}
REVISION=${REVISION-}
IMAGE=${IMAGE:-codex-sub-proxy:$VERSION}
RUN_IMAGE=0
if [ "${1-}" = "--run" ]; then
	RUN_IMAGE=1
	shift
fi
if [ "$#" -ne 0 ]; then
	echo "unexpected container option" >&2
	exit 1
fi
case "$VERSION" in
	v[0-9]*.[0-9]*.[0-9]*) ;;
	*) echo "VERSION must use vMAJOR.MINOR.PATCH" >&2; exit 1 ;;
esac
case "$SOURCE_DATE_EPOCH" in
	''|*[!0-9]*) echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2; exit 1 ;;
esac
case "$IMAGE" in
	''|*" "*|*"/../"*|*"..") echo "unsafe image name" >&2; exit 1 ;;
esac
if [ -z "$REVISION" ]; then
	if ! REVISION=$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null); then
		echo "REVISION is required outside a git work tree" >&2
		exit 1
	fi
fi
validate_containerfile() {
	if ! grep -Eq '^FROM golang:1\.25\.0-bookworm@sha256:[0-9a-f]{64} AS build$' "$ROOT/Containerfile"; then
		echo "container: build base is not pinned" >&2
		exit 1
	fi
	if ! grep -Eq '^FROM gcr\.io/distroless/static-debian12:nonroot@sha256:[0-9a-f]{64}$' "$ROOT/Containerfile"; then
		echo "container: runtime base is not pinned" >&2
		exit 1
	fi
	for required in \
		'USER 65532:65532' \
		'VOLUME ["/var/lib/codex-sub-proxy"]' \
		'CSP_STORAGE_SQLITE_PATH=/var/lib/codex-sub-proxy/csp.sqlite3' \
		'CSP_STORAGE_ARTIFACT_ROOT=/var/lib/codex-sub-proxy/artifacts' \
		'CSP_CODEX_CREDENTIAL_FILE=/var/lib/codex-sub-proxy/credential.enc' \
		'GODEBUG=netdns=go' \
		'ENTRYPOINT ["/usr/local/bin/codex-sub-proxy"]'; do
		if ! grep -Fq "$required" "$ROOT/Containerfile"; then
			echo "container: missing contract $required" >&2
			exit 1
		fi
	done
}
validate_containerfile
ENGINE=${CONTAINER_ENGINE-}
if [ -z "$ENGINE" ]; then
	if command -v podman >/dev/null 2>&1; then
		ENGINE=podman
	elif command -v docker >/dev/null 2>&1; then
		ENGINE=docker
	else
		echo "container: unavailable (docker and podman are not installed)"
		exit 0
	fi
fi
if ! command -v "$ENGINE" >/dev/null 2>&1; then
	echo "container: unavailable ($ENGINE is not installed)"
	exit 0
fi
cd "$ROOT"
if ! "$ENGINE" info >/dev/null 2>&1; then
	echo "container: unavailable ($ENGINE daemon is not running)"
	exit 0
fi
CREATED=$(go run ./scripts/created -epoch "$SOURCE_DATE_EPOCH")
	"$ENGINE" build --pull=false --file Containerfile \
	--build-arg VERSION="$VERSION" \
	--build-arg REVISION="$REVISION" \
	--build-arg CREATED="$CREATED" \
	--label org.opencontainers.image.version="$VERSION" \
	--label org.opencontainers.image.revision="$REVISION" \
	--label org.opencontainers.image.created="$CREATED" \
	--tag "$IMAGE" .
IMAGE_ID=$("$ENGINE" image inspect --format '{{.Id}}' "$IMAGE")
IMAGE_USER=$("$ENGINE" image inspect --format '{{.Config.User}}' "$IMAGE")
IMAGE_ENV=$("$ENGINE" image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE")
IMAGE_ENTRYPOINT=$("$ENGINE" image inspect --format '{{json .Config.Entrypoint}}' "$IMAGE")
IMAGE_VOLUME=$("$ENGINE" image inspect --format '{{json .Config.Volumes}}' "$IMAGE")
if [ "$IMAGE_USER" != "65532:65532" ] ||
	! printf '%s\n' "$IMAGE_ENV" | grep -Fxq 'HOME=/var/lib/codex-sub-proxy' ||
	! printf '%s\n' "$IMAGE_ENV" | grep -Fxq 'CSP_STORAGE_SQLITE_PATH=/var/lib/codex-sub-proxy/csp.sqlite3' ||
	! printf '%s\n' "$IMAGE_ENV" | grep -Fxq 'CSP_STORAGE_ARTIFACT_ROOT=/var/lib/codex-sub-proxy/artifacts' ||
	! printf '%s\n' "$IMAGE_ENV" | grep -Fxq 'CSP_CODEX_CREDENTIAL_FILE=/var/lib/codex-sub-proxy/credential.enc' ||
	! printf '%s\n' "$IMAGE_ENV" | grep -Fxq 'GODEBUG=netdns=go' ||
	[ "$IMAGE_ENTRYPOINT" != '["/usr/local/bin/codex-sub-proxy"]' ] ||
	! printf '%s\n' "$IMAGE_VOLUME" | grep -Fq '/var/lib/codex-sub-proxy'; then
	echo "container: image contract inspection failed" >&2
	exit 1
fi
IMAGE_DIGEST=$("$ENGINE" image inspect --format '{{.Digest}}' "$IMAGE" 2>/dev/null || true)
if [ -z "$IMAGE_DIGEST" ]; then
	IMAGE_DIGEST=$IMAGE_ID
fi
printf 'image=%s\nimage_id=%s\nimage_digest=%s\n' "$IMAGE" "$IMAGE_ID" "$IMAGE_DIGEST"
if [ "$RUN_IMAGE" -eq 1 ]; then
	DATA=$(mktemp -d "${TMPDIR:-/tmp}/csp-container.XXXXXX")
	trap 'rm -rf "$DATA"' EXIT HUP INT TERM
	chmod 700 "$DATA"
	"$ENGINE" run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --tmpfs /run:rw,noexec,nosuid,size=16m \
		--user 65532:65532 --volume "$DATA:/var/lib/codex-sub-proxy:rw" "$IMAGE" version
fi
