#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=${VERSION-}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH-}
COMMIT=${COMMIT-}
OUT_DIR=${OUT_DIR:-$ROOT/dist}

case "$ROOT" in
	/|*"/../"*|*"/..") echo "unsafe source path" >&2; exit 1 ;;
esac
case "$VERSION" in
	v[0-9]*.[0-9]*.[0-9]*) ;;
	*) echo "VERSION must use vMAJOR.MINOR.PATCH" >&2; exit 1 ;;
esac
case "$SOURCE_DATE_EPOCH" in
	''|*[!0-9]*) echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2; exit 1 ;;
esac
case "$OUT_DIR" in
	/|"$ROOT"|*"/../"*|*"/..") echo "unsafe output path" >&2; exit 1 ;;
esac
if [ -L "$OUT_DIR" ]; then
	echo "output path must not be a symlink" >&2
	exit 1
fi
if [ -z "$COMMIT" ]; then
	if ! COMMIT=$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null); then
		echo "COMMIT is required outside a git work tree" >&2
		exit 1
	fi
fi
case "$COMMIT" in
	''|*" "*|*"/"*|*".."*) echo "unsafe COMMIT" >&2; exit 1 ;;
esac

if ! command -v go >/dev/null 2>&1; then
	echo "go is required" >&2
	exit 1
fi
cd "$ROOT"
if ! (cd "$ROOT" && go mod verify); then
	echo "module verification failed" >&2
	exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/csp-release.XXXXXX")
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir -p "$WORK/bin"

export GOFLAGS='-trimpath -buildvcs=false -mod=readonly'
BUILD_TIME=$SOURCE_DATE_EPOCH
TARGETS=${RELEASE_TARGETS:-'darwin/arm64 darwin/amd64 linux/arm64 linux/amd64'}
for target in $TARGETS; do
	GOOS=${target%/*}
	GOARCH=${target#*/}
	case "$GOOS/$GOARCH" in
		darwin/arm64) CC_NAME=${CC_DARWIN_ARM64-} ;;
		darwin/amd64) CC_NAME=${CC_DARWIN_AMD64-} ;;
		linux/arm64) CC_NAME=${CC_LINUX_ARM64-} ;;
		linux/amd64) CC_NAME=${CC_LINUX_AMD64-} ;;
		*) echo "unsupported release target" >&2; exit 1 ;;
	esac
	if [ -z "$CC_NAME" ] && [ "$GOOS" = darwin ]; then
		CC_NAME=clang
	fi
	if [ -z "$CC_NAME" ]; then
		echo "set CC_${GOOS}_${GOARCH} for CGO release builds" >&2
		exit 1
	fi
	if ! command -v "$CC_NAME" >/dev/null 2>&1; then
		echo "C compiler $CC_NAME is not installed" >&2
		exit 1
	fi
	NAME="codex-sub-proxy-$VERSION-$GOOS-$GOARCH"
	TARGET_DIR="$WORK/bin/$GOOS-$GOARCH"
	mkdir -p "$TARGET_DIR"
	CGO_ENABLED=1 GOOS="$GOOS" GOARCH="$GOARCH" CC="$CC_NAME" go build \
		-o "$TARGET_DIR/codex-sub-proxy" \
		-ldflags "-s -w -X github.com/catgirl-systems/codex-sub-proxy/internal/version.Version=$VERSION -X github.com/catgirl-systems/codex-sub-proxy/internal/version.Commit=$COMMIT -X github.com/catgirl-systems/codex-sub-proxy/internal/version.BuildTime=$BUILD_TIME" \
		./cmd/codex-sub-proxy
	go run ./scripts/mtime -epoch "$SOURCE_DATE_EPOCH" "$TARGET_DIR/codex-sub-proxy"
	go run ./scripts/archive -root "$TARGET_DIR" -output "$OUT_DIR/$NAME.tar" -name "$NAME" -epoch "$SOURCE_DATE_EPOCH"
done

go run ./scripts/checksums -root "$OUT_DIR" -output "$OUT_DIR/SHA256SUMS"
cat "$OUT_DIR/SHA256SUMS"
