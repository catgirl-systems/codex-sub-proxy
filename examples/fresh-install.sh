#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
DRY_RUN=0
if [ "${1-}" = "--dry-run" ]; then
	DRY_RUN=1
	shift
fi
if [ "$#" -ne 0 ]; then
	echo "unexpected argument" >&2
	exit 1
fi
for command in go curl; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "$command is required" >&2
		exit 1
	fi
done
: "${CSP_PAYLOAD_ENCRYPTION_KEY:?Set CSP_PAYLOAD_ENCRYPTION_KEY in the environment.}"
: "${CSP_CREDENTIAL_ENCRYPTION_KEY:?Set CSP_CREDENTIAL_ENCRYPTION_KEY in the environment.}"
: "${CSP_API_KEY_HMAC_KEY:?Set CSP_API_KEY_HMAC_KEY in the environment.}"
: "${CSP_ADMIN_TOKEN_HMAC_KEY:?Set CSP_ADMIN_TOKEN_HMAC_KEY in the environment.}"
: "${CSP_ADMIN_BOOTSTRAP_TOKEN:?Set CSP_ADMIN_BOOTSTRAP_TOKEN in the environment.}"
if [ "$DRY_RUN" -eq 1 ]; then
	: "${CSP_DRY_RUN_ACCESS_TOKEN:?Set CSP_DRY_RUN_ACCESS_TOKEN in the environment.}"
	: "${CSP_DRY_RUN_REFRESH_TOKEN:?Set CSP_DRY_RUN_REFRESH_TOKEN in the environment.}"
else
	: "${CSP_CODEX_AUTH_SOURCE:?Set CSP_CODEX_AUTH_SOURCE to an existing Codex auth source.}"
	: "${CSP_UPSTREAM_RESPONSES_URL:?Set CSP_UPSTREAM_RESPONSES_URL to the Codex Responses URL.}"
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/csp-install.XXXXXX")
PROXY_PID=
UPSTREAM_PID=
cleanup() {
	if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
		kill -TERM "$PROXY_PID" 2>/dev/null || true
		count=0
		while kill -0 "$PROXY_PID" 2>/dev/null; do
			count=$((count + 1))
			if [ "$count" -ge 50 ]; then
				kill -KILL "$PROXY_PID" 2>/dev/null || true
				break
			fi
			sleep 0.1
		done
		wait "$PROXY_PID" 2>/dev/null || true
	fi
	if [ -n "$UPSTREAM_PID" ] && kill -0 "$UPSTREAM_PID" 2>/dev/null; then
		kill -TERM "$UPSTREAM_PID" 2>/dev/null || true
		wait "$UPSTREAM_PID" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

DATA_LISTEN=${CSP_INSTALL_DATA_LISTEN:-127.0.0.1:4000}
ADMIN_LISTEN=${CSP_INSTALL_ADMIN_LISTEN:-127.0.0.1:4001}
CONFIG="$WORK/config.toml"
DB_PATH="$WORK/csp.sqlite3"
ARTIFACT_ROOT="$WORK/artifacts"
CREDENTIAL_FILE="$WORK/credential.enc"
cp "$ROOT/examples/config.toml" "$CONFIG"
export CSP_SERVER_LISTEN="$DATA_LISTEN"
export CSP_SERVER_ADMIN_LISTEN="$ADMIN_LISTEN"
export CSP_STORAGE_SQLITE_PATH="$DB_PATH"
export CSP_STORAGE_ARTIFACT_ROOT="$ARTIFACT_ROOT"
export CSP_CODEX_CREDENTIAL_FILE="$CREDENTIAL_FILE"
if [ "$DRY_RUN" -eq 1 ]; then
	go build -o "$WORK/fake-upstream" ./scripts/fake-upstream
	"$WORK/fake-upstream" -listen 127.0.0.1:0 >"$WORK/upstream-url" 2>"$WORK/upstream.log" &
	UPSTREAM_PID=$!
	count=0
	while [ ! -s "$WORK/upstream-url" ]; do
		count=$((count + 1))
		if [ "$count" -ge 100 ]; then
			echo "fake upstream did not start" >&2
			exit 1
		fi
		sleep 0.1
	done
	UPSTREAM_URL=$(sed -n '1p' "$WORK/upstream-url")
	export CSP_CODEX_RESPONSES_URL="$UPSTREAM_URL/v1/responses"
	cat >"$WORK/auth.json" <<EOF
{"access_token":"$CSP_DRY_RUN_ACCESS_TOKEN","refresh_token":"$CSP_DRY_RUN_REFRESH_TOKEN","expires_at":4102444800,"account_id":"dry-run-account"}
EOF
	go run ./cmd/codex-sub-proxy import --config "$CONFIG" --source "$WORK/auth.json"
else
	export CSP_CODEX_RESPONSES_URL="$CSP_UPSTREAM_RESPONSES_URL"
	go run ./cmd/codex-sub-proxy import --config "$CONFIG" --source "$CSP_CODEX_AUTH_SOURCE"
fi

go build -o "$WORK/codex-sub-proxy" ./cmd/codex-sub-proxy
"$WORK/codex-sub-proxy" --config "$CONFIG" >"$WORK/proxy.log" 2>"$WORK/proxy.err" &
PROXY_PID=$!
count=0
while :; do
	if curl -fsS --max-time 1 "http://$DATA_LISTEN/readyz" >/dev/null 2>&1; then
		break
	fi
	count=$((count + 1))
	if [ "$count" -ge 100 ]; then
		echo "proxy readiness did not complete" >&2
		exit 1
	fi
	sleep 0.1
done
if ! ADMIN_RESPONSE=$(curl -sS --max-time 5 -H "Authorization: Bearer $CSP_ADMIN_BOOTSTRAP_TOKEN" -H "Content-Type: application/json" \
	-d '{"name":"fresh-install","owner":"fresh-install","policy":{"allowed_endpoints":["/v1/responses"],"allowed_models":["gpt-4.1"],"max_concurrent_requests":1,"rolling_request_count":0,"rolling_request_window":0,"period_request_limit":0,"period_token_limit":0,"period_image_limit":0,"period_cost_microunit_limit":0,"period_duration":0,"token_reservation_default":0,"token_reservation_ceiling":0,"image_reservation_default":0,"image_reservation_ceiling":0,"cost_microunit_reservation_default":0,"cost_microunit_reservation_ceiling":0}}' \
	"http://$ADMIN_LISTEN/admin/v1/api-keys"); then
	cat "$WORK/proxy.err" >&2
	exit 1
fi
API_KEY=$(printf '%s' "$ADMIN_RESPONSE" | sed -n 's/.*"key":"\([^"]*\)".*/\1/p')
if [ -z "$API_KEY" ]; then
	echo "admin API key issue failed" >&2
	exit 1
fi
RESPONSE=$(curl -fsS --max-time 15 -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
	-d '{"model":"gpt-4.1","input":"hello"}' "http://$DATA_LISTEN/v1/responses")
if ! printf '%s' "$RESPONSE" | go run ./scripts/validate-response; then
	if [ "$DRY_RUN" -eq 1 ]; then
		echo "dry-run Responses validation failed" >&2
	else
		echo "Responses response validation failed" >&2
	fi
	exit 1
fi
printf '%s\n' "fresh install complete"
