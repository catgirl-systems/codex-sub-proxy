package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/catgirl-systems/codex-sub-proxy/internal/codex"
)

const sessionAffinityHashSalt = "codex-sub-proxy/session-affinity/v1"

func sessionAffinityIdentity(headers codex.RequestHeaderConfig) string {
	var identity strings.Builder
	if headers.SessionID != "" {
		identity.WriteString("session_id\x00")
		identity.WriteString(headers.SessionID)
	}
	if headers.ThreadID != "" {
		if identity.Len() != 0 {
			identity.WriteByte(0)
		}
		identity.WriteString("thread_id\x00")
		identity.WriteString(headers.ThreadID)
	}
	return identity.String()
}

func sessionAffinityHash(apiKeyID string, headers codex.RequestHeaderConfig) string {
	if headers.Validate() != nil {
		return ""
	}
	identity := sessionAffinityIdentity(headers)
	if identity == "" || apiKeyID == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(sessionAffinityHashSalt + "\x00" + apiKeyID + "\x00" + identity))
	return hex.EncodeToString(digest[:])
}

func resolveSessionAffinity(ctx context.Context, journal *Journal, apiKeyID string, headers codex.RequestHeaderConfig) (string, string, error) {
	hash := sessionAffinityHash(apiKeyID, headers)
	if hash == "" || journal == nil {
		return hash, "", nil
	}
	accountID, err := journal.ResolveSessionAffinity(ctx, apiKeyID, hash)
	if errors.Is(err, ErrSessionAffinityNotFound) {
		return hash, "", nil
	}
	if err != nil {
		return "", "", err
	}
	return hash, accountID, nil
}

func canRetrySessionAffinity(err error, sessionHash, forcedAccountID string, wroteOutput bool) bool {
	return sessionHash != "" && forcedAccountID == "" && sessionAffinityConflict(err, wroteOutput)
}

func sessionAffinityConflict(err error, wroteOutput bool) bool {
	return !wroteOutput && errors.Is(err, ErrBrokerBind) && errors.Is(err, ErrSessionAffinityConflict)
}

func sessionAffinityHashForAccount(sessionHash, hintedAccountID, accountID string) string {
	if sessionHash == "" || (hintedAccountID != "" && hintedAccountID != accountID) {
		return ""
	}
	return sessionHash
}
