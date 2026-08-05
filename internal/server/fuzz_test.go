package server

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
)

func FuzzForwardedParser(f *testing.F) {
	f.Add("192.0.2.1, 198.51.100.2")
	f.Add("for=192.0.2.1, for=198.51.100.2")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		_, _ = parseXForwardedFor(raw)
		_, _ = parseForwardedChain(raw)
	})
}

func FuzzOriginAndContentType(f *testing.F) {
	f.Add("https://example.test", "application/json")
	f.Add("", "multipart/form-data; boundary=abc")
	f.Fuzz(func(t *testing.T, origin, contentType string) {
		if len(origin) > 4096 || len(contentType) > 4096 {
			t.Skip()
		}
		request := httptest.NewRequest("POST", "https://example.test/v1/responses", nil)
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", contentType)
		_, _, _ = parseRequestMediaType(request)
		_ = validateAdminRequestOrigin(request, true)
	})
}

func FuzzRequestIDs(f *testing.F) {
	f.Add("req_01")
	f.Add("00000000-0000-4000-8000-000000000000")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		_ = validRequestID(raw)
		_ = safeRequestID([]string{raw})
	})
}

func FuzzAdminAndLifecycleCursors(f *testing.F) {
	f.Add([]byte("csp_admin_0000000000000000_000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), "not-a-cursor")
	f.Add([]byte("not-a-token"), "")
	f.Fuzz(func(t *testing.T, raw []byte, cursor string) {
		if len(raw) > 4096 || len(cursor) > 4096 {
			t.Skip()
		}
		_, _ = parseAdminToken(raw)
		_, _ = decodeAdminLifecycleCursor(cursor)
	})
}

func FuzzJournalEnvelope(f *testing.F) {
	f.Add([]byte("not-an-envelope"))
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > envelope.MaxEnvelopeSize+1 {
			t.Skip()
		}
		_ = validateJournalEnvelope(payload)
	})
}

func FuzzBackupManifest(f *testing.F) {
	f.Add([]byte(`{"format":"csp-backup-v1","schema_version":1,"timestamp":"2023-11-14T22:13:20Z","entries":[]}`))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > backupMaxManifestSize+1 {
			t.Skip()
		}
		var manifest BackupManifest
		if json.Unmarshal(raw, &manifest) == nil {
			_ = validateRestoreManifest(manifest, RestoreOptions{})
		}
	})
}
