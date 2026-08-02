package payload

import "github.com/catgirl-systems/codex-sub-proxy/internal/envelope"

// Encrypt protects a conversation payload with the active payload key.
func Encrypt(plaintext []byte, keys envelope.KeySet) ([]byte, error) {
	return envelope.Encrypt(plaintext, envelope.PayloadDomain, keys)
}

// Decrypt opens a conversation payload with the active or previous payload key.
func Decrypt(data []byte, keys envelope.KeySet) ([]byte, error) {
	return envelope.Decrypt(data, envelope.PayloadDomain, keys)
}
