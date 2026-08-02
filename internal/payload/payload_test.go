package payload

import (
	"bytes"
	"testing"

	"github.com/catgirl-systems/codex-sub-proxy/internal/envelope"
)

func TestEncryptDecryptRoundTripAndAuthentication(t *testing.T) {
	key, err := envelope.NewKey(3, bytes.Repeat([]byte{0x33}, envelope.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := envelope.NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encrypt([]byte("conversation body"), keys)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	got, err := Decrypt(encoded, keys)
	if err != nil {
		t.Fatalf("decrypt payload: %v", err)
	}
	if string(got) != "conversation body" {
		t.Fatalf("payload = %q", got)
	}
	encoded[len(encoded)-1] ^= 1
	if _, err := Decrypt(encoded, keys); err == nil {
		t.Fatal("tampered payload was accepted")
	}
}
