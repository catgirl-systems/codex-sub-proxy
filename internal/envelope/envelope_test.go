package envelope

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTripAndRotation(t *testing.T) {
	oldKey, err := NewKey(7, bytes.Repeat([]byte{0x17}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := NewKey(8, bytes.Repeat([]byte{0x18}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	oldKeys, err := NewKeySet(oldKey)
	if err != nil {
		t.Fatal(err)
	}
	rotatedKeys, err := NewKeySet(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}

	oldEnvelope, err := Encrypt([]byte("conversation body"), PayloadDomain, oldKeys)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(oldEnvelope, PayloadDomain, rotatedKeys)
	if err != nil {
		t.Fatalf("decrypt old envelope: %v", err)
	}
	if string(got) != "conversation body" {
		t.Fatalf("plaintext = %q", got)
	}
	newEnvelope, err := Encrypt([]byte("new body"), PayloadDomain, rotatedKeys)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(newEnvelope[5:9]); got != newKey.Version {
		t.Fatalf("stored key version = %d, want %d", got, newKey.Version)
	}
	if _, err := Decrypt(newEnvelope, PayloadDomain, oldKeys); err == nil {
		t.Fatal("new envelope decrypted without active key")
	}
}

func TestDecryptRejectsTamperingWrongDomainAndWrongKey(t *testing.T) {
	key, err := NewKey(1, bytes.Repeat([]byte{0x21}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Encrypt([]byte("secret body"), PayloadDomain, keys)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		data   []byte
		domain Domain
		keys   KeySet
	}{
		{"ciphertext", func() []byte { copyOf := append([]byte(nil), data...); copyOf[len(copyOf)-1] ^= 1; return copyOf }(), PayloadDomain, keys},
		{"header", func() []byte { copyOf := append([]byte(nil), data...); copyOf[4] ^= 1; return copyOf }(), PayloadDomain, keys},
		{"domain", data, CredentialDomain, keys},
	}
	wrongKey, err := NewKey(1, bytes.Repeat([]byte{0x22}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	wrongKeys, err := NewKeySet(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, struct {
		name   string
		data   []byte
		domain Domain
		keys   KeySet
	}{"key", data, PayloadDomain, wrongKeys})

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Decrypt(test.data, test.domain, test.keys); err == nil {
				t.Fatal("tampered input was accepted")
			} else if strings.Contains(err.Error(), "secret body") {
				t.Fatal("plaintext reached error")
			}
		})
	}
}

func TestEnvelopeRejectsInvalidKeysFormatsAndBounds(t *testing.T) {
	if _, err := NewKey(1, bytes.Repeat([]byte{1}, KeySize-1)); err == nil {
		t.Fatal("short key was accepted")
	}
	if _, err := NewKey(0, bytes.Repeat([]byte{1}, KeySize)); err == nil {
		t.Fatal("zero key version was accepted")
	}
	key, err := NewKey(1, bytes.Repeat([]byte{1}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewKeySet(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Encrypt(bytes.Repeat([]byte{'x'}, MaxPlaintextSize+1), PayloadDomain, keys); err == nil {
		t.Fatal("oversized plaintext was accepted")
	}
	if _, err := Decrypt(bytes.Repeat([]byte{'x'}, MaxEnvelopeSize+1), PayloadDomain, keys); err == nil {
		t.Fatal("oversized envelope was accepted")
	}
	for _, bad := range [][]byte{
		nil,
		make([]byte, headerSize),
		append(make([]byte, headerSize), make([]byte, TagSize-1)...),
	} {
		if _, err := Decrypt(bad, PayloadDomain, keys); err == nil {
			t.Fatal("malformed envelope was accepted")
		}
	}
}

func FuzzDecryptNeverPanics(f *testing.F) {
	key, err := NewKey(1, bytes.Repeat([]byte{0x31}, KeySize))
	if err != nil {
		f.Fatal(err)
	}
	keys, err := NewKeySet(key)
	if err != nil {
		f.Fatal(err)
	}
	envelope, err := Encrypt([]byte("seed"), CredentialDomain, keys)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(envelope)
	f.Add([]byte("not an envelope"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decrypt(data, CredentialDomain, keys)
	})
}
