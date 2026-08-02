package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const (
	KeySize           = 32
	NonceSize         = 12
	TagSize           = 16
	EnvelopeVersion   = 1
	MaxPreviousKeys   = 4
	MaxPlaintextSize  = 1 << 20
	headerSize        = 4 + 1 + 4 + NonceSize
	MaxEnvelopeSize   = headerSize + MaxPlaintextSize + TagSize
	maxCiphertextSize = MaxPlaintextSize + TagSize
)

// Domain selects the fixed associated-data domain.
type Domain byte

const (
	CredentialDomain Domain = 1
	PayloadDomain    Domain = 2
)

// Key is one AES-256 key with its stored version.
type Key struct {
	Version uint32
	Bytes   [KeySize]byte
}

// KeySet contains the active key and keys that can decrypt old records.
type KeySet struct {
	Active   Key
	Previous []Key
}

var envelopeMagic = [4]byte{'C', 'S', 'P', 'E'}

// NewKey validates and copies one raw AES-256 key.
func NewKey(version uint32, value []byte) (Key, error) {
	if version == 0 {
		return Key{}, errors.New("encryption key version is invalid")
	}
	if len(value) != KeySize {
		return Key{}, errors.New("encryption key must be 32 bytes")
	}
	var key Key
	key.Version = version
	copy(key.Bytes[:], value)
	return key, nil
}

// NewKeySet validates the active and previous keys.
func NewKeySet(active Key, previous ...Key) (KeySet, error) {
	keys := KeySet{Active: active, Previous: append([]Key(nil), previous...)}
	if err := keys.Validate(); err != nil {
		return KeySet{}, err
	}
	return keys, nil
}

// Validate checks key versions and the bounded previous-key list.
func (keys KeySet) Validate() error {
	if keys.Active.Version == 0 {
		return errors.New("active encryption key is invalid")
	}
	if len(keys.Previous) > MaxPreviousKeys {
		return errors.New("too many previous encryption keys")
	}
	for index, key := range keys.Previous {
		if key.Version == 0 {
			return errors.New("previous encryption key is invalid")
		}
		if key.Version == keys.Active.Version {
			return errors.New("encryption key versions must be unique")
		}
		for previousIndex := range index {
			if key.Version == keys.Previous[previousIndex].Version {
				return errors.New("encryption key versions must be unique")
			}
		}
	}
	return nil
}

// Encrypt creates a versioned authenticated envelope with the active key.
func Encrypt(plaintext []byte, domain Domain, keys KeySet) ([]byte, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	domainTag, err := domainTag(domain)
	if err != nil {
		return nil, err
	}
	if len(plaintext) > MaxPlaintextSize {
		return nil, errors.New("encrypted input is too large")
	}
	block, err := aes.NewCipher(keys.Active.Bytes[:])
	if err != nil {
		return nil, errors.New("create encryption cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("create encryption authenticator")
	}
	if aead.NonceSize() != NonceSize || aead.Overhead() != TagSize {
		return nil, errors.New("unsupported encryption parameters")
	}

	header := make([]byte, headerSize)
	copy(header[:len(envelopeMagic)], envelopeMagic[:])
	header[4] = EnvelopeVersion
	binary.BigEndian.PutUint32(header[5:9], keys.Active.Version)
	if _, err := rand.Read(header[9:]); err != nil {
		return nil, errors.New("generate encryption nonce")
	}
	associatedData := makeAssociatedData(domainTag, header)
	ciphertext := aead.Seal(nil, header[9:], plaintext, associatedData)
	if len(ciphertext) > maxCiphertextSize {
		return nil, errors.New("encrypted input is too large")
	}
	envelope := make([]byte, headerSize+len(ciphertext))
	copy(envelope, header)
	copy(envelope[headerSize:], ciphertext)
	return envelope, nil
}

// Decrypt authenticates an envelope with the active or previous key.
func Decrypt(data []byte, domain Domain, keys KeySet) ([]byte, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	domainTag, err := domainTag(domain)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("encrypted input is empty")
	}
	if len(data) > MaxEnvelopeSize {
		return nil, errors.New("encrypted input is too large")
	}
	if len(data) < headerSize+TagSize {
		return nil, errors.New("invalid encrypted envelope")
	}
	header := data[:headerSize]
	if !sameMagic(header[:len(envelopeMagic)], envelopeMagic[:]) || header[4] != EnvelopeVersion {
		return nil, errors.New("unsupported encrypted envelope")
	}
	keyVersion := binary.BigEndian.Uint32(header[5:9])
	key, ok := findKey(keys, keyVersion)
	if !ok {
		return nil, errors.New("encryption key is unavailable")
	}
	ciphertext := data[headerSize:]
	if len(ciphertext) > maxCiphertextSize || len(ciphertext) < TagSize {
		return nil, errors.New("invalid encrypted envelope")
	}
	block, err := aes.NewCipher(key.Bytes[:])
	if err != nil {
		return nil, errors.New("create decryption cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("create decryption authenticator")
	}
	associatedData := makeAssociatedData(domainTag, header)
	plaintext, err := aead.Open(nil, header[9:], ciphertext, associatedData)
	if err != nil {
		return nil, errors.New("decrypt encrypted input")
	}
	if len(plaintext) > MaxPlaintextSize {
		return nil, errors.New("decrypted input is too large")
	}
	return plaintext, nil
}

func findKey(keys KeySet, version uint32) (Key, bool) {
	if keys.Active.Version == version {
		return keys.Active, true
	}
	for _, key := range keys.Previous {
		if key.Version == version {
			return key, true
		}
	}
	return Key{}, false
}

func domainTag(domain Domain) ([]byte, error) {
	switch domain {
	case CredentialDomain:
		return []byte("csp:credential:v1"), nil
	case PayloadDomain:
		return []byte("csp:payload:v1"), nil
	default:
		return nil, errors.New("invalid encryption domain")
	}
}

func makeAssociatedData(domainTag, header []byte) []byte {
	data := make([]byte, len(domainTag)+len(header))
	copy(data, domainTag)
	copy(data[len(domainTag):], header)
	return data
}

func sameMagic(got, want []byte) bool {
	if len(got) != len(want) {
		return false
	}
	var difference byte
	for index := range got {
		difference |= got[index] ^ want[index]
	}
	return difference == 0
}
