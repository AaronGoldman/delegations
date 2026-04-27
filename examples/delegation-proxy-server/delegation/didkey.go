package delegation

import (
	"crypto/ed25519"
	"fmt"
	"math/big"
	"strings"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Decode decodes a base58btc-encoded string (without a multibase prefix).
func base58Decode(s string) ([]byte, error) {
	result := new(big.Int)
	base := big.NewInt(58)
	for _, c := range s {
		idx := strings.IndexRune(base58Alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("base58Decode: invalid character %q", c)
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(idx)))
	}
	decoded := result.Bytes()
	// Prepend a zero byte for each leading '1' character (represents a 0x00 byte).
	leadingZeros := 0
	for _, c := range s {
		if c != '1' {
			break
		}
		leadingZeros++
	}
	out := make([]byte, leadingZeros+len(decoded))
	copy(out[leadingZeros:], decoded)
	return out, nil
}

// ParseDIDKey parses a did:key URI for an Ed25519 public key.
// Expected format: did:key:z<base58btc(0xed 0x01 || 32-byte-pubkey)>
// The 0xed 0x01 prefix is the varint-encoded multicodec identifier for Ed25519 public keys.
func ParseDIDKey(didKey string) (ed25519.PublicKey, error) {
	const prefix = "did:key:z"
	if !strings.HasPrefix(didKey, prefix) {
		return nil, fmt.Errorf("ParseDIDKey: unsupported format (expected did:key:z...)")
	}
	encoded := didKey[len(prefix):]
	decoded, err := base58Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("ParseDIDKey: base58 decode: %w", err)
	}
	// Ed25519 multicodec prefix: 0xed 0x01
	if len(decoded) < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("ParseDIDKey: not an Ed25519 did:key (wrong multicodec prefix)")
	}
	pubKeyBytes := decoded[2:]
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ParseDIDKey: invalid Ed25519 public key length %d (want %d)",
			len(pubKeyBytes), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(pubKeyBytes), nil
}
