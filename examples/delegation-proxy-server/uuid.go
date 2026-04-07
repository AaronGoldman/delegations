package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

// randomHex returns n random bytes hex-encoded (2n chars).
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// deriveID returns a UUIDv5 derived from serverSecret (a UUID string used as
// the namespace) and cookieValue (the raw cookie string). This matches
// Python's uuid.uuid5(server_secret, cookie_value).
func deriveID(serverSecret, cookieValue string) (string, error) {
	ns, err := parseUUID(serverSecret)
	if err != nil {
		return "", fmt.Errorf("deriveID: invalid server secret: %w", err)
	}
	return uuidv5(ns, []byte(cookieValue)), nil
}

// parseUUID parses a UUID string (with or without dashes) into 16 bytes.
func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return u, fmt.Errorf("invalid UUID %q: expected 32 hex chars, got %d", s, len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return u, fmt.Errorf("invalid UUID %q: %w", s, err)
	}
	copy(u[:], b)
	return u, nil
}

// formatUUID formats 16 bytes as a lowercase UUID string.
func formatUUID(u [16]byte) string {
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// newUUIDv4 generates a random RFC 4122 version 4 UUID.
func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return formatUUID(b)
}

// uuidv5 computes a RFC 4122 version 5 UUID from a 16-byte namespace and a name.
// This matches Python's uuid.uuid5(namespace, name).
func uuidv5(namespace [16]byte, name []byte) string {
	h := sha1.New()
	h.Write(namespace[:])
	h.Write(name)
	hash := h.Sum(nil) // 20 bytes; we use the first 16

	var u [16]byte
	copy(u[:], hash[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC 4122 variant
	return formatUUID(u)
}
