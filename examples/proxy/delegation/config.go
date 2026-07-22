package delegation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// ConfigValues holds delegation-specific configuration values loaded from config.json.
type ConfigValues struct {
	DelegationURLSecret []byte
	IdDerivationSecret  string
	DelegationHeaderKey ed25519.PrivateKey
	DelegationHeaderPub ed25519.PublicKey
}

// LoadConfig reads config.json and returns delegation configuration values.
// It auto-generates any missing secrets and ensures they are persisted.
func LoadConfig(configPath string) (*ConfigValues, error) {
	cfg, err := loadConfigFile(configPath)
	if err != nil {
		return nil, err
	}

	// Ensure all required secrets exist, generating any that are missing
	if err := ensureDelegationSecrets(cfg, configPath); err != nil {
		return nil, err
	}

	// Parse and validate secrets
	delegationURLSecret := cfg["delegation_url_secret"]
	idDerivationSecret := cfg["id_derivation_secret"]
	delegationHeaderKeyHex := cfg["delegation_header_key"]

	if _, err := ParseUUID(idDerivationSecret); err != nil {
		return nil, fmt.Errorf("id_derivation_secret is not a valid UUID: %w", err)
	}

	keyBytes, err := hex.DecodeString(delegationHeaderKeyHex)
	if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("delegation_header_key is invalid (want %d-byte hex): %w", ed25519.PrivateKeySize, err)
	}

	delegationHeaderKey := ed25519.PrivateKey(keyBytes)
	delegationHeaderPub := delegationHeaderKey.Public().(ed25519.PublicKey)

	return &ConfigValues{
		DelegationURLSecret: []byte(delegationURLSecret),
		IdDerivationSecret:  idDerivationSecret,
		DelegationHeaderKey: delegationHeaderKey,
		DelegationHeaderPub: delegationHeaderPub,
	}, nil
}

// loadConfigFile reads config.json as a flat map[string]string.
// If the file does not exist it is created with defaults.
func loadConfigFile(path string) (map[string]string, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := writeDefaultConfig(path); err != nil {
			return nil, fmt.Errorf("create %s: %w", path, err)
		}
		log.Printf("No %s found — created with defaults. Edit it to customize.", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg map[string]string
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// writeDefaultConfig writes a config.json with localhost defaults and all random secrets.
func writeDefaultConfig(path string) error {
	urlSecret, err := RandomHex(32) // 256-bit HS256 key
	if err != nil {
		return fmt.Errorf("generate delegation_url_secret: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate delegation_header_key: %w", err)
	}
	return writeConfig(path, map[string]string{
		"delegation_url_secret": urlSecret,
		"id_derivation_secret":  NewUUIDv4(),
		"delegation_header_key": hex.EncodeToString([]byte(priv)),
	})
}

// writeConfig serialises cfg as indented JSON and writes it atomically to path (mode 0600).
func writeConfig(path string, cfg map[string]string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

// ensureDelegationSecrets fills in any missing secrets in cfg, writing back if needed.
// Generates missing: delegation_url_secret, id_derivation_secret, delegation_header_key.
func ensureDelegationSecrets(cfg map[string]string, path string) error {
	updated := false

	if cfg["delegation_url_secret"] == "" {
		secret, err := RandomHex(32)
		if err != nil {
			return fmt.Errorf("generate delegation_url_secret: %w", err)
		}
		cfg["delegation_url_secret"] = secret
		updated = true
		log.Printf("Generated delegation_url_secret")
	}

	if cfg["id_derivation_secret"] == "" {
		cfg["id_derivation_secret"] = NewUUIDv4()
		updated = true
		log.Printf("Generated id_derivation_secret")
	}

	if cfg["delegation_header_key"] == "" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate delegation_header_key: %w", err)
		}
		cfg["delegation_header_key"] = hex.EncodeToString([]byte(priv))
		updated = true
		log.Printf("Generated delegation_header_key")
	}

	if updated {
		if err := writeConfig(path, cfg); err != nil {
			return fmt.Errorf("write config: %w", err)
		}
	}
	return nil
}
