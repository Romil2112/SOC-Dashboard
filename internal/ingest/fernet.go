package ingest

import (
	"fmt"

	gofernet "github.com/fernet/fernet-go"
)

// fernetKeys holds the decoded keys loaded from DB_ENCRYPTION_KEY. Nil when
// no key is configured (field encryption disabled, matching Flask's behaviour).
type fernetKeys struct {
	keys []*gofernet.Key
}

// newFernetKeys decodes a base64url-encoded Fernet key string. Returns nil
// (encryption disabled) when keyStr is empty, matching Flask's behaviour when
// DB_ENCRYPTION_KEY is unset.
func newFernetKeys(keyStr string) (*fernetKeys, error) {
	if keyStr == "" {
		return nil, nil
	}
	k, err := gofernet.DecodeKey(keyStr)
	if err != nil {
		return nil, fmt.Errorf("decode fernet key: %w", err)
	}
	return &fernetKeys{keys: []*gofernet.Key{k}}, nil
}

// Encrypt returns the Fernet token for plaintext. Returns plaintext unchanged
// when encryption is disabled (fk == nil), exactly as Flask does when
// DB_ENCRYPTION_KEY is unset.
func (fk *fernetKeys) Encrypt(plaintext string) (string, error) {
	if fk == nil || plaintext == "" {
		return plaintext, nil
	}
	token, err := gofernet.EncryptAndSign([]byte(plaintext), fk.keys[0])
	if err != nil {
		return "", fmt.Errorf("fernet encrypt: %w", err)
	}
	return string(token), nil
}

// encryptField is a nil-safe convenience wrapper over Encrypt that returns an
// empty string for empty input — mirroring encrypt_field() in crypto.py.
func (fk *fernetKeys) encryptField(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	return fk.Encrypt(s)
}
