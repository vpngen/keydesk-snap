package crypto

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/vpngen/keydesk-snap/core"
)

const (
	DefaultAuthoritiesKeysFileName = "authorities_keys"
	SharedThreshold                = 1
)

// RSAPublicKey is a map of RSA public keys.
type RSAPublicKey struct {
	Key         *rsa.PublicKey
	FingerPrint string
}

// RSAPrivate is a map of RSA private keys.
type RSAPrivateKeys struct {
	Key         *rsa.PrivateKey
	FingerPrint string
}

// EncryptSecretForAuthorities encrypts the secret with each authority's public key.
// The result is a map of encrypted secrets and authority fingerprints.
func EncryptSecretForAuthorities(auths []*RSAPublicKey, secret []byte) (core.EncryptedSecretPair, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}

	encryptedSecrets := make(core.EncryptedSecretPair)

	for _, auth := range auths {
		encryptedSecret, err := EncryptSecret(auth.Key, secret)
		if err != nil {
			return nil, fmt.Errorf("encrypt secret: %w", err)
		}

		encryptedSecrets[auth.FingerPrint] = base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(encryptedSecret)
	}

	return encryptedSecrets, nil
}

// DecryptRSAEncodedSecret decrypts an encoded encrypted secret using a RSA private key.
// The result is aт original secret.
func DecryptRSAEncodedSecret(key *rsa.PrivateKey, encodedEncryptedSecret string) ([]byte, error) {
	encryptedSecret, err := base64.StdEncoding.DecodeString(encodedEncryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted secret: %w", err)
	}

	secret, err := DecryptSecret(key, encryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}

	return secret, nil
}
