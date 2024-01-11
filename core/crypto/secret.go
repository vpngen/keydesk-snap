package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// EncryptSecret encrypts the secret with the public key.
func EncryptSecret(key *rsa.PublicKey, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}

	if len(secret) > key.Size()-11 {
		return nil, ErrSecretTooLong
	}

	encryptedSecret, err := rsa.EncryptPKCS1v15(rand.Reader, key, secret)
	if err != nil {
		return nil, fmt.Errorf("encrypt secret: %w", err)
	}

	return encryptedSecret, nil
}

// DecryptSecret decrypts the secret with the private key.
func DecryptSecret(key *rsa.PrivateKey, encryptedSecret []byte) ([]byte, error) {
	if len(encryptedSecret) == 0 {
		return nil, ErrEmptySecret
	}

	secret, err := rsa.DecryptPKCS1v15(rand.Reader, key, encryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}

	return secret, nil
}

// GenSecret creates a new secret of the specified size.
func GenSecret(sz int) ([]byte, error) {
	secret := make([]byte, sz)

	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("read random: %w", err)
	}

	return secret, nil
}
