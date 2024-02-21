package crypto

import (
	"bytes"
	"crypto/rsa"
	"fmt"

	"github.com/vpngen/keydesk-snap/core"
	"github.com/vpngen/keydesk-snap/core/helper"
	"golang.org/x/crypto/ssh"
)

const (
	DefaultRealmsKeysFileName = "realms_keys"
)

// FindPubKeyInFile returns the public RSA key by fingerprint
// from the authorized_keys format file.
func FindPubKeyInFile(path string, fp string) (*rsa.PublicKey, error) {
	data, err := helper.ReadFileSafeSize(path, core.MaxKeysFileSize)
	if err != nil {
		return nil, fmt.Errorf("read keyfile: %w", err)
	}

	pubKeyRSA, err := GetPublicRSAKeyByFingerprint(data, fp)
	if err != nil {
		return nil, fmt.Errorf("get public RSA key by fingerprint: %w", err)
	}

	return pubKeyRSA, nil
}

// GetPublicRSAKeyByFingerprint returns the public RSA key by fingerprint
// from the authorized_keys format data.
func GetPublicRSAKeyByFingerprint(data []byte, fp string) (*rsa.PublicKey, error) {
	var pubKey ssh.PublicKey

	data = bytes.TrimSpace(data)

	// walk through all keys in the file
	for {
		if len(data) == 0 {
			break
		}

		key, _, _, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}

		// prepare data for next iteration
		data = bytes.TrimSpace(rest)

		if key.Type() != core.KeyTypeRSA {
			continue
		}

		if ssh.FingerprintSHA256(key) == fp {
			pubKey = key

			break
		}
	}

	pubKeyRSA, err := ConvSSHPubKeyToRSAPubKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("extract rsa key: %w", err)
	}

	return pubKeyRSA, nil
}
