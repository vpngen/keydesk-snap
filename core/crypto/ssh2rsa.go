package crypto

import (
	"bytes"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"path/filepath"

	snapCore "github.com/vpngen/keydesk-snap/core"
	snapHelper "github.com/vpngen/keydesk-snap/core/helper"
	"golang.org/x/crypto/ssh"
)

// ConvSSHPubKeyToRSAPubKey returns the RSA public key from the ssh public key.
func ConvSSHPubKeyToRSAPubKey(key ssh.PublicKey) (*rsa.PublicKey, error) {
	if key == nil {
		return nil, ErrKeyNotFound
	}

	if key.Type() != snapCore.KeyTypeRSA {
		return nil, ErrKeyNotRSAKey
	}

	// extract RSA public key from the ssh public key

	cryptoKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return nil, ErrKeyNotCryptoKey
	}

	pubKeyRSA, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return nil, ErrKeyNotRSAKey
	}

	return pubKeyRSA, nil
}

// GetRSAPublicKeyList returns the list of RSA public keys
// from the authorized_keys format data.
func GetRSAPublicKeysList(data []byte) ([]*RSAPublicKey, error) {
	list := []*RSAPublicKey{}

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

		if key.Type() != snapCore.KeyTypeRSA {
			continue
		}

		pubKeyRSA, err := ConvSSHPubKeyToRSAPubKey(key)
		if err != nil {
			return nil, fmt.Errorf("extract rsa key: %w", err)
		}

		list = append(list, &RSAPublicKey{
			Key:         pubKeyRSA,
			FingerPrint: ssh.FingerprintSHA256(key),
		})
	}

	return list, nil
}

func ReadAuthoritiesPubKeyFile(path string) ([]*RSAPublicKey, error) {
	data, err := snapHelper.ReadFileSafeSize(filepath.Join(path, DefaultAuthoritiesKeysFileName), snapCore.MaxKeysFileSize)
	if err != nil {
		return nil, fmt.Errorf("read keyfile: %w", err)
	}

	keys, err := GetRSAPublicKeysList(data)
	if err != nil {
		return nil, fmt.Errorf("get public RSA key by fingerprint: %w", err)
	}

	return keys, nil
}

func ReadPrivateSSHKeyFile(path string) (*rsa.PrivateKey, error) {
	// Read the private key file
	pemBytes, err := snapHelper.ReadFileSafeSize(path, snapCore.MaxKeysFileSize)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key file: %w", err)
	}

	// Decode the PEM file
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrDecodePEM
	}

	// Convert to ssh.PrivateKey
	sshKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %w", err)
	}

	// Assert type to *rsa.PrivateKey
	rsaKey, ok := sshKey.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrNoRSAKey
	}

	return rsaKey, nil
}
