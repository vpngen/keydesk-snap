package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// AES256KeySize is the size of the AES256 key.
	AES256KeySize = 32
	// OpenSSLSaltSize is the size of the salt used by OpenSSL.
	OpenSSLSaltSize = 8
	// OpenSSLPDKF2Iter is the number of iterations used by OpenSSL.
	OpenSSLPDKF2Iter = 10000
	// OpenSSLSaltedPrefix is the prefix used by OpenSSL.
	OpenSSLSaltedPrefix = "Salted__"
)

// Errors
var (
	ErrEmptyData = errors.New("empty data")
)

// EncryptAES256CBC aes-cbc-encrypts the data with the secret.
// openssl enc -aes-256-cbc -pass zzz ...
func EncryptAES256CBC(r io.Reader, w io.Writer, secret []byte) error {
	if len(secret) == 0 {
		return ErrEmptySecret
	}

	salt, err := generateSalt(OpenSSLSaltSize)
	if err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	key, iv := generateAESKeyIV(secret, salt, OpenSSLPDKF2Iter)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("new cipher: %w", err)
	}

	// write salt
	if err := writeSalt(w, salt); err != nil {
		return fmt.Errorf("write salt: %w", err)
	}

	// encrypt
	mode := cipher.NewCBCEncrypter(block, iv)

	for {
		rbuf := make([]byte, aes.BlockSize)

		n, err := io.ReadFull(r, rbuf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("read full: %w", err)
		}

		if n != aes.BlockSize {
			rbuf, err = pkcs7pad(rbuf[:n], aes.BlockSize)
			if err != nil {
				return fmt.Errorf("pkcs7pad: %w", err)
			}
		}

		wbuf := make([]byte, aes.BlockSize)

		mode.CryptBlocks(wbuf, rbuf)

		if _, err := w.Write(wbuf); err != nil {
			return fmt.Errorf("write: %w", err)
		}

		if n != aes.BlockSize {
			break
		}
	}

	return nil
}

// DecryptAES256CBC aes-cbc-decrypts the data with the secret.
// openssl enc -d -aes-256-cbc -pass zzz ...
func DecryptAES256CBC(r io.Reader, w io.Writer, secret []byte) error {
	if len(secret) == 0 {
		return ErrEmptySecret
	}

	// read salt
	salt, err := readSalt(r)
	if err != nil {
		return fmt.Errorf("read salt: %w", err)
	}

	key, iv := generateAESKeyIV(secret, salt, OpenSSLPDKF2Iter)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("new cipher: %w", err)
	}

	// decrypt
	mode := cipher.NewCBCDecrypter(block, iv)

	prev := []byte(nil) // previous block

	for {
		rbuf := make([]byte, aes.BlockSize)

		n, err := io.ReadFull(r, rbuf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("read full: %w", err)
		}

		if n > 0 && n != aes.BlockSize {
			return fmt.Errorf("%w: block size: %d", io.ErrUnexpectedEOF, n)
		}

		if n == 0 && prev == nil {
			return fmt.Errorf("%w: %d", ErrEmptyData, n)
		}

		wbuf := []byte(nil) // decrypted block

		if prev != nil {
			wbuf = make([]byte, aes.BlockSize)
			mode.CryptBlocks(wbuf, prev)
		}

		switch n {
		case aes.BlockSize:
			prev = rbuf
		case 0:
			wbuf, err = pkcs7strip(wbuf, aes.BlockSize)
			if err != nil {
				return fmt.Errorf("pkcs7strip: %w", err)
			}
		}

		if _, err := w.Write(wbuf); err != nil {
			return fmt.Errorf("write: %w", err)
		}

		if n != aes.BlockSize {
			break
		}
	}

	return nil
}

// generateSalt generates a random salt.
func generateSalt(sz int) ([]byte, error) {
	salt := make([]byte, sz)

	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("read full: %w", err)
	}

	return salt, nil
}

// generateAESKeyIV generates the key and iv for AES256 encryption.
func generateAESKeyIV(secret, salt []byte, iter int) ([]byte, []byte) {
	key := pbkdf2.Key(secret, salt, iter, AES256KeySize+aes.BlockSize, sha256.New)

	return key[:len(key)-aes.BlockSize], key[len(key)-aes.BlockSize:]
}

var ErrSaltPrefixMismatch = errors.New("salt prefix mismatch")

// read salt
func readSalt(r io.Reader) ([]byte, error) {
	buf := make([]byte, len(OpenSSLSaltedPrefix)+OpenSSLSaltSize)

	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read full: %w", err)
	}

	if !bytes.HasPrefix(buf, []byte(OpenSSLSaltedPrefix)) {
		return nil, fmt.Errorf("%w: %s", ErrSaltPrefixMismatch, buf)
	}

	return buf[len(OpenSSLSaltedPrefix):], nil
}

// write salt
func writeSalt(w io.Writer, salt []byte) error {
	if _, err := w.Write([]byte(OpenSSLSaltedPrefix)); err != nil {
		return fmt.Errorf("salted prefix: %w", err)
	}

	if _, err := w.Write(salt); err != nil {
		return fmt.Errorf("salt: %w", err)
	}

	return nil
}

var ErrPKCS7BlockSize = errors.New("invalid pkcs7 block size")

// pkcs7pad add pkcs7 padding.
func pkcs7pad(buf []byte, blockSize int) ([]byte, error) {
	if blockSize <= 1 || blockSize >= 256 {
		return nil, fmt.Errorf("%w %d", ErrPKCS7BlockSize, blockSize)
	} else {
		padLen := blockSize - len(buf)%blockSize
		padding := bytes.Repeat([]byte{byte(padLen)}, padLen)

		return append(buf, padding...), nil
	}
}

var (
	ErrPKCS7DataIsNotAligned = errors.New("is not block-aligned")
	ErrPKCS7InvalidPadding   = errors.New("invalid padding on input")
)

// pkcs7strip remove pkcs7 padding.
func pkcs7strip(buf []byte, blockSize int) ([]byte, error) {
	length := len(buf)
	if length == 0 {
		return nil, ErrEmptyData
	}

	if length%blockSize != 0 {
		return nil, ErrPKCS7DataIsNotAligned
	}

	padLen := int(buf[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)

	if padLen > blockSize || padLen <= 0 || !bytes.HasSuffix(buf, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}

	return buf[:length-padLen], nil
}
