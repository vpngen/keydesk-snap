package crypto

import (
	"errors"
)

var (
	ErrKeyNotFound     = errors.New("key not found")
	ErrKeyNotCryptoKey = errors.New("key is not a crypto key")
	ErrKeyNotRSAKey    = errors.New("key is not a RSA key")
)

var (
	ErrSecretTooLong = errors.New("secret too long")
	ErrEmptySecret   = errors.New("empty secret")
)

var (
	ErrDecodePEM = errors.New("unable to decode pem file")
	ErrNoRSAKey  = errors.New("not an RSA private key")
)
