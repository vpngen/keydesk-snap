package snap

import (
	"bytes"
	"compress/gzip"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	snapCore "github.com/vpngen/keydesk-snap/core"
	snapCrypto "github.com/vpngen/keydesk-snap/core/crypto"
)

type SnapOpts struct {
	BrigadeID    string
	Tag          string
	GlobalSnapAt time.Time
	PSK          []byte
	RealFP       string
	RealmKey     *rsa.PublicKey
	AuthKeys     []*snapCrypto.RSAPublicKey
}

type secretsPack struct {
	LockerSecret []byte
	Secret       []byte
	FinalSecret  []byte
	LocalSnapAt  time.Time
}

const (
	LockerSecretSize = 16
	SecretSize       = 16
)

var ErrEmptyTag = fmt.Errorf("empty tag")

func MakeSnapshot(r io.Reader, opts SnapOpts) ([]byte, error) {
	secrets, err := genSecrets(opts.Tag, opts.BrigadeID, opts.GlobalSnapAt, opts.PSK)
	if err != nil {
		return nil, fmt.Errorf("gen secrets: %w", err)
	}

	encryptedLockerSecret, err := snapCrypto.EncryptSecret(opts.RealmKey, secrets.LockerSecret)
	if err != nil {
		return nil, fmt.Errorf("encrypt locker secret: %w", err)
	}

	encryptedSecrets, err := snapCrypto.EncryptSecretForAuthorities(opts.AuthKeys, secrets.Secret)
	if err != nil {
		return nil, fmt.Errorf("encrypt secrets: %w", err)
	}

	payload, err := CompressEncryptSnapshot(r, secrets.FinalSecret)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}

	encryptedBrigade := &snapCore.EncryptedBrigade{
		Tag:       opts.Tag,
		BrigadeID: opts.BrigadeID,

		GlobalSnapAt: opts.GlobalSnapAt,
		LocalSnapAt:  secrets.LocalSnapAt,

		RealmKeyFP:            opts.RealFP,
		EncryptedLockerSecret: base64.StdEncoding.EncodeToString(encryptedLockerSecret),

		Secrets: encryptedSecrets,

		Payload: base64.StdEncoding.EncodeToString(payload),
	}

	data, err := json.MarshalIndent(encryptedBrigade, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	return data, nil
}

func CompressEncryptSnapshot(r io.Reader, secret []byte) ([]byte, error) {
	w := &bytes.Buffer{}

	if err := func() error {
		rz, wz := io.Pipe()
		gw := gzip.NewWriter(wz)

		go func() {
			defer gw.Close()

			for {
				n, err := io.Copy(gw, r)
				if err != nil {
					gw.Flush()
					wz.CloseWithError(err)

					return
				}

				if n == 0 {
					gw.Flush()
					wz.CloseWithError(io.EOF)

					break
				}

			}
		}()

		if err := snapCrypto.EncryptAES256CBC(rz, w, secret); err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}

		return nil
	}(); err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}

	return w.Bytes(), nil
}

func DecryptDecompressSnapshot(r io.Reader, secret []byte) ([]byte, error) {
	w := &bytes.Buffer{}

	rz, wz := io.Pipe()

	go func() {
		gw, err := gzip.NewReader(rz)
		if err != nil {
			rz.CloseWithError(err)

			return
		}

		defer rz.Close()
		defer gw.Close()

		for {
			n, err := io.Copy(w, gw)
			if err != nil {
				rz.CloseWithError(err)

				return
			}

			if n == 0 {
				rz.CloseWithError(io.EOF)

				break
			}
		}
	}()

	if err := snapCrypto.DecryptAES256CBC(r, wz, secret); err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	wz.Close()

	return w.Bytes(), nil
}

// Final secret: Tag + BrigadeID + [8]byte(unixtime(GlobaSnapAt)) + [8]byte(unixtime(LocalSnapAt)) + PSK + LockerSecret + Secret
func genSecrets(tag string, id string, gt time.Time, psk []byte) (*secretsPack, error) {
	if len(tag) == 0 {
		return nil, ErrEmptyTag
	}

	lt := time.Now()

	locker, err := snapCrypto.GenSecret(LockerSecretSize)
	if err != nil {
		return nil, fmt.Errorf("gen locker secret: %w", err)
	}

	secret, err := snapCrypto.GenSecret(SecretSize)
	if err != nil {
		return nil, fmt.Errorf("gen secret: %w", err)
	}

	finalSecret := make([]byte, 0, len([]byte(tag))+len([]byte(id))+8+8+len(psk)+len(locker)+len(secret))

	finalSecret = fmt.Append(finalSecret, tag, id, gt.Unix(), lt.Unix(), psk, locker, secret)

	return &secretsPack{
		LockerSecret: locker,
		Secret:       secret,
		FinalSecret:  finalSecret,
		LocalSnapAt:  lt,
	}, nil
}
