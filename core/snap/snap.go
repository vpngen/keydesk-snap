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
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read all: %w", err)
	}

	rz := &bytes.Buffer{}
	wz := gzip.NewWriter(rz)

	if _, err := bytes.NewBuffer(buf).WriteTo(wz); err != nil {
		return nil, fmt.Errorf("write to: %w", err)
	}

	wz.Flush()
	wz.Close()

	w := &bytes.Buffer{}
	if err := snapCrypto.EncryptAES256CBC(rz, w, secret); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	return w.Bytes(), nil
}

func DecryptDecompressSnapshot(r io.Reader, secret []byte) ([]byte, error) {
	wz := &bytes.Buffer{}

	if err := snapCrypto.DecryptAES256CBC(r, wz, secret); err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	rz, err := gzip.NewReader(wz)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}

	w := &bytes.Buffer{}
	if _, err := w.ReadFrom(rz); err != nil {
		return nil, fmt.Errorf("read from: %w", err)
	}

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
