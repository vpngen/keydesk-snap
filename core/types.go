package core

import "time"

// EncryptedSecretPair is a map of encrypted secrets.
// Key is a RSA key fingerprint, value is a encrypted by the key secret.
type EncryptedSecretPair map[string]string

// EncryptedBrigade is a snapshot of the brigade.
// It contains encrypted payload and encrypted secrets.
// PSK used but not stored in the snapshot.
// Final secret: Tag + [8]byte(unixtime(GlobaSnapAt)) + [8]byte(unixtime(LocalSnapAt)) + PSK + LockerSecret + Secret
type EncryptedBrigade struct {
	// identification tag, using to ident whole snapshot.
	// 2023-01-01T00:00:00Z-regular-quarter-snapshot
	Tag string `json:"tag"`

	// GlobalSnapAt is a time of the global snapshot start.
	// It is used to identify the snapshot.
	GlobalSnapAt time.Time `json:"global_snap_at"`

	BrigadeID   string    `json:"brigade_id"`
	Payload     string    `json:"payload"`
	LocalSnapAt time.Time `json:"local_snap_at"`

	// RealmKeyFP is a fingerprint of the realm public key with which
	// the LockerSecret was encrypted.
	RealmKeyFP string `json:"realm_key_fp"`
	// AuthorityKeyFP is a fingerprint of the authority public key
	// with which the LockerSecret was encrypted.
	AuthorityKeyFP string `json:"authority_key_fp"`
	// LockerSecret is a secret, which is used to concatenate
	// with the main secret and PSK to get the final secret.
	// We need to provide it to decrypt the payload.
	// LockerSecret is encrypted with Realm public key
	// or Authority public key determined by situation.
	EncryptedLockerSecret string `json:"encrypted_locker_secret"`

	// Secrets is a map of encrypted main secrets.
	Secrets EncryptedSecretPair `json:"sss_keys"`
}
