package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func Test_EncryptDecryptSharedSecrets(t *testing.T) {
	const keySize = 4096

	// generate a new RSA key pair
	auth1, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		t.Fatal(err)
	}

	// generate a new RSA key pair
	auth2, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		t.Fatal(err)
	}

	// generate a new RSA key pair
	auth3, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		t.Fatal(err)
	}

	pubAuths := []*RSAPublicKey{
		{
			Key:         &auth1.PublicKey,
			FingerPrint: "auth1",
		},
		{
			Key:         &auth2.PublicKey,
			FingerPrint: "auth2",
		},
		{
			Key:         &auth3.PublicKey,
			FingerPrint: "auth3",
		},
	}

	privAuths := []*RSAPrivateKeys{
		{
			Key:         auth1,
			FingerPrint: "auth1",
		},
		{
			Key:         auth2,
			FingerPrint: "auth2",
		},
		{
			Key:         auth3,
			FingerPrint: "auth3",
		},
	}

	secret := []byte("my password")

	// encrypt a secret
	encryptedSecrets, err := EncryptSecretForAuthorities(pubAuths, secret)
	if err != nil {
		t.Fatal(err)
	}

	for _, auth := range privAuths {
		encodedEncryptedSecret, ok := encryptedSecrets[auth.FingerPrint]
		if !ok {
			t.Errorf("encrypted secret for %s not found", auth.FingerPrint)

			return
		}

		// decrypt the secret
		decryptedSecret, err := DecryptRSAEncodedSecret(auth.Key, encodedEncryptedSecret)
		if err != nil {
			t.Fatal(err)
		}

		if string(decryptedSecret) != string(secret) {
			t.Errorf("decrypted secret = %s, want %s", decryptedSecret, secret)
		}
	}
}
