package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func Test_EncryptDecryptSecret(t *testing.T) {
	// generate a new RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}

	loremIpsum := []byte(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas urna augue, fringilla ut tortor eget, efficitur tempus ante. Praesent dignissim est orci, sit amet vehicula lectus aliquet quis. Curabitur viverra at risus eget scelerisque. Sed pellentesque orci at arcu condimentum tristique. In at dictum enim. Maecenas semper mollis sodales. Fusce euismod porta massa at semper. Suspendisse et laoreet nibh. Nulla commodo egestas leo in molestie. Mauris ligula ex, tincidunt ac condimentum et, mattis mollis nisl quam.`)

	tests := []struct {
		secret  []byte
		wantErr bool
	}{
		{
			[]byte(""),
			true,
		},
		{
			loremIpsum[:key.Size()-1-11],
			false,
		},
		{
			loremIpsum[:key.Size()-11],
			false,
		},
		{
			loremIpsum[:key.Size()+1-11],
			true,
		},
	}

	for _, tt := range tests {
		// encrypt a secret
		encryptedSecret, err := EncryptSecret(&key.PublicKey, tt.secret)
		if (err != nil) != tt.wantErr {
			t.Errorf("EncryptSecret() error = %v, len=%d, ksize: %d, wantErr %v", err, len(tt.secret), key.Size(), tt.wantErr)

			return
		}

		// decrypt the secret
		decryptedSecret, err := DecryptSecret(key, encryptedSecret)
		if (err != nil) != tt.wantErr {
			t.Errorf("DecryptSecret() error = %v, wantErr %v", err, tt.wantErr)

			return
		}

		if len(tt.secret) == 0 && len(decryptedSecret) == 0 {
			continue
		}

		// compare the decrypted secret with the original secret
		if !bytes.Equal(tt.secret, decryptedSecret) != tt.wantErr {
			t.Error("decrypted secret is not equal to the original secret")

			return
		}
	}
}
