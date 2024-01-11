package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func Test_EncryptAES256CBC_DecryptAES256CBC(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		secret  string
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    "",
			secret:  "my super secret password",
			wantErr: false,
		},
		{
			name:    "short secret",
			data:    "Lorem ipsum dui.",
			secret:  "",
			wantErr: true,
		},
		{
			name:    "16 bytes data",
			data:    "Lorem ipsum dui.",
			secret:  "my super secret password",
			wantErr: false,
		},
		{
			name:    "20 bytes data",
			data:    "Lorem ipsum viverra.",
			secret:  "my super secret password",
			wantErr: false,
		},
		{
			name:    "100 bytes data",
			data:    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. In laoreet ipsum in mauris ullamcorper nam.",
			secret:  "my super secret password",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.data)
			encrypted := &bytes.Buffer{}

			// encrypt
			err := EncryptAES256CBC(r, encrypted, []byte(tt.secret))
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptAES256CBC() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil {
				return
			}

			decrypted := &bytes.Buffer{}

			// decrypt
			err = DecryptAES256CBC(encrypted, decrypted, []byte(tt.secret))
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptAES256CBC() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil {
				return
			}

			if decrypted.String() != tt.data {
				t.Errorf("DecryptAES256CBC() have = %q, want %q", decrypted.String(), tt.data)
			}
		})
	}
}
