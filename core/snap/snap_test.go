package snap

import (
	"bytes"
	"strings"
	"testing"
)

func Test_compressEcryptSnapshot_decryptDecompressSnapshot(t *testing.T) {
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

			// encrypt
			encrypted, err := CompressEncryptSnapshot(r, []byte(tt.secret))
			if (err != nil) != tt.wantErr {
				t.Errorf("compressEncryptSnapshot() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil {
				return
			}

			// decrypt
			decrypted, err := DecryptDecompressSnapshot(bytes.NewBuffer(encrypted), []byte(tt.secret))
			if (err != nil) != tt.wantErr {
				t.Errorf("decryptDecompressSnapshot() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil {
				return
			}

			// compare
			if string(decrypted) != tt.data {
				t.Errorf("decryptDecompressSnapshot() decrypted = %v, want %v", string(decrypted), tt.data)
			}
		})
	}
}
