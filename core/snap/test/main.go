package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/vpngen/keydesk-snap/core/snap"
)

func main() {
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
		fmt.Fprintf(os.Stderr, "NAME: %s\n", tt.name)

		r := strings.NewReader(tt.data)

		fmt.Fprintf(os.Stderr, "Encrypt\n")

		// encrypt
		encrypted, err := snap.CompressEncryptSnapshot(r, []byte(tt.secret))
		if (err != nil) != tt.wantErr {
			log.Fatalf("compressEncryptSnapshot() error = %v, wantErr %v", err, tt.wantErr)
		}

		if err != nil {
			return
		}

		fmt.Fprintf(os.Stderr, "Decrtypt\n")

		// decrypt
		decrypted, err := snap.DecryptDecompressSnapshot(bytes.NewBuffer(encrypted), []byte(tt.secret))
		if (err != nil) != tt.wantErr {
			log.Fatalf("decryptDecompressSnapshot() error = %v, wantErr %v", err, tt.wantErr)
		}

		if err != nil {
			return
		}

		// compare
		if string(decrypted) != tt.data {
			log.Fatalf("decryptDecompressSnapshot() decrypted = %v, want %v", string(decrypted), tt.data)
		}
	}
}
