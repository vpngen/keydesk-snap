package crypto

import (
	_ "embed"
	"testing"
)

//go:embed testdata/authorities_keys
var AuthoritiesKeysSample []byte

//go:embed testdata/realms_keys
var RealmsKeysSample []byte

/*
SHA256:JzLNum+9ePHjqZS/Bc4EfDbeih+kMOsQRNM48XXK4Dg
SHA256:+CNUhfh5XaQ1ao8BYKPaxdRoqd+/YOlrJDNbTOleh+c
SHA256:9lqf2VrjnlaX4S/WtzfwkbhqVY06pSCxB0ZddSJKHjE
SHA256:fNZ5RhoKGVOczwL8oI/d7ikiEuD5S6JSfrp7Xk0hS3c

SHA256:g3+OoyULfxUvOr/JTcpY0ZgIajOqPq+BU8Eff6wHMwk
SHA256:Mq1Y8F3nVzevtJD4bh6ULKTXTrCaPdLijx1TpkwWuBc
*/

func Test_GetPublicRSAKeyByFingerprint(t *testing.T) {
	type args struct {
		data []byte
		fp   string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "Fingerprint not found",
			args:    args{data: AuthoritiesKeysSample, fp: "not-found"},
			wantErr: true,
		},
		{
			name:    "Fingerprint found",
			args:    args{data: AuthoritiesKeysSample, fp: "SHA256:JzLNum+9ePHjqZS/Bc4EfDbeih+kMOsQRNM48XXK4Dg"},
			wantErr: false,
		},
		{
			name:    "Fingerprint found",
			args:    args{data: AuthoritiesKeysSample, fp: "SHA256:+CNUhfh5XaQ1ao8BYKPaxdRoqd+/YOlrJDNbTOleh+c"},
			wantErr: false,
		},
		{
			name:    "Fingerprint found",
			args:    args{data: AuthoritiesKeysSample, fp: "SHA256:9lqf2VrjnlaX4S/WtzfwkbhqVY06pSCxB0ZddSJKHjE"},
			wantErr: true,
		},
		{
			name:    "Fingerprint found",
			args:    args{data: AuthoritiesKeysSample, fp: "SHA256:fNZ5RhoKGVOczwL8oI/d7ikiEuD5S6JSfrp7Xk0hS3c"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPublicRSAKeyByFingerprint(tt.args.data, tt.args.fp)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPublicRSAKeyByFingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
