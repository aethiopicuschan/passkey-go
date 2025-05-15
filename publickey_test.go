package passkey_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/aethiopicuschan/passkey-go"
	"github.com/stretchr/testify/assert"
)

func TestMarshalUnmarshalPublicKey(t *testing.T) {

	tests := []struct {
		name       string
		setupKey   func() ([]byte, error) // prepares the input bytes
		wantErr    bool
		expectCode string
	}{
		{
			name: "valid ecdsa public key",
			setupKey: func() ([]byte, error) {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, err
				}
				pkr := passkey.PublicKeyRecord{Key: &priv.PublicKey}
				return passkey.MarshalPublicKey(pkr)
			},
			wantErr:    false,
			expectCode: "",
		},
		{
			name: "invalid ASN.1 data",
			setupKey: func() ([]byte, error) {
				return []byte{0x01, 0x02, 0x03}, nil
			},
			wantErr:    true,
			expectCode: "E2004", // ErrPublicKeyParseFailed
		},
		{
			name: "not an ECDSA public key (RSA instead)",
			setupKey: func() ([]byte, error) {
				// Generate RSA key and marshal it to PKIX DER format
				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, err
				}
				return x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
			},
			wantErr:    true,
			expectCode: "E3003", // ErrNotECDSAPublicKey
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := tt.setupKey()
			assert.NoError(t, err, "setupKey failed")

			result, err := passkey.UnmarshalPublicKey(data)
			if tt.wantErr {
				assert.Error(t, err)
				var perr *passkey.PasskeyError
				if assert.ErrorAs(t, err, &perr) {
					assert.Equal(t, tt.expectCode, perr.Code)
				}
				assert.Nil(t, result.Key)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result.Key)
			}
		})
	}
}
