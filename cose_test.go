package passkey_test

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aethiopicuschan/passkey-go"
)

func TestConvertCOSEKeyToECDSA(t *testing.T) {
	// Generate valid X, Y on P-256 curve
	x, y := elliptic.P256().Params().Gx.Bytes(), elliptic.P256().Params().Gy.Bytes()

	validCOSE := map[int]interface{}{
		1:  2, // kty: EC2
		-1: 1, // crv: P-256
		-2: x, // x coordinate
		-3: y, // y coordinate
	}

	tests := []struct {
		name      string
		coseKey   map[int]interface{}
		wantErr   bool
		wantErrIs error
	}{
		{
			name:    "valid COSE key",
			coseKey: validCOSE,
			wantErr: false,
		},
		{
			name: "missing kty",
			coseKey: map[int]interface{}{
				-1: 1, -2: x, -3: y,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrUnsupportedKeyType,
		},
		{
			name: "unsupported kty",
			coseKey: map[int]interface{}{
				1: 99, -1: 1, -2: x, -3: y,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrUnsupportedKeyType,
		},
		{
			name: "unsupported crv",
			coseKey: map[int]interface{}{
				1: 2, -1: 99, -2: x, -3: y,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrUnsupportedKeyType,
		},
		{
			name: "missing x",
			coseKey: map[int]interface{}{
				1: 2, -1: 1, -3: y,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidCOSEKey,
		},
		{
			name: "missing y",
			coseKey: map[int]interface{}{
				1: 2, -1: 1, -2: x,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidCOSEKey,
		},
		{
			name: "x is not []byte",
			coseKey: map[int]interface{}{
				1: 2, -1: 1, -2: 123, -3: y,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidCOSEKey,
		},
		{
			name: "y is not []byte",
			coseKey: map[int]interface{}{
				1: 2, -1: 1, -2: x, -3: "not-bytes",
			},
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidCOSEKey,
		},
		{
			name: "point not on curve",
			coseKey: map[int]interface{}{
				1: 2, -1: 1,
				-2: []byte{0x01}, // invalid point
				-3: []byte{0x01},
			},
			wantErr:   true,
			wantErrIs: passkey.ErrPublicKeyParseFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pub, err := passkey.ConvertCOSEKeyToECDSA(tt.coseKey)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				assert.Nil(t, pub)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, pub)
				assert.True(t, elliptic.P256().IsOnCurve(pub.X, pub.Y))
			}
		})
	}
}
