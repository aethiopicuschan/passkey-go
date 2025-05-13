package passkey_test

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aethiopicuschan/passkey-go"
)

// IsOnCurveP256 returns true if (x, y) is a valid point on the NIST P-256 curve using crypto/ecdh
func IsOnCurveP256(x, y *big.Int) bool {
	curve := ecdh.P256()

	byteLen := (elliptic.P256().Params().BitSize + 7) >> 3
	encoded := make([]byte, 1+2*byteLen)
	encoded[0] = 4
	x.FillBytes(encoded[1 : 1+byteLen])
	y.FillBytes(encoded[1+byteLen:])
	_, err := curve.NewPublicKey(encoded)
	return err == nil
}

func TestConvertCOSEKeyToECDSA(t *testing.T) {
	// Generate valid X, Y on P-256 curve
	x, y := elliptic.P256().Params().Gx.Bytes(), elliptic.P256().Params().Gy.Bytes()

	validCOSE := map[int]any{
		1:  2, // kty: EC2
		-1: 1, // crv: P-256
		-2: x, // x coordinate
		-3: y, // y coordinate
	}

	tests := []struct {
		name      string
		coseKey   map[int]any
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
			coseKey: map[int]any{
				-1: 1, -2: x, -3: y,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrUnsupportedKeyType,
		},
		{
			name: "unsupported kty",
			coseKey: map[int]any{
				1: 99, -1: 1, -2: x, -3: y,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrUnsupportedKeyType,
		},
		{
			name: "unsupported crv",
			coseKey: map[int]any{
				1: 2, -1: 99, -2: x, -3: y,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrUnsupportedKeyType,
		},
		{
			name: "missing x",
			coseKey: map[int]any{
				1: 2, -1: 1, -3: y,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidCOSEKey,
		},
		{
			name: "missing y",
			coseKey: map[int]any{
				1: 2, -1: 1, -2: x,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidCOSEKey,
		},
		{
			name: "x is not []byte",
			coseKey: map[int]any{
				1: 2, -1: 1, -2: 123, -3: y,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidCOSEKey,
		},
		{
			name: "y is not []byte",
			coseKey: map[int]any{
				1: 2, -1: 1, -2: x, -3: "not-bytes",
			},
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidCOSEKey,
		},
		{
			name: "point not on curve",
			coseKey: map[int]any{
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
				assert.True(t, IsOnCurveP256(pub.X, pub.Y))
			}
		})
	}
}
