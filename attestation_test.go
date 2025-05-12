package passkey_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aethiopicuschan/passkey-go"
	"github.com/fxamacker/cbor/v2"
)

func TestParseAttestationObject(t *testing.T) {
	validObj := passkey.AttestationObject{
		Format:   "packed",
		AuthData: []byte{0x01, 0x02, 0x03},
		AttestationStatement: map[string]any{
			"alg": -7,
			"sig": []byte{0x04, 0x05, 0x06},
		},
	}

	validCBOR, err := cbor.Marshal(validObj)
	assert.NoError(t, err)
	validEncoded := base64.RawURLEncoding.EncodeToString(validCBOR)

	tests := []struct {
		name        string
		inputBase64 string
		wantErr     bool
		wantErrIs   error
	}{
		{
			name:        "valid attestation",
			inputBase64: validEncoded,
			wantErr:     false,
		},
		{
			name:        "invalid base64 string",
			inputBase64: "!invalid base64!",
			wantErr:     true,
			wantErrIs:   passkey.ErrInvalidAttestationFormat,
		},
		{
			name:        "valid base64 but invalid CBOR",
			inputBase64: base64.RawURLEncoding.EncodeToString([]byte("not-cbor")),
			wantErr:     true,
			wantErrIs:   passkey.ErrInvalidAttestationFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			obj, err := passkey.ParseAttestationObject(tt.inputBase64)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				assert.Nil(t, obj)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, obj)
				assert.Equal(t, validObj.Format, obj.Format)
				assert.Equal(t, validObj.AuthData, obj.AuthData)

				alg, ok := obj.AttestationStatement["alg"].(int64)
				assert.True(t, ok, "alg should be int64")
				assert.Equal(t, int64(-7), alg)

				assert.Equal(t, validObj.AttestationStatement["sig"], obj.AttestationStatement["sig"])
			}
		})
	}
}
