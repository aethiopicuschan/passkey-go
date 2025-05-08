package passkey_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/aethiopicuschan/passkey-go"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
)

func TestParseAuthData(t *testing.T) {
	makeAuthData := func(withAttested bool, pubKey map[interface{}]interface{}) []byte {
		var buf bytes.Buffer

		// 32 bytes RPID hash (dummy)
		buf.Write(bytes.Repeat([]byte{0x01}, 32))

		// Flags
		flags := byte(0x00)
		if withAttested {
			flags |= 0x40 // attested credential flag
		}
		buf.WriteByte(flags)

		// Signature counter (4 bytes)
		buf.Write([]byte{0x00, 0x00, 0x00, 0x05})

		if withAttested {
			// AAGUID (16 bytes dummy)
			buf.Write(bytes.Repeat([]byte{0x02}, 16))

			// Credential ID length (2 bytes)
			credID := []byte{0x03, 0x04, 0x05}
			credIDLen := uint16(len(credID))
			_ = binary.Write(&buf, binary.BigEndian, credIDLen)

			// Credential ID
			buf.Write(credID)

			// Public Key (COSE Key)
			cborPubKey, err := cbor.Marshal(pubKey)
			if err != nil {
				panic(err)
			}
			buf.Write(cborPubKey)
		}

		return buf.Bytes()
	}

	validCOSEKey := map[interface{}]interface{}{
		int64(1):  2,
		int64(3):  -7,
		int64(-1): []byte{0x20, 0x01},
	}

	tests := []struct {
		name      string
		input     []byte
		wantErr   bool
		wantErrIs error
		check     func(t *testing.T, p *passkey.ParsedAuthData)
	}{
		{
			name:    "valid authData without attestation",
			input:   makeAuthData(false, nil),
			wantErr: false,
			check: func(t *testing.T, p *passkey.ParsedAuthData) {
				assert.Equal(t, byte(0x00), p.Flags)
				assert.Equal(t, uint32(5), p.SignCount)
				assert.Nil(t, p.CredID)
				assert.Nil(t, p.PublicKey)
			},
		},
		{
			name:    "valid authData with attestation",
			input:   makeAuthData(true, validCOSEKey),
			wantErr: false,
			check: func(t *testing.T, p *passkey.ParsedAuthData) {
				assert.Equal(t, byte(0x40), p.Flags)
				assert.Equal(t, uint32(5), p.SignCount)
				assert.Equal(t, []byte{0x03, 0x04, 0x05}, p.CredID)
				assert.NotNil(t, p.PublicKey)

				// COSE key 1: should be uint64(2)
				v, ok := p.PublicKey[1]
				assert.True(t, ok)
				assert.IsType(t, uint64(0), v)
				assert.Equal(t, uint64(2), v)

				// COSE key 3: should be int64(-7)
				v3, ok := p.PublicKey[3]
				assert.True(t, ok)
				assert.IsType(t, int64(0), v3)
				assert.Equal(t, int64(-7), v3)
			},
		},
		{
			name:      "authData too short",
			input:     bytes.Repeat([]byte{0x00}, 10),
			wantErr:   true,
			wantErrIs: passkey.ErrAuthDataInvalid,
		},
		{
			name: "invalid COSE key index type",
			input: func() []byte {
				pubKey := map[interface{}]interface{}{
					"string-key": "value", // invalid key type
				}
				return makeAuthData(true, pubKey)
			}(),
			wantErr:   true,
			wantErrIs: passkey.ErrAuthDataInvalid,
		},
		{
			name: "COSE key index too large",
			input: func() []byte {
				pubKey := map[interface{}]interface{}{
					uint64(^uint(0)): 42, // max uint64, overflow int
				}
				return makeAuthData(true, pubKey)
			}(),
			wantErr:   true,
			wantErrIs: passkey.ErrAuthDataInvalid,
		},
	}

	for _, tt := range tests {
		tt := tt // capture loop variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p, err := passkey.ParseAuthData(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				assert.Nil(t, p)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, p)
				if tt.check != nil {
					tt.check(t, p)
				}
			}
		})
	}
}
