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
	makeAuthData := func(withAttested bool, credID []byte, pubKey map[any]any) []byte {
		var buf bytes.Buffer

		// RPID hash (32 bytes)
		buf.Write(bytes.Repeat([]byte{0x01}, 32))

		// Flags
		flags := byte(0x00)
		if withAttested {
			flags |= 0x40
		}
		buf.WriteByte(flags)

		// Sign count
		buf.Write([]byte{0x00, 0x00, 0x00, 0x05})

		if withAttested {
			// AAGUID
			buf.Write(bytes.Repeat([]byte{0x02}, 16))

			// Credential ID length
			_ = binary.Write(&buf, binary.BigEndian, uint16(len(credID)))
			buf.Write(credID)

			// COSE public key
			cborPubKey, err := cbor.Marshal(pubKey)
			if err != nil {
				panic(err)
			}
			buf.Write(cborPubKey)
		}

		return buf.Bytes()
	}

	validCredID := []byte{0x03, 0x04, 0x05}

	validCOSEKey := map[any]any{
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
			name:  "valid authData without attestation",
			input: makeAuthData(false, nil, nil),
			check: func(t *testing.T, p *passkey.ParsedAuthData) {
				assert.Equal(t, byte(0x00), p.Flags)
				assert.Equal(t, uint32(5), p.SignCount)
				assert.Nil(t, p.CredID)
				assert.Nil(t, p.PublicKey)
			},
		},
		{
			name:  "valid authData with attestation",
			input: makeAuthData(true, validCredID, validCOSEKey),
			check: func(t *testing.T, p *passkey.ParsedAuthData) {
				assert.Equal(t, byte(0x40), p.Flags)
				assert.Equal(t, uint32(5), p.SignCount)
				assert.Equal(t, validCredID, p.CredID)

				v, ok := p.PublicKey[1]
				assert.True(t, ok)
				assert.IsType(t, uint64(0), v)
				assert.Equal(t, uint64(2), v)

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
			input: makeAuthData(true, validCredID, map[any]any{
				"invalid-key": 123,
			}),
			wantErr:   true,
			wantErrIs: passkey.ErrAuthDataInvalid,
		},
		{
			name: "COSE key index too large",
			input: makeAuthData(true, validCredID, map[any]any{
				uint64(^uint(0)): 123, // extremely large uint64
			}),
			wantErr:   true,
			wantErrIs: passkey.ErrAuthDataInvalid,
		},
		{
			name:      "credential ID too long",
			input:     makeAuthData(true, bytes.Repeat([]byte{0xAA}, 2000), validCOSEKey),
			wantErr:   true,
			wantErrIs: passkey.ErrAuthDataInvalid,
		},
		{
			name: "credential ID length > buf.Len()",
			input: func() []byte {
				var buf bytes.Buffer
				buf.Write(bytes.Repeat([]byte{0x01}, 32))        // RPID hash
				buf.WriteByte(0x40)                              // flags
				buf.Write([]byte{0x00, 0x00, 0x00, 0x01})        // signCount
				buf.Write(bytes.Repeat([]byte{0x02}, 16))        // AAGUID
				binary.Write(&buf, binary.BigEndian, uint16(10)) // credIDLen = 10
				buf.Write([]byte{0xAA})                          // only 1 byte → underflow
				return buf.Bytes()
			}(),
			wantErr:   true,
			wantErrIs: passkey.ErrAuthDataInvalid,
		},
	}

	for _, tt := range tests {
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
