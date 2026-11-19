package passkey_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/aethiopicuschan/passkey-go"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestVerifyRegistration(t *testing.T) {
	const origin, rpID, challenge = "https://example.com", "example.com", "c2VydmVyLWNoYWxsZW5nZQ"
	makeClientData := func(typ, ch, org string) []byte {
		data, err := json.Marshal(passkey.ClientData{Type: typ, Challenge: ch, Origin: org})
		require.NoError(t, err)
		return data
	}
	makeAuthData := func(id []byte, rp string, flags byte) []byte {
		h := sha256.Sum256([]byte(rp))
		var b bytes.Buffer
		b.Write(h[:])
		b.WriteByte(flags)
		_ = binary.Write(&b, binary.BigEndian, uint32(0))
		if flags&0x40 != 0 {
			b.Write(make([]byte, 16))
			_ = binary.Write(&b, binary.BigEndian, uint16(len(id)))
			b.Write(id)
			key, err := cbor.Marshal(map[any]any{int64(1): 2, int64(3): -7, int64(-1): 1, int64(-2): bytes.Repeat([]byte{1}, 32), int64(-3): bytes.Repeat([]byte{2}, 32)})
			require.NoError(t, err)
			b.Write(key)
		}
		return b.Bytes()
	}

	tests := []struct {
		name             string
		typ, ch, org, rp string
		flags            byte
		want             error
	}{
		{name: "valid", typ: "webauthn.create", ch: challenge, org: origin, rp: rpID, flags: 0x41},
		{name: "missing user presence", typ: "webauthn.create", ch: challenge, org: origin, rp: rpID, flags: 0x40, want: passkey.ErrUserPresenceRequired},
		{name: "wrong type", typ: "webauthn.get", ch: challenge, org: origin, rp: rpID, flags: 0x41, want: passkey.ErrRegistrationTypeInvalid},
		{name: "wrong challenge", typ: "webauthn.create", ch: "b3RoZXI", org: origin, rp: rpID, flags: 0x41, want: passkey.ErrChallengeMismatch},
		{name: "wrong origin", typ: "webauthn.create", ch: challenge, org: "https://evil.example", rp: rpID, flags: 0x41, want: passkey.ErrInvalidClientData},
		{name: "wrong rp id", typ: "webauthn.create", ch: challenge, org: origin, rp: "evil.example", flags: 0x41, want: passkey.ErrRegistrationRPIDMismatch},
		{name: "missing attested data", typ: "webauthn.create", ch: challenge, org: origin, rp: rpID, flags: 0, want: passkey.ErrRegistrationDataMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := makeClientData(tt.typ, tt.ch, tt.org)
			got, err := passkey.VerifyRegistration(client, makeAuthData([]byte("credential-id"), tt.rp, tt.flags), origin, rpID, challenge)
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, []byte("credential-id"), got.CredID)
			require.NotEmpty(t, got.PublicKey)
		})
	}
}
