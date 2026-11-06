package passkey_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/aethiopicuschan/passkey-go"
	"github.com/stretchr/testify/assert"
)

func TestVerifyAssertionSignature(t *testing.T) {
	// Generate ECDSA key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)
	pubKey := &privKey.PublicKey

	authData := []byte("authenticator-data")
	clientDataJSON := []byte(`{"type":"webauthn.get","challenge":"abc","origin":"https://example.com"}`)

	clientHash := sha256.Sum256(clientDataJSON)
	signed := append(authData, clientHash[:]...)
	signedHash := sha256.Sum256(signed)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, signedHash[:])
	assert.NoError(t, err)

	// Canonicalize S (Low-S)
	halfOrder := new(big.Int).Rsh(privKey.Params().N, 1)
	if s.Cmp(halfOrder) == 1 {
		s.Sub(privKey.Params().N, s)
	}

	sig, err := asn1.Marshal(struct {
		R, S *big.Int
	}{R: r, S: s})
	assert.NoError(t, err)
	zeroR, err := asn1.Marshal(struct{ R, S *big.Int }{R: big.NewInt(0), S: big.NewInt(1)})
	assert.NoError(t, err)
	zeroS, err := asn1.Marshal(struct{ R, S *big.Int }{R: big.NewInt(1), S: big.NewInt(0)})
	assert.NoError(t, err)
	orderR, err := asn1.Marshal(struct{ R, S *big.Int }{R: new(big.Int).Set(privKey.Params().N), S: big.NewInt(1)})
	assert.NoError(t, err)
	orderS, err := asn1.Marshal(struct{ R, S *big.Int }{R: big.NewInt(1), S: new(big.Int).Set(privKey.Params().N)})
	assert.NoError(t, err)
	trailing := append(append([]byte(nil), sig...), 0x00)

	tests := []struct {
		name      string
		authData  []byte
		client    []byte
		sig       []byte
		pub       *ecdsa.PublicKey
		wantErr   bool
		wantErrIs error
	}{
		{
			name:     "valid signature",
			authData: authData,
			client:   clientDataJSON,
			sig:      sig,
			pub:      pubKey,
			wantErr:  false,
		},
		{
			name:      "invalid ASN.1 signature",
			authData:  authData,
			client:    clientDataJSON,
			sig:       []byte{0x01, 0x02, 0x03},
			pub:       pubKey,
			wantErr:   true,
			wantErrIs: passkey.ErrSignatureInvalid,
		},
		{name: "zero R", authData: authData, client: clientDataJSON, sig: zeroR, pub: pubKey, wantErr: true, wantErrIs: passkey.ErrSignatureInvalid},
		{name: "zero S", authData: authData, client: clientDataJSON, sig: zeroS, pub: pubKey, wantErr: true, wantErrIs: passkey.ErrSignatureInvalid},
		{name: "R equals curve order", authData: authData, client: clientDataJSON, sig: orderR, pub: pubKey, wantErr: true, wantErrIs: passkey.ErrSignatureInvalid},
		{name: "S equals curve order", authData: authData, client: clientDataJSON, sig: orderS, pub: pubKey, wantErr: true, wantErrIs: passkey.ErrSignatureInvalid},
		{name: "trailing DER bytes", authData: authData, client: clientDataJSON, sig: trailing, pub: pubKey, wantErr: true, wantErrIs: passkey.ErrSignatureInvalid},
		{
			name:     "signature with wrong key",
			authData: authData,
			client:   clientDataJSON,
			sig:      sig,
			pub: func() *ecdsa.PublicKey {
				k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &k.PublicKey
			}(),
			wantErr:   true,
			wantErrIs: passkey.ErrSignatureInvalid,
		},
		{
			name:      "tampered authData",
			authData:  []byte("tampered-auth-data"),
			client:    clientDataJSON,
			sig:       sig,
			pub:       pubKey,
			wantErr:   true,
			wantErrIs: passkey.ErrSignatureInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := passkey.VerifyAssertionSignature(tt.authData, tt.client, tt.sig, tt.pub)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
