package passkey_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aethiopicuschan/passkey-go"
)

func TestParseAssertion(t *testing.T) {
	t.Parallel()

	validAuthData := base64.RawURLEncoding.EncodeToString([]byte("auth-data"))
	validClientData := base64.RawURLEncoding.EncodeToString([]byte("client-data"))
	validSignature := base64.RawURLEncoding.EncodeToString([]byte("signature"))

	type args struct {
		authData   string
		clientData string
		signature  string
		encStdSig  bool
	}

	tests := []struct {
		name      string
		rawBody   []byte
		input     args
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "valid data (raw encoding)",
			input: args{
				authData:   validAuthData,
				clientData: validClientData,
				signature:  validSignature,
			},
			wantErr: false,
		},
		{
			name: "valid data with standard base64 signature fallback",
			input: args{
				authData:   validAuthData,
				clientData: validClientData,
				signature:  base64.URLEncoding.EncodeToString([]byte("signature")),
				encStdSig:  true,
			},
			wantErr: false,
		},
		{
			name:      "invalid JSON",
			rawBody:   []byte(`{"id":`),
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidClientData,
		},
		{
			name: "invalid base64 in authData",
			input: args{
				authData:   "!!!",
				clientData: validClientData,
				signature:  validSignature,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrAuthDataInvalid,
		},
		{
			name: "invalid base64 in clientData",
			input: args{
				authData:   validAuthData,
				clientData: "###",
				signature:  validSignature,
			},
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidClientData,
		},
		{
			name: "invalid base64 in signature (both raw and std fail)",
			input: args{
				authData:   validAuthData,
				clientData: validClientData,
				signature:  "$$$",
			},
			wantErr:   true,
			wantErrIs: passkey.ErrSignatureInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var body []byte
			var err error

			if tt.rawBody != nil {
				body = tt.rawBody
			} else {
				ar := passkey.AssertionResponse{
					ID:    "test-id",
					Type:  "public-key",
					RawID: "test-raw-id",
				}
				ar.Response.AuthenticatorData = tt.input.authData
				ar.Response.ClientDataJSON = tt.input.clientData
				ar.Response.Signature = tt.input.signature
				body, err = json.Marshal(ar)
				assert.NoError(t, err)
			}

			parsed, err := passkey.ParseAssertion(body)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				assert.Nil(t, parsed)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, parsed)
				assert.Equal(t, []byte("auth-data"), parsed.AuthData)
				assert.Equal(t, []byte("client-data"), parsed.ClientData)
				assert.Equal(t, []byte("signature"), parsed.Signature)
			}
		})
	}
}

func generateAssertionRequest(
	t *testing.T,
	privKey *ecdsa.PrivateKey,
	challenge []byte,
	origin string,
	rpID string,
	signCount uint32,
	tamperSig bool,
	tamperOrigin bool,
	tamperChallenge bool,
) ([]byte, *ecdsa.PublicKey, uint32) {
	t.Helper()

	clientChallenge := challenge
	if tamperChallenge {
		clientChallenge = []byte("wrong-challenge")
	}
	clientOrigin := origin
	if tamperOrigin {
		clientOrigin = "https://evil.example.com"
	}
	clientData := map[string]string{
		"type":      "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(clientChallenge),
		"origin":    clientOrigin,
	}
	clientDataJSON, err := json.Marshal(clientData)
	assert.NoError(t, err)

	clientHash := sha256.Sum256(clientDataJSON)

	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := bytes.NewBuffer(nil)
	authData.Write(rpIDHash[:])
	authData.WriteByte(0x01)
	binary.Write(authData, binary.BigEndian, signCount)

	signed := append(authData.Bytes(), clientHash[:]...)
	signedHash := sha256.Sum256(signed)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, signedHash[:])
	assert.NoError(t, err)

	halfOrder := new(big.Int).Rsh(privKey.Params().N, 1)
	if s.Cmp(halfOrder) == 1 {
		s.Sub(privKey.Params().N, s)
	}
	if tamperSig {
		s = new(big.Int).Add(s, big.NewInt(1))
	}

	sigBytes, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	assert.NoError(t, err)

	assertion := map[string]any{
		"id":    "credential-id",
		"type":  "public-key",
		"rawId": "credential-id",
		"response": map[string]string{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData.Bytes()),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"signature":         base64.RawURLEncoding.EncodeToString(sigBytes),
			"userHandle":        "",
		},
	}
	req, err := json.Marshal(assertion)
	assert.NoError(t, err)

	return req, &privKey.PublicKey, signCount
}

func TestVerifyAssertion(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	challenge := []byte("challenge-xyz")
	challengeStr := base64.RawURLEncoding.EncodeToString(challenge) // ← 修正済み
	rpID := "example.com"
	origin := "https://example.com"

	tests := []struct {
		name             string
		tamperSig        bool
		tamperOrigin     bool
		tamperChallenge  bool
		storedSignCount  uint32
		authenticatorInc uint32
		wantErr          bool
		wantErrIs        error
	}{
		{
			name:             "valid",
			storedSignCount:  4,
			authenticatorInc: 5,
			wantErr:          false,
		},
		{
			name:             "wrong signature",
			tamperSig:        true,
			storedSignCount:  4,
			authenticatorInc: 5,
			wantErr:          true,
			wantErrIs:        passkey.ErrSignatureInvalid,
		},
		{
			name:             "wrong origin",
			tamperOrigin:     true,
			storedSignCount:  4,
			authenticatorInc: 5,
			wantErr:          true,
			wantErrIs:        passkey.ErrInvalidClientData,
		},
		{
			name:             "wrong challenge",
			tamperChallenge:  true,
			storedSignCount:  4,
			authenticatorInc: 5,
			wantErr:          true,
			wantErrIs:        passkey.ErrChallengeMismatch,
		},
		{
			name:             "signCount replay",
			storedSignCount:  10,
			authenticatorInc: 8,
			wantErr:          true,
			wantErrIs:        passkey.ErrSignCountReplay,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req, pubKey, _ := generateAssertionRequest(
				t,
				privKey,
				challenge,
				origin,
				rpID,
				tt.authenticatorInc,
				tt.tamperSig,
				tt.tamperOrigin,
				tt.tamperChallenge,
			)

			newCount, err := passkey.VerifyAssertion(
				req,
				origin,
				rpID,
				challengeStr,
				tt.storedSignCount,
				pubKey,
			)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrIs != nil {
					assert.ErrorIs(t, err, tt.wantErrIs)
				}
				assert.Zero(t, newCount)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.authenticatorInc, newCount)
			}
		})
	}
}
