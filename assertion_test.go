package passkey_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aethiopicuschan/passkey-go"
)

func TestParseAssertion(t *testing.T) {
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
			rawBody:   []byte(`{"id":`), // intentionally malformed JSON
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
				assert.NoError(t, err, "failed to marshal JSON for test")
			}

			authData, clientData, sig, err := passkey.ParseAssertion(body)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				assert.Nil(t, authData)
				assert.Nil(t, clientData)
				assert.Nil(t, sig)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, []byte("auth-data"), authData)
				assert.Equal(t, []byte("client-data"), clientData)
				assert.Equal(t, []byte("signature"), sig)
			}
		})
	}
}
