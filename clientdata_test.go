package passkey_test

import (
	"encoding/json"
	"testing"

	"github.com/aethiopicuschan/passkey-go"
	"github.com/stretchr/testify/assert"
)

func TestParseClientDataJSON(t *testing.T) {
	valid := passkey.ClientData{
		Type:      "webauthn.create",
		Challenge: "YmFzZTY0dXJsLWNoYWxsZW5nZQ", // base64url("base64url-challenge")
		Origin:    "https://example.com",
	}
	validJSON, err := json.Marshal(valid)
	assert.NoError(t, err)

	tests := []struct {
		name      string
		input     []byte
		want      *passkey.ClientData
		wantErr   bool
		wantErrIs error
	}{
		{
			name:    "valid client data JSON",
			input:   validJSON,
			want:    &valid,
			wantErr: false,
		},
		{
			name:      "invalid JSON syntax",
			input:     []byte(`{"type":`),
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidClientData,
		},
		{
			name:      "empty JSON object",
			input:     []byte(`{}`),
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidClientData,
		},
		{
			name: "invalid type field",
			input: func() []byte {
				c := passkey.ClientData{
					Type:      "invalid-type",
					Challenge: valid.Challenge,
					Origin:    valid.Origin,
				}
				b, _ := json.Marshal(c)
				return b
			}(),
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidClientData,
		},
		{
			name: "invalid base64 challenge",
			input: func() []byte {
				c := passkey.ClientData{
					Type:      "webauthn.get",
					Challenge: "!!!invalid",
					Origin:    valid.Origin,
				}
				b, _ := json.Marshal(c)
				return b
			}(),
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidClientData,
		},
		{
			name: "empty origin",
			input: func() []byte {
				c := passkey.ClientData{
					Type:      "webauthn.get",
					Challenge: valid.Challenge,
					Origin:    "",
				}
				b, _ := json.Marshal(c)
				return b
			}(),
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidClientData,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := passkey.ParseClientDataJSON(tt.input, "https://example.com")

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
