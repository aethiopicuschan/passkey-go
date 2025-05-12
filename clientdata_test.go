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
		Challenge: "base64url-challenge",
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
			input:     []byte(`{"type":`), // broken
			wantErr:   true,
			wantErrIs: passkey.ErrInvalidClientData,
		},
		{
			name:    "empty JSON",
			input:   []byte(`{}`),
			wantErr: false,
			want: &passkey.ClientData{
				Type:      "",
				Challenge: "",
				Origin:    "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := passkey.ParseClientDataJSON(tt.input)

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
