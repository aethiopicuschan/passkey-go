package passkey_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/aethiopicuschan/passkey-go"
	"github.com/stretchr/testify/assert"
)

func TestCreateOptions(t *testing.T) {
	tests := []struct {
		name        string
		rpID        string
		rpName      string
		userIDRaw   []byte
		userName    string
		displayName string
		challenge   []byte
		wantErr     bool
	}{
		{
			name:        "valid inputs",
			rpID:        "example.com",
			rpName:      "Example",
			userIDRaw:   []byte("userid"),
			userName:    "alice",
			displayName: "Alice A.",
			challenge:   []byte("khligehova"),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encodedChallenge := base64.RawURLEncoding.EncodeToString(tt.challenge)
			encodedUserID := base64.RawURLEncoding.EncodeToString(tt.userIDRaw)

			result, err := passkey.CreateOptions(tt.rpID, tt.rpName, string(tt.userIDRaw), tt.userName, tt.displayName, encodedChallenge)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)

			var parsed map[string]any
			err = json.Unmarshal(result, &parsed)
			assert.NoError(t, err)

			assert.Equal(t, encodedChallenge, parsed["challenge"])
			assert.Equal(t, tt.rpID, parsed["rp"].(map[string]any)["id"])
			assert.Equal(t, tt.rpName, parsed["rp"].(map[string]any)["name"])
			assert.Equal(t, encodedUserID, parsed["user"].(map[string]any)["id"])
			assert.Equal(t, tt.userName, parsed["user"].(map[string]any)["name"])
			assert.Equal(t, tt.displayName, parsed["user"].(map[string]any)["displayName"])
			assert.Equal(t, "none", parsed["attestation"])

			authSel := parsed["authenticatorSelection"].(map[string]any)
			assert.Equal(t, "preferred", authSel["userVerification"])

			params := parsed["pubKeyCredParams"].([]any)
			assert.Len(t, params, 2)
		})
	}
}
