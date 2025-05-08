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
		userID      string
		userName    string
		displayName string
		challenge   string
		wantErr     bool
	}{
		{
			name:        "valid inputs",
			rpID:        "example.com",
			rpName:      "Example",
			userID:      base64.StdEncoding.EncodeToString([]byte("userid")),
			userName:    "alice",
			displayName: "Alice A.",
			challenge:   base64.StdEncoding.EncodeToString([]byte("khligehova")),
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		tt := tt // capture
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := passkey.CreateOptions(tt.rpID, tt.rpName, tt.userID, tt.userName, tt.displayName, tt.challenge)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)

				var parsed map[string]interface{}
				err := json.Unmarshal(result, &parsed)
				assert.NoError(t, err)

				assert.Equal(t, tt.challenge, parsed["challenge"])
				assert.Equal(t, tt.rpID, parsed["rp"].(map[string]interface{})["id"])
				assert.Equal(t, tt.rpName, parsed["rp"].(map[string]interface{})["name"])
				assert.Equal(t, tt.userID, parsed["user"].(map[string]interface{})["id"])
				assert.Equal(t, tt.userName, parsed["user"].(map[string]interface{})["name"])
				assert.Equal(t, tt.displayName, parsed["user"].(map[string]interface{})["displayName"])
				assert.Equal(t, "none", parsed["attestation"])

				authSel := parsed["authenticatorSelection"].(map[string]interface{})
				assert.Equal(t, "preferred", authSel["userVerification"])

				params := parsed["pubKeyCredParams"].([]interface{})
				assert.Len(t, params, 2)
			}
		})
	}
}
