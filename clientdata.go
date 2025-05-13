package passkey

import (
	"encoding/json"
	"errors"
)

// ClientData represents the parsed client-side data from a WebAuthn or Passkey authentication process.
type ClientData struct {
	Type      string `json:"type"`      // Type indicates the operation type, typically "webauthn.create" or "webauthn.get".
	Challenge string `json:"challenge"` // Challenge is a base64-encoded challenge that was originally sent to the client.
	Origin    string `json:"origin"`    // Origin is the origin of the request, e.g., the web application URL.
}

// ParseClientDataJSON parses the provided JSON byte array into a ClientData struct.
// It returns an error if the input data is not valid JSON or does not conform to the expected structure.
func ParseClientDataJSON(data []byte) (*ClientData, error) {
	var cd ClientData
	if err := json.Unmarshal(data, &cd); err != nil {
		return nil, errors.Join(ErrInvalidClientData, err) // Combine and return detailed errors for easier debugging.
	}
	return &cd, nil
}
