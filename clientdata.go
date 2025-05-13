package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// ClientData represents the parsed client-side data from a WebAuthn or Passkey authentication process.
type ClientData struct {
	Type      string `json:"type"`      // Operation type: "webauthn.create" or "webauthn.get"
	Challenge string `json:"challenge"` // Base64url-encoded challenge string
	Origin    string `json:"origin"`    // Origin of the request (e.g., "https://example.com")
}

// ParseClientDataJSON parses the input JSON and validates its contents against expectedOrigin.
// It returns a parsed ClientData or an error if parsing or validation fails.
func ParseClientDataJSON(data []byte, expectedOrigin string) (*ClientData, error) {
	var cd ClientData
	if err := json.Unmarshal(data, &cd); err != nil {
		return nil, errors.Join(ErrInvalidClientData, err)
	}

	// Validate Type
	switch cd.Type {
	case "webauthn.create", "webauthn.get":
		// OK
	default:
		return nil, errors.Join(ErrInvalidClientData, fmt.Errorf("unexpected type: %q", cd.Type))
	}

	// Validate Challenge: must be base64url-decodable
	if _, err := base64.RawURLEncoding.DecodeString(cd.Challenge); err != nil {
		return nil, errors.Join(ErrInvalidClientData, fmt.Errorf("invalid challenge encoding: %w", err))
	}

	// Validate Origin: must match expected origin
	if cd.Origin != expectedOrigin {
		return nil, errors.Join(ErrInvalidClientData, fmt.Errorf("unexpected origin: got %q, want %q", cd.Origin, expectedOrigin))
	}

	return &cd, nil
}
