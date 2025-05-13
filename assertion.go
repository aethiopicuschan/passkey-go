package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// AssertionResponse represents the structure of an assertion response sent by a client (browser or authenticator device).
type AssertionResponse struct {
	ID       string `json:"id"`    // ID is the credential identifier.
	Type     string `json:"type"`  // Type is typically "public-key" for passkeys.
	RawID    string `json:"rawId"` // RawID is the base64-encoded credential identifier.
	Response struct {
		AuthenticatorData string `json:"authenticatorData"` // AuthenticatorData contains authenticator-specific data (encoded in base64).
		ClientDataJSON    string `json:"clientDataJSON"`    // ClientDataJSON contains client data, such as origin and challenge (encoded in base64).
		Signature         string `json:"signature"`         // Signature is the cryptographic signature provided by the authenticator (encoded in base64).
		UserHandle        string `json:"userHandle"`        // UserHandle identifies the user associated with the credential (optional, encoded in base64).
	} `json:"response"`
}

// ParseAssertion parses a JSON-formatted assertion response from a client.
// It decodes base64-encoded authenticator data, client data, and the signature.
// Returns decoded authenticator data, client data JSON, signature, or an error if parsing fails.
func ParseAssertion(jsonBody []byte) ([]byte, []byte, []byte, error) {
	var ar AssertionResponse

	// Unmarshal JSON body into AssertionResponse structure.
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, nil, nil, errors.Join(ErrInvalidClientData, err)
	}

	// Decode authenticatorData from base64 URL encoding.
	authData, err := base64.RawURLEncoding.DecodeString(ar.Response.AuthenticatorData)
	if err != nil {
		return nil, nil, nil, errors.Join(ErrAuthDataInvalid, err)
	}

	// Decode clientDataJSON from base64 URL encoding.
	clientData, err := base64.RawURLEncoding.DecodeString(ar.Response.ClientDataJSON)
	if err != nil {
		return nil, nil, nil, errors.Join(ErrInvalidClientData, err)
	}

	// Attempt to decode the signature first with RawURL encoding (no padding).
	sig, err := base64.RawURLEncoding.DecodeString(ar.Response.Signature)
	if err != nil {
		// If RawURL decoding fails, fall back to standard URL encoding (with padding).
		sig, err = base64.URLEncoding.DecodeString(ar.Response.Signature)
		if err != nil {
			return nil, nil, nil, errors.Join(ErrSignatureInvalid, err)
		}
	}

	// Return the decoded authenticator data, client data, and signature.
	return authData, clientData, sig, nil
}
