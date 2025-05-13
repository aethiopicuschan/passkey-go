package passkey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// AssertionResponse represents the structure of an assertion response sent by a client (browser or authenticator device).
type AssertionResponse struct {
	ID       string `json:"id"`    // Credential ID
	Type     string `json:"type"`  // Must be "public-key"
	RawID    string `json:"rawId"` // Base64url-encoded credential ID
	Response struct {
		AuthenticatorData string `json:"authenticatorData"` // Base64url-encoded authenticator data
		ClientDataJSON    string `json:"clientDataJSON"`    // Base64url-encoded client data JSON
		Signature         string `json:"signature"`         // Base64url-encoded signature
		UserHandle        string `json:"userHandle"`        // Optional base64url-encoded user handle
	} `json:"response"`
}

// ParsedAssertion contains all decoded fields from an assertion response.
type ParsedAssertion struct {
	Raw        AssertionResponse
	AuthData   []byte
	ClientData []byte
	Signature  []byte
	UserHandle []byte // may be nil
}

// ParseAssertion parses a JSON-formatted assertion response from a client.
// It returns a ParsedAssertion struct containing decoded data.
func ParseAssertion(jsonBody []byte) (*ParsedAssertion, error) {
	var ar AssertionResponse

	// Parse JSON
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, errors.Join(ErrInvalidClientData, err)
	}

	// Validate type
	if ar.Type != "public-key" {
		return nil, errors.Join(ErrInvalidClientData, fmt.Errorf("unexpected type: %q", ar.Type))
	}

	// Decode AuthenticatorData
	authData, err := base64.RawURLEncoding.DecodeString(ar.Response.AuthenticatorData)
	if err != nil {
		return nil, errors.Join(ErrAuthDataInvalid, err)
	}

	// Decode ClientDataJSON
	clientData, err := base64.RawURLEncoding.DecodeString(ar.Response.ClientDataJSON)
	if err != nil {
		return nil, errors.Join(ErrInvalidClientData, err)
	}

	// Decode Signature (with fallback)
	sig, err := base64.RawURLEncoding.DecodeString(ar.Response.Signature)
	if err != nil {
		sig, err = base64.URLEncoding.DecodeString(ar.Response.Signature)
		if err != nil {
			return nil, errors.Join(ErrSignatureInvalid, err)
		}
	}

	// Decode UserHandle (optional)
	var userHandle []byte
	if ar.Response.UserHandle != "" {
		userHandle, err = base64.RawURLEncoding.DecodeString(ar.Response.UserHandle)
		if err != nil {
			return nil, errors.Join(ErrInvalidClientData, fmt.Errorf("invalid userHandle: %w", err))
		}
	}

	return &ParsedAssertion{
		Raw:        ar,
		AuthData:   authData,
		ClientData: clientData,
		Signature:  sig,
		UserHandle: userHandle,
	}, nil
}

// VerifyAssertion verifies a WebAuthn assertion response.
//
// Parameters:
//   - jsonBody: Raw JSON request body received from the client.
//   - expectedOrigin: Origin string the server expects (e.g. "https://example.com").
//   - expectedRPID: Relying Party ID string (e.g. "example.com") used to hash and verify authenticator data.
//   - expectedChallenge: The base64url-encoded challenge that was originally issued to the client.
//     This must match the 'challenge' field found in the decoded clientDataJSON.
//     Verifying the challenge ensures that the response corresponds to an ongoing authentication session,
//     and prevents replay attacks or cross-site request forgery.
//   - storedSignCount: The signCount previously stored for this credential, used to detect cloned authenticators.
//   - pubKey: The public key that was originally registered with the credential.
//
// Returns:
// - newSignCount: The updated signCount to store on success.
// - error: nil if valid, or a detailed structured PasskeyError on failure.
func VerifyAssertion(
	jsonBody []byte,
	expectedOrigin string,
	expectedRPID string,
	expectedChallenge string,
	storedSignCount uint32,
	pubKey *ecdsa.PublicKey,
) (uint32, error) {
	// Step 1: Parse assertion
	parsed, err := ParseAssertion(jsonBody)
	if err != nil {
		return 0, errors.Join(ErrInvalidClientData, err)
	}

	// Step 2: Parse and validate clientDataJSON
	clientData, err := ParseClientDataJSON(parsed.ClientData, expectedOrigin)
	if err != nil {
		return 0, errors.Join(ErrInvalidClientData, err)
	}

	// Step 3: Verify challenge
	if err := CheckChallenge(expectedChallenge, clientData.Challenge); err != nil {
		return 0, errors.Join(ErrChallengeMismatch, err)
	}

	// Step 4: Parse and validate authenticatorData
	authData, err := ParseAuthData(parsed.AuthData)
	if err != nil {
		return 0, errors.Join(ErrAuthDataInvalid, err)
	}

	// Step 5: Validate RP ID hash
	expectedHash := sha256.Sum256([]byte(expectedRPID))
	if !equalBytes(authData.RPIDHash, expectedHash[:]) {
		return 0, errors.Join(ErrAuthDataInvalid, fmt.Errorf("RPID hash mismatch"))
	}

	// Step 6: Verify signature
	if err := VerifyAssertionSignature(parsed.AuthData, parsed.ClientData, parsed.Signature, pubKey); err != nil {
		return 0, errors.Join(ErrSignatureInvalid, err)
	}

	// Step 7: Replay protection (signCount)
	if err := CheckSignCount(storedSignCount, authData.SignCount); err != nil {
		return 0, errors.Join(ErrSignCountReplay, err)
	}

	return authData.SignCount, nil
}

// equalBytes compares two byte slices using constant-time comparison.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
