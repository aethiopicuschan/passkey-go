package passkey

import (
	"crypto/sha256"
	"errors"
)

// VerifyRegistration verifies the client data and authenticator data in a
// WebAuthn registration response. Call this before trusting or storing the
// credential ID or public key extracted from the attestation object.
// Attestation statement verification (and attestation trust policy) is not
// performed by this function.
func VerifyRegistration(clientDataJSON, authData []byte, expectedOrigin, expectedRPID, expectedChallenge string) (*ParsedAuthData, error) {
	clientData, err := ParseClientDataJSON(clientDataJSON, expectedOrigin)
	if err != nil {
		return nil, err
	}
	if clientData.Type != "webauthn.create" {
		return nil, ErrRegistrationTypeInvalid
	}
	if err := CheckChallenge(expectedChallenge, clientData.Challenge); err != nil {
		return nil, errors.Join(ErrChallengeMismatch, err)
	}
	parsed, err := ParseAuthData(authData)
	if err != nil {
		return nil, err
	}
	if parsed.Flags&0x40 == 0 || len(parsed.CredID) == 0 || parsed.PublicKey == nil {
		return nil, ErrRegistrationDataMissing
	}
	const flagUserPresent = 1 << 0
	if parsed.Flags&flagUserPresent == 0 {
		return nil, ErrUserPresenceRequired
	}
	expectedHash := sha256.Sum256([]byte(expectedRPID))
	if !equalBytes(parsed.RPIDHash, expectedHash[:]) {
		return nil, ErrRegistrationRPIDMismatch
	}
	return parsed, nil
}
