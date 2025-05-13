package passkey

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// GenerateChallenge creates a secure random challenge string, encoded in URL-safe Base64.
func GenerateChallenge() (string, error) {
	buf := make([]byte, 32) // Allocate 32 bytes for the challenge.
	if _, err := rand.Read(buf); err != nil {
		return "", errors.Join(ErrChallengeGen, err) // Return an error if random byte generation fails.
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil // Return the encoded challenge.
}

// CheckChallenge verifies that the received Base64-encoded challenge matches the expected challenge.
func CheckChallenge(expected, receivedB64 string) error {
	// Decode the received challenge from Base64.
	receivedDecoded, err := base64.RawURLEncoding.DecodeString(receivedB64)
	if err != nil {
		return errors.Join(ErrChallengeDecode, err) // Return an error if decoding fails.
	}
	// Check if the decoded received challenge matches the expected challenge.
	if expected != string(receivedDecoded) {
		return ErrChallengeMismatch // Return an error if there's a mismatch.
	}
	return nil // No error means challenges match.
}
