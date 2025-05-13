package passkey

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// GenerateChallenge creates a secure random challenge string, encoded in URL-safe Base64.
func GenerateChallenge() (string, error) {
	buf := make([]byte, 32) // 32-byte challenge
	if _, err := rand.Read(buf); err != nil {
		return "", errors.Join(ErrChallengeGen, err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// CheckChallenge compares two base64url-encoded challenge strings for exact match.
// If decoding fails or the decoded values do not match, an error is returned.
func CheckChallenge(expectedB64, receivedB64 string) error {
	expectedDecoded, err := base64.RawURLEncoding.DecodeString(expectedB64)
	if err != nil {
		return errors.Join(ErrChallengeDecode, err)
	}
	receivedDecoded, err := base64.RawURLEncoding.DecodeString(receivedB64)
	if err != nil {
		return errors.Join(ErrChallengeDecode, err)
	}
	if len(expectedDecoded) != len(receivedDecoded) {
		return ErrChallengeMismatch
	}
	for i := range expectedDecoded {
		if expectedDecoded[i] != receivedDecoded[i] {
			return ErrChallengeMismatch
		}
	}
	return nil
}
