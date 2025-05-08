package passkey

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

func GenerateChallenge() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.Join(ErrChallengeGen, err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func CheckChallenge(expected, receivedB64 string) error {
	receivedDecoded, err := base64.RawURLEncoding.DecodeString(receivedB64)
	if err != nil {
		return errors.Join(ErrChallengeDecode, err)
	}
	if expected != string(receivedDecoded) {
		return ErrChallengeMismatch
	}
	return nil
}
