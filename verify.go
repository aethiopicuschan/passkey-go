package passkey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

type ecdsaSignature struct {
	R, S *big.Int
}

func VerifyAssertionSignature(authData, clientDataJSON, signature []byte, pubKey *ecdsa.PublicKey) error {
	clientHash := sha256.Sum256(clientDataJSON)
	signed := append(authData, clientHash[:]...)

	signedHash := sha256.Sum256(signed)

	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		return errors.Join(ErrSignatureInvalid, fmt.Errorf("asn1 unmarshal failed: %w", err))
	}

	if !ecdsa.Verify(pubKey, signedHash[:], sig.R, sig.S) {
		return ErrSignatureInvalid
	}
	return nil
}
