package passkey

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// ecdsaSignature represents a parsed ECDSA signature with R and S components.
// The signature is expected to be in ASN.1 DER format.
type ecdsaSignature struct {
	R, S *big.Int
}

// VerifyAssertionSignature verifies an ECDSA signature for WebAuthn assertion responses.
// It checks that the signature was generated over the concatenation of authenticator data
// and the SHA-256 hash of the clientDataJSON, using the given public key.
//
// Parameters:
// - authData: Raw authenticator data received from the authenticator.
// - clientDataJSON: JSON-encoded client data from the browser.
// - signature: ASN.1 DER encoded ECDSA signature.
// - pubKey: The public key that should have been used to sign the data.
//
// Returns:
// - nil if the signature is valid.
// - ErrSignatureInvalid if the signature is malformed or does not verify.
func VerifyAssertionSignature(authData, clientDataJSON, signature []byte, pubKey *ecdsa.PublicKey) error {
	// Validate the public key
	if pubKey == nil || pubKey.X == nil || pubKey.Y == nil || pubKey.Params() == nil {
		return errors.New("invalid public key")
	}

	// Compute the SHA-256 hash of the clientDataJSON
	clientHash := sha256.Sum256(clientDataJSON)

	// Concatenate authData and clientHash to form the message that was signed
	signed := append(authData, clientHash[:]...)

	// Hash the concatenated data to get the final digest to verify
	signedHash := sha256.Sum256(signed)

	// Parse the ASN.1 DER encoded ECDSA signature into R and S values
	var sig ecdsaSignature
	rest, err := asn1.Unmarshal(signature, &sig)
	if err != nil || len(rest) > 0 {
		return errors.Join(ErrSignatureInvalid, fmt.Errorf("asn1 unmarshal failed or trailing bytes: %w", err))
	}

	// Optional: enforce low-S signature (to prevent malleability)
	halfOrder := new(big.Int).Rsh(pubKey.Params().N, 1)
	if sig.S.Cmp(halfOrder) > 0 {
		return errors.New("signature uses high-S value (not canonical)")
	}

	// Verify the ECDSA signature using the public key and hashed message
	if !ecdsa.Verify(pubKey, signedHash[:], sig.R, sig.S) {
		return ErrSignatureInvalid
	}

	// Signature is valid
	return nil
}
