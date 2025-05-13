package passkey

import (
	"encoding/base64"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// AttestationObject represents the parsed CBOR-encoded attestation object returned from the authenticator.
type AttestationObject struct {
	Format               string         `cbor:"fmt"`      // Format specifies the attestation format (e.g., "packed", "fido-u2f").
	AuthData             []byte         `cbor:"authData"` // AuthData contains authenticator data, including the credential public key and metadata.
	AttestationStatement map[string]any `cbor:"attStmt"`  // AttestationStatement includes the attestation statement specific to the format.
}

// ParseAttestationObject decodes a base64-encoded CBOR attestation object string.
// Returns a structured AttestationObject or an error if decoding or parsing fails.
func ParseAttestationObject(attestationB64 string) (*AttestationObject, error) {
	// Decode attestation object from base64 URL encoding.
	raw, err := base64.RawURLEncoding.DecodeString(attestationB64)
	if err != nil {
		return nil, errors.Join(ErrInvalidAttestationFormat, err)
	}

	// Unmarshal CBOR data into the AttestationObject struct.
	var obj AttestationObject
	if err := cbor.Unmarshal(raw, &obj); err != nil {
		return nil, errors.Join(ErrInvalidAttestationFormat, err)
	}

	// Successfully parsed AttestationObject returned.
	return &obj, nil
}
