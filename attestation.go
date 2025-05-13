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

// ParseAttestationObject decodes a base64url-encoded CBOR attestation object string
// and performs minimal structural validation.
func ParseAttestationObject(attestationB64 string) (*AttestationObject, error) {
	// Decode from base64url
	raw, err := base64.RawURLEncoding.DecodeString(attestationB64)
	if err != nil {
		return nil, errors.Join(ErrInvalidAttestationFormat, err)
	}

	// Decode CBOR
	var obj AttestationObject
	if err := cbor.Unmarshal(raw, &obj); err != nil {
		return nil, errors.Join(ErrInvalidAttestationFormat, err)
	}

	// Validate required fields
	if obj.Format == "" {
		return nil, errors.Join(ErrInvalidAttestationFormat, errors.New("missing format"))
	}
	if len(obj.AuthData) == 0 {
		return nil, errors.Join(ErrInvalidAttestationFormat, errors.New("missing authData"))
	}
	if obj.AttestationStatement == nil {
		return nil, errors.Join(ErrInvalidAttestationFormat, errors.New("missing attStmt"))
	}

	return &obj, nil
}
