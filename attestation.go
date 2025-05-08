package passkey

import (
	"encoding/base64"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

type AttestationObject struct {
	Format               string         `cbor:"fmt"`
	AuthData             []byte         `cbor:"authData"`
	AttestationStatement map[string]any `cbor:"attStmt"`
}

func ParseAttestationObject(attestationB64 string) (*AttestationObject, error) {
	raw, err := base64.RawURLEncoding.DecodeString(attestationB64)
	if err != nil {
		return nil, errors.Join(ErrInvalidAttestationFormat, err)
	}

	var obj AttestationObject
	if err := cbor.Unmarshal(raw, &obj); err != nil {
		return nil, errors.Join(ErrInvalidAttestationFormat, err)
	}

	return &obj, nil
}
