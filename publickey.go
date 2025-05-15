package passkey

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
)

// PublicKeyRecord stores an ECDSA public key associated with a user's passkey.
// This structure typically represents the credential stored on the server side,
// used for verifying signatures during authentication.
type PublicKeyRecord struct {
	Key *ecdsa.PublicKey // ECDSA public key used for authentication.
}

// ParsePublicKey converts a byte slice containing an ASN.1 DER-encoded public key
func MarshalPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub) // → ASN.1 DER []byte
}

// ParsePublicKey converts a byte slice containing an ASN.1 DER-encoded public key
func UnmarshalPublicKey(data []byte) (pkr PublicKeyRecord, err error) {
	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		err = errors.Join(ErrPublicKeyParseFailed, err)
		return
	}
	key, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		err = errors.Join(ErrNotECDSAPublicKey, err)
	}
	pkr = PublicKeyRecord{
		Key: key,
	}
	return
}
