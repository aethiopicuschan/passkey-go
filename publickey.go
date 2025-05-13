package passkey

import "crypto/ecdsa"

// PublicKeyRecord stores an ECDSA public key associated with a user's passkey.
// This structure typically represents the credential stored on the server side,
// used for verifying signatures during authentication.
type PublicKeyRecord struct {
	Key *ecdsa.PublicKey // ECDSA public key used for authentication.
}
