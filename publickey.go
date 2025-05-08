package passkey

import "crypto/ecdsa"

type PublicKeyRecord struct {
	Key *ecdsa.PublicKey
}
