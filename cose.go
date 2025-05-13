package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
)

// ConvertCOSEKeyToECDSA converts a COSE-formatted public key (used in WebAuthn and Passkeys)
// into a standard Go ecdsa.PublicKey.
func ConvertCOSEKeyToECDSA(coseKey map[int]any) (*ecdsa.PublicKey, error) {
	// Helper function to retrieve an integer value from the COSE key map.
	getInt := func(key int) (int64, error) {
		v, ok := coseKey[key]
		if !ok {
			return 0, fmt.Errorf("missing key %d", key)
		}
		switch val := v.(type) {
		case int:
			return int64(val), nil
		case int64:
			return val, nil
		case uint64:
			return int64(val), nil
		default:
			return 0, fmt.Errorf("unexpected type for key %d: %T", key, v)
		}
	}

	// Validate key type (kty); expected type for EC2 keys is 2.
	kty, err := getInt(1)
	if err != nil || kty != 2 {
		return nil, errors.Join(ErrUnsupportedKeyType, err)
	}

	// Validate curve type (crv); expected curve type for P-256 is 1.
	crv, err := getInt(-1)
	if err != nil || crv != 1 {
		return nil, errors.Join(ErrUnsupportedKeyType, err)
	}

	// Extract raw X coordinate.
	xRaw, ok := coseKey[-2]
	if !ok {
		return nil, errors.Join(ErrInvalidCOSEKey, errors.New("missing x coordinate"))
	}

	// Extract raw Y coordinate.
	yRaw, ok := coseKey[-3]
	if !ok {
		return nil, errors.Join(ErrInvalidCOSEKey, errors.New("missing y coordinate"))
	}

	// Validate and cast X coordinate to []byte.
	x, ok := xRaw.([]byte)
	if !ok {
		return nil, errors.Join(ErrInvalidCOSEKey, fmt.Errorf("x is not []byte: %T", xRaw))
	}

	// Validate and cast Y coordinate to []byte.
	y, ok := yRaw.([]byte)
	if !ok {
		return nil, errors.Join(ErrInvalidCOSEKey, fmt.Errorf("y is not []byte: %T", yRaw))
	}

	// Use elliptic curve P-256 as specified by WebAuthn.
	curve := elliptic.P256()
	X := new(big.Int).SetBytes(x)
	Y := new(big.Int).SetBytes(y)

	params := curve.Params()
	p := params.P
	b := params.B

	// Compute a = -3 mod p (specific to P-256 curve)
	negThree := new(big.Int).Neg(big.NewInt(3))
	a := new(big.Int).Mod(negThree, p)

	// Calculate left side of elliptic curve equation (y² mod p).
	y2 := new(big.Int).Exp(Y, big.NewInt(2), p)

	// Calculate right side of elliptic curve equation (x³ + ax + b mod p).
	x3 := new(big.Int).Exp(X, big.NewInt(3), p)
	ax := new(big.Int).Mul(a, X)
	right := new(big.Int).Add(x3, ax)
	right.Add(right, b)
	right.Mod(right, p)

	// Verify that (x, y) satisfies the elliptic curve equation.
	if y2.Cmp(right) != 0 {
		return nil, ErrPublicKeyParseFailed
	}

	// Return the validated ECDSA public key.
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     X,
		Y:     Y,
	}, nil
}
