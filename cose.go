package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math"
	"math/big"
)

// ConvertCOSEKeyToECDSA converts a COSE-formatted public key (used in WebAuthn and Passkeys)
// into a standard Go ecdsa.PublicKey, performing full validation of key parameters.
func ConvertCOSEKeyToECDSA(coseKey map[int]any) (*ecdsa.PublicKey, error) {
	// Helper to extract integer values safely
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
			if val > uint64(math.MaxInt64) {
				return 0, fmt.Errorf("uint64 value too large to fit in int64: %d", val)
			}
			return int64(val), nil
		default:
			return 0, fmt.Errorf("unexpected type for key %d: %T", key, v)
		}
	}

	// Validate kty (1) = 2 (EC2)
	kty, err := getInt(1)
	if err != nil || kty != 2 {
		return nil, errors.Join(ErrUnsupportedKeyType, err)
	}

	// Validate crv (-1) = 1 (P-256)
	crv, err := getInt(-1)
	if err != nil || crv != 1 {
		return nil, errors.Join(ErrUnsupportedKeyType, err)
	}

	// Validate and extract X, Y
	xRaw, ok := coseKey[-2]
	if !ok {
		return nil, errors.Join(ErrInvalidCOSEKey, errors.New("missing x coordinate"))
	}
	yRaw, ok := coseKey[-3]
	if !ok {
		return nil, errors.Join(ErrInvalidCOSEKey, errors.New("missing y coordinate"))
	}

	x, ok := xRaw.([]byte)
	if !ok {
		return nil, errors.Join(ErrInvalidCOSEKey, fmt.Errorf("x is not []byte: %T", xRaw))
	}
	y, ok := yRaw.([]byte)
	if !ok {
		return nil, errors.Join(ErrInvalidCOSEKey, fmt.Errorf("y is not []byte: %T", yRaw))
	}

	X := new(big.Int).SetBytes(x)
	Y := new(big.Int).SetBytes(y)

	curve := elliptic.P256()
	params := curve.Params()

	// Elliptic curve equation: y² ≡ x³ + ax + b (mod p)
	y2 := new(big.Int).Exp(Y, big.NewInt(2), params.P)

	x3 := new(big.Int).Exp(X, big.NewInt(3), params.P)
	ax := new(big.Int).Mul(X, big.NewInt(-3)) // a = -3
	ax.Mod(ax, params.P)

	rhs := new(big.Int).Add(x3, ax)
	rhs.Add(rhs, params.B)
	rhs.Mod(rhs, params.P)

	if y2.Cmp(rhs) != 0 {
		return nil, ErrPublicKeyParseFailed
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     X,
		Y:     Y,
	}, nil
}
