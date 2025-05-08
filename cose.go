package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
)

func ConvertCOSEKeyToECDSA(coseKey map[int]interface{}) (*ecdsa.PublicKey, error) {
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

	kty, err := getInt(1)
	if err != nil || kty != 2 {
		return nil, errors.Join(ErrUnsupportedKeyType, err)
	}

	crv, err := getInt(-1)
	if err != nil || crv != 1 {
		return nil, errors.Join(ErrUnsupportedKeyType, err)
	}

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

	curve := elliptic.P256()
	X := new(big.Int).SetBytes(x)
	Y := new(big.Int).SetBytes(y)

	params := curve.Params()
	p := params.P
	b := params.B

	// a = -3 (mod p)
	negThree := new(big.Int).Neg(big.NewInt(3))
	a := new(big.Int).Mod(negThree, p)

	// y² mod p
	y2 := new(big.Int).Exp(Y, big.NewInt(2), p)

	// x³ + ax + b mod p
	x3 := new(big.Int).Exp(X, big.NewInt(3), p)
	ax := new(big.Int).Mul(a, X)
	right := new(big.Int).Add(x3, ax)
	right.Add(right, b)
	right.Mod(right, p)

	if y2.Cmp(right) != 0 {
		return nil, ErrPublicKeyParseFailed
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     X,
		Y:     Y,
	}, nil
}
