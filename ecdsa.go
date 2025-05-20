package passkey

import "math/big"

// ToLowS normalizes an ECDSA S value to a canonical low-S form as recommended by FIDO/WebAuthn specifications.
// If S is greater than half the curve order, it is replaced with N - S.
func ToLowS(s *big.Int, curveN *big.Int) *big.Int {
	halfOrder := new(big.Int).Rsh(curveN, 1)
	if s.Cmp(halfOrder) == 1 {
		return new(big.Int).Sub(curveN, s)
	}
	return s
}
