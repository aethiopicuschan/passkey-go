package passkey_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/aethiopicuschan/passkey-go"
)

// TestToLowS verifies that toLowS correctly normalizes S to a low-S form.
func TestToLowS(t *testing.T) {
	curve := elliptic.P256()
	N := curve.Params().N
	halfN := new(big.Int).Rsh(N, 1)

	tests := []struct {
		name     string
		inputS   *big.Int
		expected *big.Int
	}{
		{
			name:     "S below halfN stays the same",
			inputS:   big.NewInt(1),
			expected: big.NewInt(1),
		},
		{
			name:     "S equal to halfN stays the same",
			inputS:   new(big.Int).Set(halfN),
			expected: new(big.Int).Set(halfN),
		},
		{
			name:     "S above halfN is normalized",
			inputS:   new(big.Int).Add(halfN, big.NewInt(1)),
			expected: new(big.Int).Sub(N, new(big.Int).Add(halfN, big.NewInt(1))),
		},
		{
			name:     "S equal to N - 1 is normalized",
			inputS:   new(big.Int).Sub(N, big.NewInt(1)),
			expected: big.NewInt(1),
		},
		{
			name:     "S equal to N is normalized to 0",
			inputS:   new(big.Int).Set(N),
			expected: big.NewInt(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := passkey.ToLowS(tt.inputS, N)
			if got.Cmp(tt.expected) != 0 {
				t.Errorf("ToLowS(%v) = %v; want %v", tt.inputS, got, tt.expected)
			}
		})
	}
}
