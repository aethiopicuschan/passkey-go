package passkey_test

import (
	"encoding/base64"
	"testing"

	"github.com/aethiopicuschan/passkey-go"
	"github.com/stretchr/testify/assert"
)

func TestGenerateChallenge(t *testing.T) {
	t.Parallel()

	ch, err := passkey.GenerateChallenge()
	assert.NoError(t, err)
	assert.NotEmpty(t, ch)

	decoded, err := base64.RawURLEncoding.DecodeString(ch)
	assert.NoError(t, err)
	assert.Len(t, decoded, 32) // 確実に32バイト
}

func TestCheckChallenge(t *testing.T) {
	type args struct {
		expected string
		received string
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantErrIs error
	}{
		{
			name: "matching challenge",
			args: func() args {
				raw := []byte("test-challenge-1234567890abcdef")
				encoded := base64.RawURLEncoding.EncodeToString(raw)
				return args{
					expected: string(raw),
					received: encoded,
				}
			}(),
			wantErr: false,
		},
		{
			name: "invalid base64 input",
			args: args{
				expected: "anything",
				received: "!!!not_base64",
			},
			wantErr:   true,
			wantErrIs: passkey.ErrChallengeDecode,
		},
		{
			name: "mismatched decoded challenge",
			args: func() args {
				expected := "correct-challenge"
				received := base64.RawURLEncoding.EncodeToString([]byte("wrong-challenge"))
				return args{
					expected: expected,
					received: received,
				}
			}(),
			wantErr:   true,
			wantErrIs: passkey.ErrChallengeMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := passkey.CheckChallenge(tt.args.expected, tt.args.received)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
