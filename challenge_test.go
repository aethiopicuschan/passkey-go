package passkey_test

import (
	"encoding/base64"
	"testing"

	"github.com/aethiopicuschan/passkey-go"
	"github.com/stretchr/testify/assert"
)

func TestCheckChallenge(t *testing.T) {
	type args struct {
		expectedB64 string
		receivedB64 string
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
				b64 := base64.RawURLEncoding.EncodeToString(raw)
				return args{b64, b64}
			}(),
			wantErr: false,
		},
		{
			name: "invalid base64 input",
			args: args{
				expectedB64: "ignored",
				receivedB64: "!!!not_base64",
			},
			wantErr:   true,
			wantErrIs: passkey.ErrChallengeDecode,
		},
		{
			name: "mismatched decoded challenge",
			args: func() args {
				a := base64.RawURLEncoding.EncodeToString([]byte("correct-challenge"))
				b := base64.RawURLEncoding.EncodeToString([]byte("wrong-challenge"))
				return args{a, b}
			}(),
			wantErr:   true,
			wantErrIs: passkey.ErrChallengeMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := passkey.CheckChallenge(tt.args.expectedB64, tt.args.receivedB64)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
