package passkey_test

import (
	"testing"

	"github.com/aethiopicuschan/passkey-go"
	"github.com/stretchr/testify/assert"
)

func TestCheckSignCount(t *testing.T) {
	tests := []struct {
		name      string
		old       uint32
		new       uint32
		wantErr   bool
		wantErrIs error
	}{
		{
			name:    "initial value both zero → no error",
			old:     0,
			new:     0,
			wantErr: false,
		},
		{
			name:    "valid increment",
			old:     1,
			new:     2,
			wantErr: false,
		},
		{
			name:      "replay attack (same value)",
			old:       5,
			new:       5,
			wantErr:   true,
			wantErrIs: passkey.ErrSignCountReplay,
		},
		{
			name:      "replay attack (decremented)",
			old:       10,
			new:       7,
			wantErr:   true,
			wantErrIs: passkey.ErrSignCountReplay,
		},
	}

	for _, tt := range tests {
		tt := tt // capture loop variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := passkey.CheckSignCount(tt.old, tt.new)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
