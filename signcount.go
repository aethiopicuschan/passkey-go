package passkey

import (
	"errors"
	"fmt"
)

func CheckSignCount(old, new uint32) error {
	if new == 0 && old == 0 {
		// Authenticator does not support signCount → skip
		return nil
	}
	if new <= old {
		return errors.Join(ErrSignCountReplay, fmt.Errorf("new=%d current=%d", new, old))
	}
	return nil
}
