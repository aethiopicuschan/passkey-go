package passkey

import (
	"errors"
	"fmt"
)

// CheckSignCount verifies that the new signCount value is greater than the old one,
// which helps detect cloned authenticators or replay attacks.
//
//   - If both old and new values are 0, the authenticator does not support signCount,
//     so no error is returned.
//   - If the new value is less than or equal to the old one, a potential replay or
//     cloned authenticator is suspected, and an error is returned.
func CheckSignCount(old, new uint32) error {
	if new == 0 && old == 0 {
		// Authenticator does not support signCount → skip verification
		return nil
	}
	if new <= old {
		// signCount did not increase → possible replay attack or cloned authenticator
		return errors.Join(ErrSignCountReplay, fmt.Errorf("new=%d current=%d", new, old))
	}
	return nil
}
