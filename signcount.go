package passkey

import (
	"errors"
	"fmt"
)

// CheckSignCount verifies that the new signCount value is strictly greater than the old one.
// This helps detect replay attacks or cloned authenticators.
//
// Behavior:
// - If both old and new are 0, the authenticator likely does not support signCount and no error is returned.
// - If the new value is less than or equal to the stored old value, this indicates a possible replay or cloned device.
func CheckSignCount(old, new uint32) error {
	if old == 0 && new == 0 {
		// The authenticator does not support signCount → skip verification.
		return nil
	}
	if new <= old {
		// signCount did not increase → potential replay attack or cloned device.
		return errors.Join(ErrSignCountReplay, fmt.Errorf("signCount replay detected: received=%d, stored=%d", new, old))
	}
	return nil
}
