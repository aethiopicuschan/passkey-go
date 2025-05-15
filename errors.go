package passkey

// PasskeyError is a structured error with code and field info
type PasskeyError struct {
	Code       string // e.g. "E1001"
	Message    string // human-readable message
	HTTPStatus int    // HTTP status code to return
	Field      string // optional: field name for validation errors
}

func (e *PasskeyError) Error() string {
	return e.Message
}

func (e *PasskeyError) Is(target error) bool {
	t, ok := target.(*PasskeyError)
	return ok && e.Code == t.Code
}

func (e *PasskeyError) ToJSON() map[string]any {
	return map[string]any{
		"error":  e.Message,
		"code":   e.Code,
		"field":  e.Field,
		"status": e.HTTPStatus,
	}
}

// --- Registration Errors ---
var (
	ErrInvalidAttestationFormat = &PasskeyError{"E2001", "invalid attestation format", 400, "attestation"}
	ErrUnsupportedKeyType       = &PasskeyError{"E2002", "unsupported COSE key type", 400, "coseKey"}
	ErrInvalidCOSEKey           = &PasskeyError{"E2003", "invalid COSE key format", 400, "coseKey"}
	ErrPublicKeyParseFailed     = &PasskeyError{"E2004", "failed to parse public key", 400, "publicKey"}
)

// --- Assertion Errors ---
var (
	ErrInvalidClientData = &PasskeyError{"E1001", "invalid clientDataJSON", 400, "clientDataJSON"}
	ErrChallengeMismatch = &PasskeyError{"E1002", "challenge mismatch", 400, "challenge"}
	ErrSignatureInvalid  = &PasskeyError{"E1003", "signature verification failed", 400, ""}
	ErrAuthDataInvalid   = &PasskeyError{"E1004", "invalid authenticator data", 400, "authenticatorData"}
	ErrSignCountReplay   = &PasskeyError{"E1005", "replay attack detected", 400, ""}
	ErrChallengeDecode   = &PasskeyError{"E1006", "failed to decode challenge", 400, "challenge"}
	ErrChallengeGen      = &PasskeyError{"E1007", "failed to generate challenge", 500, ""}
)

// --- Storage / Credential Errors ---
var (
	ErrCredentialNotFound     = &PasskeyError{"E3001", "credential not found", 404, "credentialID"}
	ErrCredentialIDMalformed  = &PasskeyError{"E3002", "credential ID malformed", 400, "credentialID"}
	ErrNotECDSAPublicKey      = &PasskeyError{"E3003", "not an ECDSA public key", 400, "publicKey"}
	ErrPublicKeyMarshalFailed = &PasskeyError{"E3004", "failed to marshal public key", 500, "publicKey"}
)

// --- Credential Creation Errors ---
var (
	ErrCreateOptionsMarshal = &PasskeyError{"E4001", "failed to generate credential creation options", 500, ""}
)

// --- Generic ---
var (
	ErrInternal = &PasskeyError{"E9001", "internal server error", 500, ""}
)
