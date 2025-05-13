# passkey-go

[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen?style=flat-square)](/LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/aethiopicuschan/passkey-go.svg)](https://pkg.go.dev/github.com/aethiopicuschan/passkey-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/aethiopicuschan/passkey-go)](https://goreportcard.com/report/github.com/aethiopicuschan/passkey-go)
[![CI](https://github.com/aethiopicuschan/passkey-go/actions/workflows/ci.yaml/badge.svg)](https://github.com/aethiopicuschan/passkey-go/actions/workflows/ci.yaml)

`passkey-go` is a Go library for handling server-side WebAuthn / passkey verification.

It provides low-level parsing and high-level assertion verification compatible with browser APIs like `navigator.credentials`.

## Installation

```sh
go get -u github.com/aethiopicuschan/passkey-go
```

## Usage

### 📌 Challenge Generation

Create a base64url-encoded challenge:

```go
challenge, err := passkey.GenerateChallenge()
```

You must persist this challenge per user during registration or login.

### 🏁 Registration Flow

#### 1. Parse attestation object from client

```go
att, err := passkey.ParseAttestationObject(attestationBase64)
```

#### 2. Parse authenticator data

```go
authData, err := passkey.ParseAuthData(att.AuthData)
```

#### 3. Convert COSE key to ECDSA

```go
pubKey, err := passkey.ConvertCOSEKeyToECDSA(authData.PublicKey)
```

You can now persist:

- `authData.CredID` (base64url-encoded)
- `pubKey` (as *ecdsa.PublicKey)
- `authData.SignCount` (initial counter)


### ✅ Authentication Flow (High-level)

Prefer the high-level API:

```go
newCount, err := passkey.VerifyAssertion(
    rawJSONRequest,     // []byte from the client
    expectedOrigin,     // e.g., "http://localhost:8080"
    expectedRPID,       // e.g., "localhost"
    expectedChallenge,  // base64url-encoded challenge issued to this user
    storedSignCount,    // last known signCount
    pubKey,             // *ecdsa.PublicKey for this credential
)
```

If `err == nil`, then:

- The signature is valid
- `clientData.origin`, `challenge`, and `rpID` match expectations
- `signCount` is newer than stored

Update your stored `signCount` to `newCount`.

### 🛠️ Advanced: Manual Parsing (optional)

You can also verify assertions step-by-step:

```go
parsed, _ := passkey.ParseAssertion(rawBody)
clientData, _ := passkey.ParseClientDataJSON(parsed.ClientData)
_ = passkey.VerifyAssertionSignature(parsed.AuthData, parsed.ClientData, parsed.Signature, pubKey)
authParsed, _ := passkey.ParseAuthData(parsed.AuthData)
_ = passkey.CheckSignCount(stored, authParsed.SignCount)
```

### ⚠️ Error Handling

Use structured `PasskeyError` types to map errors to HTTP responses:

```go
if err := someFn(); err != nil {
	var perr *passkey.PasskeyError
	if errors.As(err, &perr) {
		http.Error(w, perr.Message, perr.HTTPStatus)
		return
	}
	http.Error(w, "internal server error", 500)
}
```

### 📎 Notes

- This library does **not** persist credentials or challenges. You must manage:
  - Challenge issuance and storage
  - User lookup by credential ID
  - RP ID and origin enforcement
- Only **ES256 (ECDSA w/ SHA-256)** is supported (per WebAuthn recommendations).
- Challenge and credential IDs are expected to be base64url-encoded.
- Client requests should follow WebAuthn spec (e.g., from `navigator.credentials.get()`)
- For complete usage examples, please refer to the [`example`](./example) directory.
