# passkey-go

[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen?style=flat-square)](/LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/aethiopicuschan/passkey-go.svg)](https://pkg.go.dev/github.com/aethiopicuschan/passkey-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/aethiopicuschan/passkey-go)](https://goreportcard.com/report/github.com/aethiopicuschan/passkey-go)
[![CI](https://github.com/aethiopicuschan/passkey-go/actions/workflows/ci.yaml/badge.svg)](https://github.com/aethiopicuschan/passkey-go/actions/workflows/ci.yaml)

passkey-go is a library that provides backend-side processing for passkeys in Golang.

## Installation

```sh
go get -u github.com/aethiopicuschan/passkey-go
```

## Usage

### 📌 Challenge Generation

Generate a cryptographically secure challenge to be used in registration or authentication.

```go
challenge, err := passkey.GenerateChallenge()
```

### 🏁 Registration Flow

#### 1. Parse the attestation object

```go
attObj, err := passkey.ParseAttestationObject(attestationBase64)
```

#### 2. Parse authenticator data

```go
authData, err := passkey.ParseAuthData(attObj.AuthData)
```

#### 3. Convert COSE key to ECDSA public key

```go
pubKey, err := passkey.ConvertCOSEKeyToECDSA(authData.PublicKey)
```

You can now store `authData.CredID`, `pubKey`, and `authData.SignCount`.

### 🔐 Authentication Flow

#### 1. Parse the assertion JSON from the client

```go
authData, clientDataJSON, signature, err := passkey.ParseAssertion(rawBody)
```

#### 2. Parse client data

```go
clientData, err := passkey.ParseClientDataJSON(clientDataJSON)
```

#### 3. Verify the signature

```go
err := passkey.VerifyAssertionSignature(authData, clientDataJSON, signature, pubKey)
```

#### 4. Parse authenticator data and check the signature counter

```go
authParsed, err := passkey.ParseAuthData(authData)
err = passkey.CheckSignCount(storedCount, authParsed.SignCount)
```

If valid, update your stored signature counter.

### 🔥 Error Handling

Error messages are designed to be descriptive and suitable for HTTP error handling.

```go
if err := someFn(); err != nil {
	var perr *passkey.PasskeyError
	if errors.As(err, &perr) {
		http.Error(w, perr.Message, perr.HTTPStatus)
		return
	}
	// fallback
	http.Error(w, "internal server error", 500)
}
```

## Notes

- This library **does not manage storage or transport**—you are responsible for challenge persistence, origin validation, and HTTPS enforcement.
- This library supports only **ES256** public keys (ECDSA with SHA-256).
- For complete usage examples, please refer to the [`example`](./example) directory.
