# Example

This is a simple example demonstrating how to use the `passkey-go` library in a real-world application.
It launches a basic web server to register and authenticate users using passkeys.

## Prerequisites

- Go 1.24.2 or later installed
- One of the following:
  - A web browser that supports WebAuthn (e.g., Chrome, Firefox, Safari)
  - A passkey manager that supports WebAuthn (e.g., 1Password)

## Running the Example

```sh
go run .
```

Then, open your browser and navigate to [http://localhost:8080](http://localhost:8080).
You'll see a simple UI with buttons to register and log in using a passkey.
