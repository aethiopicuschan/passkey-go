package passkey

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/fxamacker/cbor/v2"
)

// ParsedAuthData represents the parsed WebAuthn authenticator data.
type ParsedAuthData struct {
	RPIDHash  []byte      // SHA-256 hash of the relying party ID.
	Flags     byte        // Flags indicating the state of the authenticator data.
	SignCount uint32      // Signature counter, used to detect cloned authenticators.
	AAGUID    []byte      // Authenticator Attestation GUID (globally unique identifier).
	CredID    []byte      // Credential ID assigned by the authenticator.
	PublicKey map[int]any // Parsed COSE public key.
}

// ParseAuthData parses raw authenticator data bytes into a structured ParsedAuthData object.
func ParseAuthData(authData []byte) (*ParsedAuthData, error) {
	// Authenticator data must be at least 37 bytes long (32 bytes hash, 1 byte flags, 4 bytes signCount).
	if len(authData) < 37 {
		return nil, errors.Join(ErrAuthDataInvalid, errors.New("authData too short"))
	}

	p := &ParsedAuthData{
		RPIDHash:  authData[:32],                            // First 32 bytes are the RP ID hash.
		Flags:     authData[32],                             // The next byte represents flags.
		SignCount: binary.BigEndian.Uint32(authData[33:37]), // The following 4 bytes indicate the signature counter.
	}

	// Check if attested credential data is present (0x40 flag).
	if p.Flags&0x40 == 0 {
		return p, nil // If not present, return parsed data up to this point.
	}

	buf := bytes.NewReader(authData[37:])

	// Read the Authenticator Attestation GUID (AAGUID, 16 bytes).
	p.AAGUID = make([]byte, 16)
	if _, err := buf.Read(p.AAGUID); err != nil {
		return nil, errors.Join(ErrAuthDataInvalid, err)
	}

	// Read the length of the Credential ID.
	var credIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &credIDLen); err != nil {
		return nil, errors.Join(ErrAuthDataInvalid, err)
	}

	// Read the Credential ID based on the length.
	p.CredID = make([]byte, credIDLen)
	if _, err := buf.Read(p.CredID); err != nil {
		return nil, errors.Join(ErrAuthDataInvalid, err)
	}

	// Read the remaining bytes, which contain the COSE-encoded public key.
	rest, err := io.ReadAll(buf)
	if err != nil {
		return nil, errors.Join(ErrAuthDataInvalid, err)
	}

	// Unmarshal the CBOR-encoded public key into a generic map.
	var raw map[any]any
	if err := cbor.Unmarshal(rest, &raw); err != nil {
		return nil, errors.Join(ErrAuthDataInvalid, err)
	}

	// Convert the COSE key map keys to integers, ensuring valid types and range.
	pk := make(map[int]any)
	for k, v := range raw {
		switch kt := k.(type) {
		case int64:
			pk[int(kt)] = v
		case uint64:
			if kt > math.MaxInt {
				return nil, errors.Join(ErrAuthDataInvalid, errors.New("COSE key index too large"))
			}
			pk[int(kt)] = v
		default:
			return nil, errors.Join(ErrAuthDataInvalid, errors.New("unexpected COSE key type"))
		}
	}
	p.PublicKey = pk

	return p, nil
}
