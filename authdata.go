package passkey

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"github.com/fxamacker/cbor/v2"
)

type ParsedAuthData struct {
	RPIDHash  []byte
	Flags     byte
	SignCount uint32
	AAGUID    []byte
	CredID    []byte
	PublicKey map[int]interface{}
}

func ParseAuthData(authData []byte) (*ParsedAuthData, error) {
	if len(authData) < 37 {
		return nil, errors.Join(ErrAuthDataInvalid, errors.New("authData too short"))
	}

	p := &ParsedAuthData{
		RPIDHash:  authData[:32],
		Flags:     authData[32],
		SignCount: binary.BigEndian.Uint32(authData[33:37]),
	}

	if p.Flags&0x40 == 0 {
		return p, nil // no attested credential data
	}

	buf := bytes.NewReader(authData[37:])
	p.AAGUID = make([]byte, 16)
	if _, err := buf.Read(p.AAGUID); err != nil {
		return nil, errors.Join(ErrAuthDataInvalid, err)
	}

	var credIDLen uint16
	if err := binary.Read(buf, binary.BigEndian, &credIDLen); err != nil {
		return nil, errors.Join(ErrAuthDataInvalid, err)
	}

	p.CredID = make([]byte, credIDLen)
	if _, err := buf.Read(p.CredID); err != nil {
		return nil, errors.Join(ErrAuthDataInvalid, err)
	}

	rest, err := io.ReadAll(buf)
	if err != nil {
		return nil, errors.Join(ErrAuthDataInvalid, err)
	}

	var raw map[interface{}]interface{}
	if err := cbor.Unmarshal(rest, &raw); err != nil {
		return nil, errors.Join(ErrAuthDataInvalid, err)
	}

	pk := make(map[int]interface{})
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
