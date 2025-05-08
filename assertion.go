package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

type AssertionResponse struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	RawID    string `json:"rawId"`
	Response struct {
		AuthenticatorData string `json:"authenticatorData"`
		ClientDataJSON    string `json:"clientDataJSON"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

func ParseAssertion(jsonBody []byte) ([]byte, []byte, []byte, error) {
	var ar AssertionResponse
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, nil, nil, errors.Join(ErrInvalidClientData, err)
	}

	authData, err := base64.RawURLEncoding.DecodeString(ar.Response.AuthenticatorData)
	if err != nil {
		return nil, nil, nil, errors.Join(ErrAuthDataInvalid, err)
	}

	clientData, err := base64.RawURLEncoding.DecodeString(ar.Response.ClientDataJSON)
	if err != nil {
		return nil, nil, nil, errors.Join(ErrInvalidClientData, err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(ar.Response.Signature)
	if err != nil {
		sig, err = base64.URLEncoding.DecodeString(ar.Response.Signature)
		if err != nil {
			return nil, nil, nil, errors.Join(ErrSignatureInvalid, err)
		}
	}

	return authData, clientData, sig, nil
}
