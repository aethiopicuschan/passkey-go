package passkey

import (
	"encoding/json"
	"errors"
)

type PublicKeyCredentialCreationOptions struct {
	Challenge              string                          `json:"challenge"`
	RP                     RelyingPartyEntity              `json:"rp"`
	User                   UserEntity                      `json:"user"`
	PubKeyCredParams       []PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	Timeout                int                             `json:"timeout,omitempty"`
	Attestation            string                          `json:"attestation,omitempty"`
	AuthenticatorSelection AuthenticatorSelection          `json:"authenticatorSelection,omitempty"`
}

type RelyingPartyEntity struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type UserEntity struct {
	ID          string `json:"id"` // base64url encoded
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PublicKeyCredentialParameters struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"` // -7: ES256, -257: RS256
}

type AuthenticatorSelection struct {
	UserVerification string `json:"userVerification"`
	ResidentKey      string `json:"residentKey,omitempty"`
}

// CreateOptions returns JSON to send to the browser
func CreateOptions(rpID, rpName, userID, userName, displayName, challenge string) ([]byte, error) {
	opts := PublicKeyCredentialCreationOptions{
		Challenge: challenge,
		RP:        RelyingPartyEntity{Name: rpName, ID: rpID},
		User:      UserEntity{ID: userID, Name: userName, DisplayName: displayName},
		PubKeyCredParams: []PublicKeyCredentialParameters{
			{Type: "public-key", Alg: -7},   // ES256
			{Type: "public-key", Alg: -257}, // RS256
		},
		Attestation: "none",
		AuthenticatorSelection: AuthenticatorSelection{
			UserVerification: "preferred",
		},
	}
	b, err := json.Marshal(opts)
	if err != nil {
		return nil, errors.Join(ErrCreateOptionsMarshal, err)
	}
	return b, nil
}
