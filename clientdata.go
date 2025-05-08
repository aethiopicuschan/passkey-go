package passkey

import (
	"encoding/json"
	"errors"
)

type ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func ParseClientDataJSON(data []byte) (*ClientData, error) {
	var cd ClientData
	if err := json.Unmarshal(data, &cd); err != nil {
		return nil, errors.Join(ErrInvalidClientData, err)
	}
	return &cd, nil
}
