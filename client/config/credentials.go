package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Credentials struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

// SaveToken saves locally username and token, with restricted
// permissions (only the owner can read it).
func SaveToken(username, token string) error {
	path, err := CredentialsPath()
	if err != nil {
		return err
	}

	creds := Credentials{Username: username, Token: token}
	data, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600) // 0600: only the owner can read/write
}

// LoadToken reads the saved token. Returns an error
// if the user has not logged in yet.
func LoadToken() (string, error) {
	creds, err := LoadCredentials()
	if err != nil {
		return "", err
	}
	return creds.Token, nil
}

func LoadCredentials() (*Credentials, error) {
	path, err := CredentialsPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no login")
		}
		return nil, err
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("corrupted credentials file: %w", err)
	}

	return &creds, nil
}

// ClearToken clears the saved credentials (used by logout).
func ClearToken() error {
	path, err := CredentialsPath()
	if err != nil {
		return err
	}

	err = os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
