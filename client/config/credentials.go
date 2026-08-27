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

// SaveToken salva username e token localmente, con permessi
// ristretti (solo il proprietario può leggerlo).
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

	return os.WriteFile(path, data, 0600) // 0600: solo il proprietario può leggere/scrivere
}

// LoadToken legge il token salvato localmente. Ritorna errore
// se l'utente non ha ancora fatto login.
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

// ClearToken cancella le credenziali salvate localmente (usato dal logout).
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
