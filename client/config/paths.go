package config

import (
	"os"
	"path/filepath"
)

const configDirName = ".efss"

// ConfigDir ritorna il percorso della cartella di configurazione
// dell'utente (es. ~/.myenc), creandola se non esiste.
func ConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(homeDir, configDirName)
	if err := os.MkdirAll(dir, 0700); err != nil { // 0700: solo il proprietario può leggere/scrivere
		return "", err
	}

	return dir, nil
}

func CredentialsPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials"), nil
}

func PrivateKeyPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "keys", "private.key.enc"), nil
}

func PublicKeyPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "keys", "public.pem"), nil
}
