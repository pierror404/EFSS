package config

import (
	"os"
	"path/filepath"
)

const configDirName = ".efss"

// ConfigDir returns the path of the user's configuration folder
// (e.g., ~/.myenc), creating it if it doesn't exist.
func ConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(homeDir, configDirName)
	if err := os.MkdirAll(dir, 0700); err != nil { // 0700: only the owner can read/write
		return "", err
	}

	return dir, nil
}

// CredentialsPath returns the path to the credentials file, which stores the username and token.
func CredentialsPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials"), nil
}

// PrivateKeyPath returns the path to the encrypted private key file.
func PrivateKeyPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "keys", "private.key.enc"), nil
}

// PublicKeyPath returns the path to the public key file.
func PublicKeyPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "keys", "public.pem"), nil
}
