package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
)

// Encrypt encrypts the given plaintext using the provided symmetric key.
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// EncryptFile reads the contents of the specified file and encrypts it using the provided symmetric key.
func EncryptFile(filepath string, key []byte) ([]byte, error) {
	text, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return Encrypt(text, key)
}
