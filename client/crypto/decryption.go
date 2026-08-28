package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
)

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}
	return plaintext, nil
}

func DecryptFile(filepath string, key []byte) ([]byte, error) {
	ciphertext, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return Decrypt(ciphertext, key)
}
