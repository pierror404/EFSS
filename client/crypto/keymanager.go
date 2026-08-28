package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

func GenerateAsymmetricKeys(path string, password []byte) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	// Private key
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	// Derive AES key from the password
	key := argon2.IDKey(
		password,
		salt,
		1,
		64*1024, // memory cost
		4,       // threads
		32,      // key length: 256 bit
	)
	encryptedFile, err := os.Create(path + "/private.key.enc")
	if err != nil {
		return err
	}
	defer encryptedFile.Close()
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	ciphertext, err := Encrypt(privateKeyBytes, key)
	if err != nil {
		return err
	}
	// Structure of the encrypted file:
	// [salt][nonce-ciphertext] (returned by encrypt function)
	if _, err := encryptedFile.Write(salt); err != nil {
		return err
	}
	if _, err := encryptedFile.Write(ciphertext); err != nil {
		return err
	}

	// Public key
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	publicFile, err := os.Create(path + "/public.pem")
	if err != nil {
		return err
	}
	defer publicFile.Close()

	return pem.Encode(publicFile, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	})
}

func GenerateRandomSymmetricKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

func LoadPrivateKey(filename string, password []byte) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(data) < saltSize {
		return nil, fmt.Errorf("Invalid private key file")
	}
	salt := data[:saltSize]
	remaining := data[saltSize:]
	key := argon2.IDKey(
		password,
		salt,
		1,
		64*1024,
		4,
		32,
	)
	privateBytes, err := Decrypt(remaining, key)
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func PublicKeyByUsername(username string) (*rsa.PublicKey, error) {
	// Implementation for loading public key by username
	// TODO
	return nil, nil
}
