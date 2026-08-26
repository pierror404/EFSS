package cmd

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

const saltSize = 16

func generateRandom32BytesKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

/*
 * ENCRYPTION
 */

func encryption(plaintext []byte, key []byte) ([]byte, error) {
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

func encryptfile(filepath string, key []byte) ([]byte, error) {
	text, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return encryption(text, key)
}

/*
 * DECRYPTION
 */

func decryption(ciphertext []byte, key []byte) ([]byte, error) {
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

func decryptfile(filepath string, key []byte) ([]byte, error) {
	ciphertext, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return decryption(ciphertext, key)
}

/*
 * KEY GENERATION AFTER REGISTRATION
 */
func generatekeys(path string, password []byte) error {
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
	ciphertext, err := encryptfile(path+"/private.key", key)
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

/*
 * LOAD PRIVATE KEY
 */
func loadPrivateKey(filename string, password []byte) (*rsa.PrivateKey, error) {
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
	privateBytes, err := decryption(remaining, key)
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

/*
 * LOAD PUBLIC KEY
 */
func getPublicKeyByUsername(username string) (*rsa.PublicKey, error) {
	// Implementation for loading public key by username
	return nil, nil
}

/*
 * SIGNING
 */
func signFile(filepath string, privateKey *rsa.PrivateKey) ([]byte, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(data)

	signature, err := rsa.SignPSS(
		rand.Reader,
		privateKey,
		crypto.SHA256,
		hash[:],
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	)

	if err != nil {
		return nil, err
	}

	return signature, nil
}

/*
 * VERIFY SIGNATURE
 */
func verifyFile(filename string, signature []byte, publicKey *rsa.PublicKey) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(data)

	return rsa.VerifyPSS(
		publicKey,
		crypto.SHA256,
		hash[:],
		signature,
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	)
}
