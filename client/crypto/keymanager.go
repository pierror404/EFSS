package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"golang.org/x/crypto/argon2"
)

func GenerateAsymmetricKeys(path string, password []byte) ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	// Private key
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
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
		return nil, err
	}
	defer encryptedFile.Close()
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	ciphertext, err := Encrypt(privateKeyBytes, key)
	if err != nil {
		return nil, err
	}
	// Structure of the encrypted file:
	// [salt][nonce-ciphertext] (returned by encrypt function)
	if _, err := encryptedFile.Write(salt); err != nil {
		return nil, err
	}
	if _, err := encryptedFile.Write(ciphertext); err != nil {
		return nil, err
	}

	// Public key
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	publicFile, err := os.Create(path + "/public.pem")
	if err != nil {
		return publicBytes, err
	}
	defer publicFile.Close()

	return publicBytes, pem.Encode(publicFile, &pem.Block{
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
		return nil, errors.New("Invalid private key file")
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
		return nil, errors.New("Wrong Password!!")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ParsePublicKey(raw []byte) (*rsa.PublicKey, error) {
	pubAny, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, errors.New("Invalid public key.")
	}

	rsaPub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Public key is not RSA type.")
	}

	return rsaPub, nil
}

func ParsePublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("error reading public key file: " + err.Error())
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM public key file")
	}

	pub, err := ParsePublicKey(block.Bytes)

	return pub, nil
}

func WrapSymmetricKey(symmetricKey []byte, recipientPubKey *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		recipientPubKey,
		symmetricKey,
		nil,
	)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func UnwrapSymmetricKey(privateKeyFilename string, password []byte, wrapped []byte) ([]byte, error) {
	privKey, err := LoadPrivateKey(privateKeyFilename, password)
	if err != nil {
		return nil, err
	}

	symmetricKey, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privKey,
		wrapped,
		nil,
	)
	if err != nil {
		return nil, errors.New("Decrypt failure: wrong private key or corrupted data.")
	}

	return symmetricKey, nil
}
