package crypto

import (
	"crypto/rsa"
	"fmt"
	"os"
)

// ExtractAndVerifyFile verifies the signature of the specified signed file using the provided public key.
// If the signature is valid, it decrypts the content using the provided symmetric key (if any)
// and writes the decrypted content to a new file with the original filename.
func ExtractAndVerifyFile(signedFilename string, publicKey *rsa.PublicKey, symmetricKey []byte) error {
	signedFile, err := VerifyFile(signedFilename, publicKey)
	if err != nil {
		return fmt.Errorf("Invalid signature: %w", err)
	}
	var content []byte
	if symmetricKey != nil {
		content, err = Decrypt(signedFile.Content, symmetricKey)
		if err != nil {
			return err
		}
	} else {
		content = signedFile.Content
	}
	return os.WriteFile(
		signedFile.Filename,
		content,
		0644,
	)
}
