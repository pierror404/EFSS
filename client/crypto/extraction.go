package crypto

import (
	"crypto/rsa"
	"fmt"
	"os"
)

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
