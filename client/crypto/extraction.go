package crypto

import (
	"crypto/rsa"
	"fmt"
	"os"
)

func ExtractAndVerifyFile(signedFilename string, publicKey *rsa.PublicKey) error {
	signedFile, err := VerifyFile(signedFilename, publicKey)
	if err != nil {
		return fmt.Errorf("Invalid signature: %w", err)
	}
	return os.WriteFile(
		signedFile.Filename,
		signedFile.Content,
		0644,
	)
}
