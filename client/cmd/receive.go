package cmd

import (
	"EFSS/client/api"
	"EFSS/client/config"
	"EFSS/client/crypto"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var outputPath string
var privKeyPath string

// receiveCmd represents the receive command
var receiveCmd = &cobra.Command{
	Use:   "receive <message-id>",
	Short: "Download, verifies and decrypt an inbox message",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		messageID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("Invalid message id: %w", err)
		}

		// 1. Scarica il messaggio dal server
		result, err := api.DownloadMessage(messageID)
		if err != nil {
			return fmt.Errorf("Error: %w", err)
		}

		encryptedBlob, _ := base64.StdEncoding.DecodeString(result.EncryptedBlob)
		signature, _ := base64.StdEncoding.DecodeString(result.Signature)
		encryptedKey, _ := base64.StdEncoding.DecodeString(result.EncryptedSymmetricKey)

		// 2. Decifra la chiave simmetrica con la propria chiave privata locale
		fmt.Printf("Password: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("Error: %w", err)
		}
		if len(privKeyPath) == 0 {
			privKeyPath, err = config.PrivateKeyPath()
			if err != nil {
				return fmt.Errorf("Can't obtain private key from default path: %w", err)
			}
		}
		symmetricKey, err := crypto.UnwrapSymmetricKey(privKeyPath, password, encryptedKey)
		if err != nil {
			return fmt.Errorf("Key decryption error: %w", err)
		}

		// 3. Decifra il file
		fileData, err := crypto.Decrypt(encryptedBlob, symmetricKey)
		if err != nil {
			return fmt.Errorf("File decryption error: %w", err)
		}

		// 4. Verifica la firma del mittente
		senderPubKeyB64, err := api.GetPublicKey(result.Sender)
		if err != nil {
			return fmt.Errorf("Unable to get sender key: %w", err)
		}
		senderPubKey, _ := base64.StdEncoding.DecodeString(senderPubKeyB64)
		publicKey, err := crypto.ParsePublicKey(senderPubKey)
		if err != nil {
			return fmt.Errorf("Error parsing public key: %w", err)
		}
		if err := crypto.VerifySignature(encryptedBlob, signature, publicKey); err != nil {
			return fmt.Errorf("Invalid signature: the might have been changed: %w", err)
		}

		// 5. Salva il file decifrato
		outPath := outputPath
		if outPath == "" {
			outPath = result.Filename
		}
		if err := os.WriteFile(outPath, fileData, 0600); err != nil {
			return fmt.Errorf("Error saving file: %w", err)
		}

		fmt.Printf("File received from %s, saved in %s (signature verified)\n", result.Sender, outPath)
		return nil
	},
}

func init() {
	receiveCmd.Flags().StringVarP(&privKeyPath, "keypath", "-p", "", "filepath to the private key used for signing (if different from the default path 'HOMEDIR/.efss/key/private.key.enc')")
	receiveCmd.Flags().StringVarP(&outputPath, "output", "o", "", "output file (default: original name)")
	rootCmd.AddCommand(receiveCmd)
}
