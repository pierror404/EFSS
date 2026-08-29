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
	Run: func(cmd *cobra.Command, args []string) {
		messageID, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println("Invalid message id: " + err.Error())
			return
		}

		// 1. Scarica il messaggio dal server
		result, err := api.DownloadMessage(messageID)
		if err != nil {
			fmt.Println("Error: " + err.Error())
			return
		}

		encryptedBlob, _ := base64.StdEncoding.DecodeString(result.EncryptedBlob)
		signature, _ := base64.StdEncoding.DecodeString(result.Signature)
		encryptedKey, _ := base64.StdEncoding.DecodeString(result.EncryptedSymmetricKey)

		// 2. Decifra la chiave simmetrica con la propria chiave privata locale
		fmt.Printf("Password: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Println("Error: " + err.Error())
			return
		}
		if len(privKeyPath) == 0 {
			privKeyPath, err = config.PrivateKeyPath()
			if err != nil {
				fmt.Println("Can't obtain private key from default path.")
				return
			}
		}
		symmetricKey, err := crypto.UnwrapSymmetricKey(privKeyPath, password, encryptedKey)
		if err != nil {
			fmt.Println("Key decryption error: " + err.Error())
			return
		}

		// 3. Decifra il file
		fileData, err := crypto.Decrypt(encryptedBlob, symmetricKey)
		if err != nil {
			fmt.Println("File decryption error: " + err.Error())
			return
		}

		// 4. Verifica la firma del mittente
		senderPubKeyB64, err := api.GetPublicKey(result.Sender)
		if err != nil {
			fmt.Println("Unable to get sender key: " + err.Error())
			return
		}
		senderPubKey, _ := base64.StdEncoding.DecodeString(senderPubKeyB64)
		publicKey, err := crypto.ParsePublicKey(senderPubKey)
		if err != nil {
			fmt.Println("Error parsing public key: " + err.Error())
			return
		}
		if err := crypto.VerifySignature(encryptedBlob, signature, publicKey); err != nil {
			fmt.Println("Invalid signature: the might have been changed.")
			return
		}

		// 5. Salva il file decifrato
		outPath := outputPath
		if outPath == "" {
			outPath = result.Filename
		}
		if err := os.WriteFile(outPath, fileData, 0600); err != nil {
			fmt.Println("Error saving file: " + err.Error())
			return
		}

		fmt.Printf("File received from %s, saved in %s (signature verified)\n", result.Sender, outPath)
	},
}

func init() {
	receiveCmd.Flags().StringVarP(&privKeyPath, "keypath", "-p", "", "filepath to the private key used for signing (if different from the default path 'HOMEDIR/.efss/key/private.key.enc')")
	receiveCmd.Flags().StringVarP(&outputPath, "output", "o", "", "output file (default: original name)")
	rootCmd.AddCommand(receiveCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// receiveCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// receiveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
