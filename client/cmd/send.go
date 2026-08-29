package cmd

import (
	"EFSS/client/api"
	"EFSS/client/config"
	"EFSS/client/crypto"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var recipients string
var symmetricKey string
var CSVSymmetricKeys string
var privateKeyPath string

// sendCmd represents the send command
var sendCmd = &cobra.Command{
	Use:   "send <files> --to <recipients>",
	Short: "Send one or more files (separated by ,) to one or more recipients",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filesPaths := strings.Split(args[0], ",")
		var keys []string
		key := []byte(symmetricKey)
		usernames := strings.Split(recipients, ",")
		if len(key) == 0 {
			keys := strings.Split(encryptionKeysString, ",")
			if len(keys) == 0 {
				key = crypto.GenerateRandomSymmetricKey()
			} else {
				if len(keys) > len(filesPaths) {
					fmt.Println("Warning: More keys provided than files. Extra keys will be ignored.")
				}
				if len(keys) < len(filesPaths) {
					fmt.Println("Warning: Number of keys provided does not match number of files. Using random keys for unmatched files.")
					for i := len(keys); i < len(filesPaths); i++ {
						generated_key := crypto.GenerateRandomSymmetricKey()
						keys = append(keys, string(generated_key))
					}
				}
				for i := 0; i < len(keys); i++ {
					if len(keys[i]) != 32 {
						fmt.Printf("Key %d must be 32 bytes long\n", i+1)
						return
					}
				}
			}
		} else if len(key) != 32 {
			fmt.Println("Key must be 32 bytes.")
			return
		}
		for i, file := range filesPaths {
			symmetric := choosekey(key, keys, i)
			encryptedBlob, err := crypto.EncryptFile(file, symmetric)
			if err != nil {
				fmt.Println("Error: " + err.Error())
				continue
			}
			key := []byte(keypath)
			if len(key) == 0 {
				privateKeyPath, err := config.PrivateKeyPath()
				if err != nil {
					fmt.Println("Error reaching default private key file: " + err.Error())
					return
				}
				key = []byte(privateKeyPath)
			}
			fmt.Printf("Password: ")
			password, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				fmt.Println("Error reading password: " + err.Error())
				return
			}
			fmt.Println()
			privateKey, err := crypto.LoadPrivateKey(string(key), password)
			if err != nil {
				fmt.Println("Error: " + err.Error())
				return
			}
			signature, err := crypto.Sign(encryptedBlob, privateKey)
			if err != nil {
				fmt.Println("Signature error: " + err.Error())
				continue
			}
			var recipientKeys []api.RecipientKey
			for _, username := range usernames {
				username = strings.TrimSpace(username)

				pubKeyB64, err := api.GetPublicKey(username)
				if err != nil {
					fmt.Println("Recipient error " + username + ": " + err.Error())
					return
				}

				pubKey, err := base64.StdEncoding.DecodeString(pubKeyB64)
				if err != nil {
					fmt.Println("Invalid public key for " + username)
					return
				}

				recipientPubKey, err := crypto.ParsePublicKey(pubKey)
				if err != nil {
					fmt.Println("Public key parsing error for " + username + ": " + err.Error())
					return
				}

				encryptedKey, err := crypto.WrapSymmetricKey([]byte(symmetricKey), recipientPubKey)
				if err != nil {
					fmt.Println("Error while crypting symmetric key for " + username + ": " + err.Error())
					return
				}

				recipientKeys = append(recipientKeys, api.RecipientKey{
					Username:              username,
					EncryptedSymmetricKey: base64.StdEncoding.EncodeToString(encryptedKey),
				})
			}
			payload := api.SendPayload{
				Filename:      filepath.Base(file),
				EncryptedBlob: base64.StdEncoding.EncodeToString(encryptedBlob),
				Signature:     base64.StdEncoding.EncodeToString(signature),
				Recipients:    recipientKeys,
			}

			if err := api.SendMessage(payload); err != nil {
				fmt.Println("Error: " + err.Error())
				continue
			}

			fmt.Printf("File sent to: %s\n", strings.Join(usernames, ", "))
		}
	},
}

func init() {

	sendCmd.Flags().StringVarP(&recipients, "to", "t", "", "recipients separated by ,")
	sendCmd.MarkFlagRequired("to")
	sendCmd.Flags().StringVarP(&CSVSymmetricKeys, "Keys", "K", "", "Keys for encryption (32 bytes separated by ,)")
	sendCmd.Flags().StringVarP(&symmetricKey, "key", "k", "", "Key for encryption (32 bytes)")
	sendCmd.MarkFlagsMutuallyExclusive("Keys", "key")
	sendCmd.Flags().StringVarP(&privateKeyPath, "keypath", "-p", "", "filepath to the private key used for signing (if different from the default path 'HOMEDIR/.efss/key/private.key.enc')")

	rootCmd.AddCommand(sendCmd)
}
