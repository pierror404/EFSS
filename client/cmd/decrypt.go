package cmd

import (
	"efss-client/crypto"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var decryptionKeyString string
var decryptionKeysString string
var decryptionOutputs string

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt <filenames> [-k <key> | -K <keys>] [flags]",
	Short: "Decrypt one or more file (separated by ,) by AES-256, using the provided key for all files",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filesPaths := strings.Split(args[0], ",")
		outputPaths := splitString(encryptionOutputs, ",")
		if len(outputPaths) > len(filesPaths) {
			fmt.Println("Warning: More output paths than input files. Extra output paths will be ignored.")
		}
		if len(outputPaths) < len(filesPaths) {
			fmt.Println("Warning: Fewer output paths than input files. Remaning files will be decrypted on stdout.")
		}
		var key []byte = []byte(decryptionKeyString)
		var keys []string
		if len(key) == 0 {
			keys = strings.Split(decryptionKeysString, ",")
			if len(keys) == 0 {
				fmt.Printf("Provide the 32 bytes key to decrypt all files: ")
				fmt.Scanf("%s", &decryptionKeyString)
				key = []byte(decryptionKeyString)
				if len(key) != 32 {
					return fmt.Errorf("Key must be 32 bytes long")
				}
			} else {
				if len(keys) != len(filesPaths) {
					return fmt.Errorf("Number of keys must match number of files")
				}
				for i := 0; i < len(keys); i++ {
					if len(keys[i]) != 32 {
						return fmt.Errorf("Key %d must be 32 bytes long\n", i+1)
					}
				}
			}
		} else {
			if len(key) != 32 {
				return fmt.Errorf("Key must be 32 bytes long")
			}
		}
		for i, filePath := range filesPaths {
			var keyToUse []byte
			if len(key) != 0 {
				keyToUse = key
			} else {
				keyToUse = []byte(keys[i])
			}
			plaintext, err := crypto.DecryptFile(filePath, keyToUse)
			if err != nil {
				fmt.Printf("Error decrypting file %s: %v\n", filePath, err)
				continue
			}
			if len(outputPaths) <= i {
				fmt.Printf("Decrypted file %s:\n%s\n\n", filePath, string(plaintext))
				continue
			} else {
				outputFilePath := outputPaths[i]
				err = os.WriteFile(outputFilePath, plaintext, 0644)
				if err != nil {
					fmt.Printf("Error writing decrypted file %s: %v\n", outputFilePath, err)
					continue
				}
				fmt.Printf("Decrypted file %s to %s\n", filePath, outputFilePath)
			}
		}
		return nil
	},
}

func init() {
	decryptCmd.Flags().StringVarP(&decryptionKeysString, "keys", "K", "", "Keys for decryption (32 bytes separated by ,) one each file")
	decryptCmd.Flags().StringVarP(&decryptionKeyString, "key", "k", "", "Key for decryption (32 bytes) for all files")
	decryptCmd.MarkFlagsMutuallyExclusive("keys", "key")
	decryptCmd.Flags().StringVarP(&decryptionOutputs, "output", "o", "", "Output file paths (separated by ,)")
	rootCmd.AddCommand(decryptCmd)
}
