package cmd

import (
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
	Run: func(cmd *cobra.Command, args []string) {
		filesPaths := strings.Split(args[0], ",")
		outputPaths := strings.Split(encryptionOutputs, ",")
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
					fmt.Println("Key must be 32 bytes long")
					return
				}
			} else {
				if len(keys) != len(filesPaths) {
					fmt.Println("Number of keys must match number of files")
					return
				}
				for i := 0; i < len(keys); i++ {
					if len(keys[i]) != 32 {
						fmt.Printf("Key %d must be 32 bytes long\n", i+1)
						return
					}
				}
			}
		} else {
			if len(key) != 32 {
				fmt.Println("Key must be 32 bytes long")
				return
			}
		}
		for i, filePath := range filesPaths {
			var keyToUse []byte
			if len(key) != 0 {
				keyToUse = key
			} else {
				keyToUse = []byte(keys[i])
			}
			plaintext, err := decryptfile(filePath, keyToUse)
			if err != nil {
				fmt.Printf("Error decrypting file %s: %v\n", filePath, err)
				continue
			}
			if len(outputPaths) <= i {
				fmt.Printf("Decrypted file %s:\n\t%s\n\n", filePath, string(plaintext))
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
	},
}

func init() {
	decryptCmd.Flags().StringVarP(&decryptionKeysString, "Keys", "K", "", "Keys for decryption (32 bytes separated by ,) one each file")
	decryptCmd.Flags().StringVarP(&decryptionKeyString, "key", "k", "", "Key for decryption (32 bytes) for all files")
	rootCmd.MarkFlagsMutuallyExclusive("Keys", "key")
	decryptCmd.Flags().StringVarP(&decryptionOutputs, "output", "o", "", "Output file paths (separated by ,)")
	rootCmd.AddCommand(decryptCmd)
}
