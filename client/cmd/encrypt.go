package cmd

import (
	"EFSS/client/crypto"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var encryptionKeyString string
var encryptionKeysString string
var encryptionOutputs string

func choosekey(key []byte, keys []string, index int) []byte {
	if len(key) != 0 {
		return key
	}
	return []byte(keys[index])
}

var encrypt = &cobra.Command{
	Use:   "encrypt <filenames> [flags]",
	Short: "Encrypt one or more file (separated by ,) by AES-256",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filesPaths := strings.Split(args[0], ",")
		outputPaths := strings.Split(encryptionOutputs, ",")
		var key []byte
		key = []byte(encryptionKeyString)
		var keys []string
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
						return nil
					}
				}
			}
		} else {
			if len(key) != 32 {
				fmt.Printf("Key must be 32 bytes long\n")
				return nil
			}
		}
		if len(outputPaths) > len(filesPaths) {
			fmt.Println("Warning: More output paths than input files. Extra output paths will be ignored.")
		}
		if len(outputPaths) < len(filesPaths) {
			fmt.Println("Warning: Fewer output paths than input files. Some files will be saved as 'inputpath.enc'.")
			for i := len(outputPaths); i < len(filesPaths); i++ {
				outputPaths = append(outputPaths, filesPaths[i]+".enc")
			}
		}
		for i := 0; i < len(filesPaths); i++ {
			encrypted, err := crypto.EncryptFile(filesPaths[i], choosekey(key, keys, i))
			if err != nil {
				panic(err)
			}
			err = os.WriteFile(outputPaths[i], encrypted, 0644)
			if err != nil {
				panic(err)
			}
			fmt.Printf("File %s encrypted and saved to %s\n", filesPaths[i], outputPaths[i])
		}

		return nil
	},
}

func init() {
	encrypt.Flags().StringVarP(&encryptionKeysString, "Keys", "K", "", "Keys for encryption (32 bytes separated by ,)")
	encrypt.Flags().StringVarP(&encryptionKeyString, "key", "k", "", "Key for encryption (32 bytes)")
	rootCmd.MarkFlagsMutuallyExclusive("Keys", "key")
	encrypt.Flags().StringVarP(&encryptionOutputs, "output", "o", "", "Output file paths (separated by ,)")
	rootCmd.AddCommand(encrypt)
}
