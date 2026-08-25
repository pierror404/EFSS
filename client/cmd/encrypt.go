package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func generateRandomKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

func choosekey(key []byte, keys []string, index int) []byte {
	if len(key) != 0 {
		return key
	}
	return []byte(keys[index])
}

func encryptfile(filepath string, key []byte) ([]byte, error) {
	text, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, text, nil), nil
}

var keyString string
var keysString string
var outputs string

var encrypt = &cobra.Command{
	Use:   "encrypt [<filenames>]",
	Short: "Encrypt one or more file (separated by ,) by AES-256",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filesPaths := strings.Split(args[0], ",")
		outputPaths := strings.Split(outputs, ",")
		var key []byte
		key = []byte(keyString)
		var keys []string
		if len(key) == 0 {
			keys := strings.Split(keysString, ",")
			if len(keys) == 0 {
				key = generateRandomKey()
			} else {
				if len(keys) > len(filesPaths) {
					fmt.Println("Warning: More keys provided than files. Extra keys will be ignored.")
				}
				if len(keys) < len(filesPaths) {
					fmt.Println("Warning: Number of keys provided does not match number of files. Using random keys for unmatched files.")
					for i := len(keys); i < len(filesPaths); i++ {
						generated_key := generateRandomKey()
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
			encrypted, err := encryptfile(filesPaths[i], choosekey(key, keys, i))
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
	encrypt.Flags().StringVarP(&keysString, "Keys", "K", "", "Keys for encryption (32 bytes separated by ,)")
	encrypt.Flags().StringVarP(&keyString, "key", "k", "", "Key for encryption (32 bytes)")
	encrypt.Flags().StringVarP(&outputs, "output", "o", "", "Output file paths (separated by ,)")
	rootCmd.AddCommand(encrypt)
}
