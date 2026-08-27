package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var keypath string
var signedoutputfile string

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign <filenames> [flags]",
	Short: "Sign documents (separated by ,) with your private key",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filepaths := strings.Split(args[0], ",")
		outputpaths := strings.Split(encryptionOutputs, ",")
		key := []byte(keypath)
		if len(key) == 0 {
			key = []byte("./keys/private.pem")
		}
		for i, filepath := range filepaths {
			fmt.Printf("Password: ")
			password, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				cmd.Println("Error reading password")
				return
			}
			fmt.Println()

			privatekey, err := loadPrivateKey(string(key), password)
			if err != nil {
				fmt.Printf("Error loading private key from %s: %v\n", string(key), err)
				return
			}

			var outputfile string
			if i < len(outputpaths) {
				outputfile = outputpaths[i]
			} else {
				outputfile = filepath + ".signed"
			}

			err = signFile(filepath, outputfile, privatekey)
			if err != nil {
				fmt.Printf("Error saving signature for %s: %v\n", filepath, err)
				continue
			} else {
				fmt.Printf("Signature for %s saved to %s\n", filepath, outputfile)
			}

		}
	},
}

func init() {
	signCmd.Flags().StringVarP(&keypath, "keypath", "-p", "", "filepath to the private key used for signing (if different from the default path './keys/private.pem')")
	encrypt.Flags().StringVarP(&signedoutputfile, "output", "o", "", "Output file paths (separated by ,)")
	rootCmd.AddCommand(signCmd)
}
