package cmd

import (
	conf "efss-client/config"
	"efss-client/crypto"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		filepaths := strings.Split(args[0], ",")
		outputpaths := splitString(encryptionOutputs, ",")
		key := []byte(keypath)
		if len(key) == 0 {
			privateKeyPath, err := conf.PrivateKeyPath()
			if err != nil {
				return fmt.Errorf("Error reaching default private key file: %w", err)
			}
			key = []byte(privateKeyPath)
		}
		fmt.Printf("Password: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("Error reading password: %w", err)
		}
		fmt.Println()

		privatekey, err := crypto.LoadPrivateKey(string(key), password)
		if err != nil {
			return fmt.Errorf("Error loading private key from %s: %w\n", string(key), err)
		}
		for i, filepath := range filepaths {

			var outputfile string
			if i < len(outputpaths) {
				outputfile = outputpaths[i]
			} else {
				outputfile = filepath + ".signed"
			}
			fmt.Printf("Output file: %s\n", outputfile)
			err = crypto.SignFile(filepath, outputfile, privatekey)
			if err != nil {
				fmt.Printf("Error saving signature for %s: %v\n", filepath, err)
				continue
			} else {
				fmt.Printf("Signature for %s saved to %s\n", filepath, outputfile)
			}

		}
		return nil
	},
}

func init() {
	signCmd.Flags().StringVarP(&keypath, "keypath", "p", "", "filepath to the private key used for signing (if different from the default path 'HOMEDIR/.efss/key/private.key.enc')")
	signCmd.Flags().StringVarP(&signedoutputfile, "output", "o", "", "Output file paths (separated by ,)")
	rootCmd.AddCommand(signCmd)
}
