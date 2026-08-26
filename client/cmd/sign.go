package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var keypath string

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign <filenames> [flags]",
	Short: "Sign documents (separated by ,) with your private key",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filepaths := strings.Split(args[0], ",")
		key := []byte(keypath)
		if len(key) == 0 {
			key = []byte("./keys/private.pem")
		}
		for _, filepath := range filepaths {
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

			signed, err := signFile(filepath, privatekey)
			if err != nil {
				fmt.Printf("Error signing %s: %v\n", filepath, err)
				continue
			}
			err = os.WriteFile(filepath+".sig", signed, 0644)
			if err != nil {
				fmt.Printf("Error saving signature for %s: %v\n", filepath, err)
				continue
			} else {
				fmt.Printf("Signature for %s saved to %s.sig\n", filepath, filepath)
			}
		}
	},
}

func init() {
	signCmd.Flags().StringVarP(&keypath, "keypath", "-p", "", "filepath to the private key used for signing (if different from the default path './keys/private.pem')")
	rootCmd.AddCommand(signCmd)
}
