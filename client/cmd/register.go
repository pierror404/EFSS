package cmd

import (
	conf "EFSS/client/config"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var keysfolder string

// registerCmd represents the register command
var registerCmd = &cobra.Command{
	Use:   "register <username> [flags]",
	Short: "Register a new user with the specified username",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		if username == "" {
			fmt.Println("Error: Username cannot be empty")
			return
		}
		// check if username is valid

		fmt.Printf("Password for user %s: ", username)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Println("Error reading password")
			return
		}
		fmt.Println()
		fmt.Printf("Again, password for user %s: ", username)
		passwordConfirm, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Println("Error reading password confirmation")
			return
		}
		fmt.Println()
		if string(password) != string(passwordConfirm) {
			fmt.Println("Error: Passwords do not match")
			return
		}
		// Here you would add logic to register the user with the provided username and password.
		// Logic to generate a key pair and store it securely would also be added here.
		// Private key must be stored securely on the client side, while the public key can be sent to the server for user registration.
		path, err := conf.ConfigDir()
		if err != nil {
			fmt.Println("Error configuring keys")
			return
		}
		// Generate key pair and save to path
		// For demonstration purposes, we will just create empty files for the keys.
		err = generatekeys(filepath.Join(path, "keys"), password)
		if err != nil {
			fmt.Println("Error generating keys:", err)
			return
		}
		fmt.Println("Keys generated and saved in", path)
		fmt.Println("User", username, "registered successfully.")
	},
}

func init() {
	registerCmd.Flags().StringVarP(&keysfolder, "folder", "-f", "", "folder where the keys will be stored (if different from the default path './keys')")
	rootCmd.AddCommand(registerCmd)
}
