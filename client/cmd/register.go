package cmd

import (
	"EFSS/client/api"
	conf "EFSS/client/config"
	"EFSS/client/crypto"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		username := args[0]
		if username == "" {
			return fmt.Errorf("Error: Username cannot be empty")
		}
		// check if username is valid

		fmt.Printf("Password for user %s: ", username)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("Error reading password: %w", err)
		}
		fmt.Println()
		fmt.Printf("Again, password for user %s: ", username)
		passwordConfirm, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("Error reading password confirmation: %w", err)
		}
		fmt.Println()
		if string(password) != string(passwordConfirm) {
			return fmt.Errorf("Error: Passwords do not match: %w", err)
		}
		// Here you would add logic to register the user with the provided username and password.
		// Logic to generate a key pair and store it securely would also be added here.
		// Private key must be stored securely on the client side, while the public key can be sent to the server for user registration.
		path, err := conf.ConfigDir()
		if err != nil {
			return fmt.Errorf("Error configuring keys: %w", err)
		}
		// Generate key pair and save to path
		// For demonstration purposes, we will just create empty files for the keys.
		publicKey, err := crypto.GenerateAsymmetricKeys(filepath.Join(path, "keys"), password)
		if err != nil {
			return fmt.Errorf("Error generating keys: %w", err)
		}
		api.Register(username, string(password), string(publicKey))
		fmt.Println("Keys generated and saved in " + path)
		fmt.Println("User " + username + " registered successfully.")
		return nil
	},
}

func init() {
	registerCmd.Flags().StringVarP(&keysfolder, "folder", "-f", "", "folder where the keys will be stored (if different from the default path './keys')")
	rootCmd.AddCommand(registerCmd)
}
