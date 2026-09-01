package cmd

import (
	"efss-client/api"
	conf "efss-client/config"
	"efss-client/crypto"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

//var keysfolder string

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

		path, err := conf.ConfigDir()
		if err != nil {
			return fmt.Errorf("Error configuring keys: %w", err)
		}

		pathToKeys := filepath.Join(path, "keys")
		err = os.MkdirAll(pathToKeys, 0700)
		if err != nil {
			return fmt.Errorf("Error generating keys path: %w", err)
		}
		publicKey, err := crypto.GenerateAsymmetricKeys(filepath.Join(path, "keys"), password)
		if err != nil {
			return fmt.Errorf("Error generating keys: %w", err)
		}
		pubKeyB64 := base64.StdEncoding.EncodeToString(publicKey)
		if err := api.Register(username, string(password), pubKeyB64); err != nil {
			return fmt.Errorf("Error signing up the user %s: %w", username, err)
		}
		fmt.Println("Keys generated and saved in " + path)
		fmt.Println("User " + username + " registered successfully.")
		return nil
	},
}

func init() {
	//registerCmd.Flags().StringVarP(&keysfolder, "folder", "f", "", "folder where the keys will be stored (if different from the default path './keys')")
	rootCmd.AddCommand(registerCmd)
}
