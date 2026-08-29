package cmd

import (
	"EFSS/client/api"
	conf "EFSS/client/config"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login <username>",
	Short: "Login to EFSS with the provided username",
	Long:  `You need to login to EFSS with a username before you can use the other commands.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		username := args[0]
		fmt.Printf("Password for user %s: ", username)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("Error: %w", err)
		}
		token, err := api.Login(username, string(password))
		if err != nil {
			fmt.Println("Login failed!")
			return fmt.Errorf("Error: %w", err)
		}
		if err := conf.SaveToken(username, token); err != nil {
			return fmt.Errorf("Error while saving credentials: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)
}
