package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func checkpasswd(password string) bool {
	return true
}

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login [username]",
	Short: "Login to EFSS with the provided username",
	Long:  `You need to login to EFSS with a username before you can use the other commands.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		username := args[0]
		fmt.Printf("Password for user %s: ", username)
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Println("Error: ", err)
			return
		}

		//Check password
		if checkpasswd(string(password)) {
			fmt.Println()
			fmt.Println("Login successful for ", username)
		} else {
			fmt.Println("Invalid password for user ", username)
		}
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)
}
