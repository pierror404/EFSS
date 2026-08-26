package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// logoutCmd represents the logout command
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from EFSS.",
	Run: func(cmd *cobra.Command, args []string) {
		//log out logic here
		fmt.Println("Logout successful.")
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
