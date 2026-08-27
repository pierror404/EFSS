package cmd

import (
	"EFSS/client/api"
	conf "EFSS/client/config"
	"fmt"

	"github.com/spf13/cobra"
)

// logoutCmd represents the logout command
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from EFSS.",
	Run: func(cmd *cobra.Command, args []string) {
		if err := api.Logout(); err != nil {
			fmt.Println("Warning: server side logaout failed, will remove local saved credentials anyway")
		}

		if err := conf.ClearToken(); err != nil {
			fmt.Println("Error removing credentials: " + err.Error())
			return
		}

		fmt.Println("Logout effettuato.")
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
