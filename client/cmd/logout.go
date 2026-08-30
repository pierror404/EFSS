package cmd

import (
	"efss-client/api"
	conf "efss-client/config"
	"fmt"

	"github.com/spf13/cobra"
)

// logoutCmd represents the logout command
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from EFSS.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := api.Logout(); err != nil {
			fmt.Println("Warning: server side logout failed, will remove local saved credentials anyway")
		}

		if err := conf.ClearToken(); err != nil {
			return fmt.Errorf("Error removing credentials: %w", err)
		}

		fmt.Println("Logout effettuato.")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
