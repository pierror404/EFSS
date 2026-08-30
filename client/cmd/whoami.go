package cmd

import (
	"efss-client/config"
	"fmt"

	"github.com/spf13/cobra"
)

// whoamiCmd represents the whoami command
var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Display the current logged-in user",
	RunE: func(cmd *cobra.Command, args []string) error {
		creds, err := config.LoadCredentials()
		if err != nil {
			return fmt.Errorf("Not logged in: %w", err)
		}

		fmt.Println(creds.Username)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)

}
