package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// whoamiCmd represents the whoami command
var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Display the current logged-in user",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Logged as: [username]")
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)

}
