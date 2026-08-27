package cmd

import (
	"github.com/spf13/cobra"
)

var keyToRebuild string
var CSkeysToRebuild string

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
	Use:   "extract <filenames> [flags]",
	Short: "verifies and extract the original file from a signed file.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func init() {
	extractCmd.Flags().StringVarP(&CSkeysToRebuild, "Keys", "K", "", "Keys for encryption (32 bytes separated by ,)")
	extractCmd.Flags().StringVarP(&keyToRebuild, "key", "k", "", "Key for encryption (32 bytes)")
	rootCmd.MarkFlagsMutuallyExclusive("Keys", "key")
	rootCmd.AddCommand(extractCmd)
}
