package cmd

import (
	"EFSS/client/api"
	"fmt"

	"github.com/spf13/cobra"
)

// inboxCmd represents the inbox command
var inboxCmd = &cobra.Command{
	Use:   "inbox",
	Short: "Shows all the incoming messages not yet received",
	Run: func(cmd *cobra.Command, args []string) {
		items, err := api.GetInbox()
		if err != nil {
			fmt.Println("Error: " + err.Error())
			return
		}

		if len(items) == 0 {
			fmt.Println("No new messages.")
			return
		}

		fmt.Println("ID\tSender\tFile")
		for _, item := range items {
			fmt.Printf("%d\t%s\t%s\n", item.MessageID, item.Sender, item.Filename)
		}
	},
}

func init() {
	rootCmd.AddCommand(inboxCmd)
}
