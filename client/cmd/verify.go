/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"EFSS/client/crypto"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify <filenames> <username>",
	Short: "Verify documents (separated by ,) signature",
	Long:  `Verify the that the documents (separated by ,) are signed by the specified user.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		filesPaths := strings.Split(args[0], ",")
		username := args[1]
		publicKey, err := crypto.PublicKeyByUsername(username)
		if err != nil {
			fmt.Printf("Error loading public key for user %s: %v\n", username, err)
			return
		}
		for _, filePath := range filesPaths {
			_, err := crypto.VerifyFile(filePath, publicKey) // Assuming signature is obtained elsewhere
			if err != nil {
				fmt.Printf("Verification failed for file %s: %v\n", filePath, err)
			} else {
				fmt.Printf("Verification successful for file %s\n", filePath)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
