/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"EFSS/client/api"
	"EFSS/client/crypto"
	"encoding/base64"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		filesPaths := strings.Split(args[0], ",")
		username := args[1]
		pubKeyB64, err := api.GetPublicKey(username)
		if err != nil {
			return fmt.Errorf("Error getting public key by username: %w", err)
		}
		pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return fmt.Errorf("Invalid public key for %s: %w", username, err)
		}
		pubKey, err := crypto.ParsePublicKey(pubKeyBytes)
		if err != nil {
			return fmt.Errorf("Public key parsing error for %s: %w", username, err)
		}
		for _, filePath := range filesPaths {
			_, err := crypto.VerifyFile(filePath, pubKey) // Assuming signature is obtained elsewhere
			if err != nil {
				fmt.Printf("Verification failed for file %s: %v\n", filePath, err)
			} else {
				fmt.Printf("Verification successful for file %s\n", filePath)
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}
