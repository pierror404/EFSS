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
	Run: func(cmd *cobra.Command, args []string) {
		filesPaths := strings.Split(args[0], ",")
		username := args[1]
		pubKeyB64, err := api.GetPublicKey(username)
		if err != nil {
			fmt.Println("Error getting public key by username.")
			return
		}
		pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			fmt.Println("Invalid public key for %s" + username)
			return
		}
		pubKey, err := crypto.ParsePublicKey(pubKeyBytes)
		if err != nil {
			fmt.Println("Public key parsing error for " + username + ": " + err.Error())
			return
		}
		for _, filePath := range filesPaths {
			_, err := crypto.VerifyFile(filePath, pubKey) // Assuming signature is obtained elsewhere
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
