package cmd

import (
	"crypto/rsa"
	"efss-client/api"
	"efss-client/crypto"
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
)

var keyToRebuild string
var CSkeysToRebuild string
var localPKpath string
var onlinePKusername string

func chooseKeyOrNil(key string, keys []string, i int) []byte {
	if len(key) == 0 && len(keys) == 0 {
		return nil
	}
	return choosekey([]byte(key), keys, i)
}

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
	Use:   "extract <filenames> [flags]",
	Short: "Verifies and extract the original file from a signed file.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		paths := splitString(args[0], ",")
		var keys []string
		if len(keyToRebuild) == 0 {
			keys = splitString(CSkeysToRebuild, ",")
			if len(keys) != len(paths) {
				return fmt.Errorf("If you specify more than 1 key, keys number must match the files number")
			}
		}
		var pubKeyToUse *rsa.PublicKey
		if len(localPKpath) != 0 {
			pubKey, err := crypto.ParsePublicKeyFromFile(localPKpath)
			if err != nil {
				return err
			}
			pubKeyToUse = pubKey
		} else if len(onlinePKusername) != 0 {
			pubKeyString, err := api.GetPublicKey(onlinePKusername)
			if err != nil {
				return err
			}
			pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyString)
			if err != nil {
				return fmt.Errorf("Invalid public key for %s: %w", onlinePKusername, err)
			}
			pubKeyToUse, err = crypto.ParsePublicKey(pubKeyBytes)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("You must specify -O or -l for the public key to verify the signature")
		}
		for i, signedPath := range paths {
			if err := crypto.ExtractAndVerifyFile(signedPath, pubKeyToUse, chooseKeyOrNil(keyToRebuild, keys, i)); err != nil {
				return fmt.Errorf("Error while extracting and verifying file: %w", err)
			}
		}
		return nil
	},
}

func init() {
	extractCmd.Flags().StringVarP(&CSkeysToRebuild, "keys", "K", "", "Keys for encryption (32 bytes separated by ,)")
	extractCmd.Flags().StringVarP(&keyToRebuild, "key", "k", "", "Key for encryption (32 bytes)")
	extractCmd.MarkFlagsMutuallyExclusive("keys", "key")
	extractCmd.Flags().StringVarP(&localPKpath, "local", "l", "", "Path to the public key to verify the signature")
	extractCmd.Flags().StringVarP(&onlinePKusername, "online", "O", "", "Get the public key from online, specify username")
	extractCmd.MarkFlagsMutuallyExclusive("local", "online")
	rootCmd.AddCommand(extractCmd)
}
