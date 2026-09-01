package cmd

import "strings"

// choosekey returns the key to use for encryption/decryption. If a specific key is provided, it uses that; otherwise, it selects from a list of keys based on the provided index.
func choosekey(key []byte, keys []string, index int) []byte {
	if len(key) != 0 {
		return key
	}
	return []byte(keys[index])
}

// splitString splits a string by the specified separator and returns a slice of non-empty, trimmed strings.
func splitString(str string, separator string) []string {
	separated := strings.Split(str, separator)
	var sanified []string
	for _, el := range separated {
		if elemOk := strings.TrimSpace(el); elemOk != "" {
			sanified = append(sanified, elemOk)
		}
	}
	return sanified
}
