package cmd

import "strings"

func choosekey(key []byte, keys []string, index int) []byte {
	if len(key) != 0 {
		return key
	}
	return []byte(keys[index])
}

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
