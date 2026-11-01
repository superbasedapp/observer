package main

import "strings"

// orText renders an empty string as alt.
func orText(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}
