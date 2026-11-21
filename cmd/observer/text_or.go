package main

import "strings"

// orText renders an empty string as alt.
func orText(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}

// orDash renders an empty string as a dash (U+2014). It lives in this
// untagged file because callers outside org.update use it too
// (process_capture_cmd.go, the opengrep dashboard), so a build that omits
// org.update must still have it.
func orDash(s string) string { return orText(s, "—") }
