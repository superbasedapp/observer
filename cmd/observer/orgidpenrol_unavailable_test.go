package main

import (
	"strings"
	"testing"
)

func TestIdpUnavailableMessage(t *testing.T) {
	t.Parallel()
	for _, multiline := range []bool{true, false} {
		got := idpUnavailableMessage("https://org.example.com/", multiline)
		for _, want := range []string{
			"https://org.example.com/me/install",
			"observer connect https://org.example.com`",
			"SBO_PAIR_CODE",
			"--pair-file",
			"observer enroll https://org.example.com <code>",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("multiline=%v: message lacks %q:\n%s", multiline, want, got)
			}
		}
		if strings.Contains(got, "\n") != multiline {
			t.Errorf("multiline=%v: newline presence wrong: %q", multiline, got)
		}
	}
}
