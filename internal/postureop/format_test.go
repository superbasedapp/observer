package postureop

import (
	"strings"
	"testing"
)

func TestCheckFormat(t *testing.T) {
	good := "ghcr.io/example/img@sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		format string
		value  any
		ok     bool
	}{
		{"", "anything", true},
		{FormatImageDigestRef, good, true},
		{FormatImageDigestRef, "alpine:3", false},
		{FormatImageDigestRef, "", false},
		{FormatImageDigestRef, 3, false},
		{"no_such_format", good, false},
	}
	for _, c := range cases {
		if err := CheckFormat(c.format, c.value); (err == nil) != c.ok {
			t.Errorf("%s %v: %v", c.format, c.value, err)
		}
	}
	if !KnownFormat("") || !KnownFormat(FormatImageDigestRef) || KnownFormat("x") {
		t.Error("KnownFormat")
	}
}
