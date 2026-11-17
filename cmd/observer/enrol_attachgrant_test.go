package main

import (
	"strings"
	"testing"
)

// TestEnrolAttachGrantArgs pins `observer enroll --attach-grant-file`'s
// argument rules: the org URL as the one argument, no other way to enrol
// beside it, and the grant from standard input, never argv.
func TestEnrolAttachGrantArgs(t *testing.T) {
	cases := []struct {
		name      string
		tokenFile string
		idp       string
		args      []string
		stdin     string
		wantURL   string
		wantGrant string
		wantErr   string
	}{
		{name: "grant on stdin", args: []string{"https://acme.superbased.app/"}, stdin: "sbag1.G.S\n", wantURL: "https://acme.superbased.app", wantGrant: "sbag1.G.S"},
		{name: "no org url", args: nil, stdin: "g", wantErr: "exactly one argument"},
		{name: "a token beside it", args: []string{"https://a.example"}, tokenFile: "-", stdin: "g", wantErr: "cannot be combined"},
		{name: "idp beside it", args: []string{"https://a.example"}, idp: "https://a.example", stdin: "g", wantErr: "cannot be combined"},
		{name: "not a URL", args: []string{"acme"}, stdin: "g", wantErr: "invalid org URL"},
		{name: "empty stdin", args: []string{"https://a.example"}, stdin: "  \n", wantErr: "holds no grant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, g, err := enrolAttachGrantArgs("-", tc.tokenFile, "", tc.idp, tc.args, strings.NewReader(tc.stdin))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || u != tc.wantURL || g != tc.wantGrant {
				t.Fatalf("= %q %q %v", u, g, err)
			}
		})
	}
}

// TestEnrollAttachGrantFlagIsHidden: the flag is for `observer connect`, not
// a person, so it stays out of the help.
func TestEnrollAttachGrantFlagIsHidden(t *testing.T) {
	f := newEnrollCmd().Flags().Lookup("attach-grant-file")
	if f == nil || !f.Hidden {
		t.Fatalf("--attach-grant-file = %+v, want a hidden flag", f)
	}
}
