package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestEnrolArgsWithTokenFile pins --token-file: the code comes from the file
// or stdin and joins the org URL as the positional pair; everything that
// would make the source ambiguous is refused.
func TestEnrolArgsWithTokenFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "code")
	if err := os.WriteFile(good, []byte("  tok_id.secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("a", enrolTokenFileLimit+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		file      string
		link, idp string
		args      []string
		stdin     string
		want      []string
		wantErr   string
	}{
		{name: "no flag passes args through", args: []string{"https://org", "x"}, want: []string{"https://org", "x"}},
		{name: "file", file: good, args: []string{"https://org"}, want: []string{"https://org", "tok_id.secret"}},
		{name: "stdin", file: "-", args: []string{"https://org"}, stdin: "tok_id.stdin\n", want: []string{"https://org", "tok_id.stdin"}},
		{name: "with link", file: good, link: "https://org/enrol/abc", wantErr: "cannot be combined"},
		{name: "with idp", file: good, idp: "https://org", wantErr: "cannot be combined"},
		{name: "two args", file: good, args: []string{"https://org", "tok"}, wantErr: "exactly one argument"},
		{name: "no args", file: good, wantErr: "exactly one argument"},
		{name: "empty file", file: empty, args: []string{"https://org"}, wantErr: "no enrolment code"},
		// F-029 V1: a non-regular file is refused before any read, and a
		// file or stdin larger than the bound is refused, never read whole.
		{name: "directory refused", file: sub, args: []string{"https://org"}, wantErr: "not a regular file"},
		// O5-A7: the refusal points at stdin for a pipe.
		{name: "refusal names stdin", file: sub, args: []string{"https://org"}, wantErr: "--token-file - and pipe it"},
		{name: "oversized file refused", file: big, args: []string{"https://org"}, wantErr: "more than"},
		{name: "oversized stdin refused", file: "-", args: []string{"https://org"}, stdin: strings.Repeat("b", enrolTokenFileLimit+1), wantErr: "more than"},
		{name: "missing file", file: filepath.Join(dir, "absent"), args: []string{"https://org"}, wantErr: "read --token-file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := enrolArgsWithTokenFile(tc.file, tc.link, tc.idp, tc.args, strings.NewReader(tc.stdin))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
