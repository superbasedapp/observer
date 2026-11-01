package integration

import (
	"reflect"
	"strings"
	"testing"
)

// TestEnvFileArguments pins the --env-file scan (CLI-7).
func TestEnvFileArguments(t *testing.T) {
	d := DotenvOverride{FileArguments: []string{"--env-file"}}
	cases := []struct {
		args []string
		want []string
	}{
		{[]string{"--env-file", "a.env"}, []string{"a.env"}},
		{[]string{"--env-file=b.env", "--model", "x"}, []string{"b.env"}},
		{[]string{"--env-file"}, nil},
		{[]string{"--", "--env-file", "c.env"}, nil},
		{[]string{"--env-file=", "x"}, nil},
	}
	for _, tc := range cases {
		if got := d.EnvFileArguments(tc.args); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v: got %v, want %v", tc.args, got, tc.want)
		}
	}
}

// TestDotenvOverrideRowsWellFormed: every DotenvOverride row names files
// under "~/" or "<project>/", at least one key, and its grounding; and every
// gated row's dotenv files follow the same spelling (CLI-6, CLI-7).
func TestDotenvOverrideRowsWellFormed(t *testing.T) {
	rooted := func(f string) bool { return strings.HasPrefix(f, "~/") || strings.HasPrefix(f, "<project>/") }
	seen := 0
	for _, c := range Capabilities() {
		if c.Proxy == nil {
			continue
		}
		if d := c.Proxy.DotenvOverride; d != nil {
			seen++
			if len(d.Files) == 0 || len(d.Keys) == 0 || d.Grounding == "" {
				t.Errorf("%s: DotenvOverride needs files, keys and grounding", c.Tool)
			}
			for _, f := range d.Files {
				if !rooted(f) {
					t.Errorf("%s: dotenv file %q is not ~/ or <project>/", c.Tool, f)
				}
			}
		}
		if g := c.Proxy.Gate; g != nil {
			for _, f := range g.DotenvFiles {
				if !rooted(f) {
					t.Errorf("%s: gate dotenv file %q is not ~/ or <project>/", c.Tool, f)
				}
			}
			if len(g.DotenvKeys) > 0 && len(g.DotenvFiles) == 0 {
				t.Errorf("%s: DotenvKeys without DotenvFiles", c.Tool)
			}
			for _, k := range g.AuthSettingKeys {
				if k.File == "" || k.Key == "" {
					t.Errorf("%s: incomplete AuthSettingKey %+v", c.Tool, k)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no DotenvOverride row: the CLI-7 aider row is gone")
	}
}
