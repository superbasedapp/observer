package guard

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestCheckUserPolicy pins the T-323 load verdict: one row per way a
// user guard-policy.toml can fail to load, with the line it is placed
// on, plus the states that are not failures.
func TestCheckUserPolicy(t *testing.T) {
	t.Parallel()
	const path = "/home/u/.observer/guard-policy.toml"
	cases := []struct {
		name      string
		raw       string
		readErr   error
		noPolicy  bool
		present   bool
		valid     bool
		line      int
		errSubstr string
	}{
		{name: "no user policy configured", noPolicy: true},
		{name: "file absent", readErr: fs.ErrNotExist},
		{name: "unreadable", readErr: errors.New("permission denied"), present: true, errSubstr: "permission denied"},
		{name: "valid", raw: "[[override]]\nrule = \"R-153\"\ndecision = \"deny\"\n", present: true, valid: true},
		{name: "empty file is valid", raw: "", present: true, valid: true},
		{
			name: "toml syntax error", present: true, line: 3, errSubstr: "parse:",
			raw: "# my rules\n[[override]]\nrule = R-153\n",
		},
		{
			name: "unknown key", present: true, line: 4, errSubstr: "unknown keys",
			raw: "[[override]]\nrule = \"R-153\"\ndecision = \"deny\"\nlabel = \"mine\"\n",
		},
		{
			name: "bad decision on the second override", present: true, line: 4, errSubstr: "override 2",
			raw: "[[override]]\nrule = \"R-153\"\n\n[[override]]\nrule = \"R-152\"\ndecision = \"explode\"\n",
		},
		{
			name: "override on an unknown rule", present: true, line: 2, errSubstr: "R-999",
			raw: "[[override]]\nrule = \"R-999\"\ndecision = \"deny\"\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.GuardConfig{}
			if !tc.noPolicy {
				cfg.Rules.UserPolicy = "~/.observer/guard-policy.toml"
			}
			read := func(p string) ([]byte, error) {
				// The product joins the path natively (backslashes on
				// Windows); compare it in slash form. The applied recipe
				// sibling is read too (none here).
				if filepath.ToSlash(p) == strings.TrimSuffix(path, ".toml")+RecipeFileSuffix {
					return nil, fs.ErrNotExist
				}
				if filepath.ToSlash(p) != path {
					t.Errorf("read %q, want %q", p, path)
				}
				if tc.readErr != nil {
					return nil, tc.readErr
				}
				return []byte(tc.raw), nil
			}
			st := CheckUserPolicy(cfg, "/home/u", read)
			if st.Present != tc.present || st.Valid != tc.valid || st.Line != tc.line {
				t.Fatalf("status = %+v, want present=%v valid=%v line=%d", st, tc.present, tc.valid, tc.line)
			}
			if st.Invalid() != (tc.present && !tc.valid) {
				t.Errorf("Invalid() = %v", st.Invalid())
			}
			if tc.errSubstr != "" && !strings.Contains(st.Error, tc.errSubstr) {
				t.Errorf("error = %q, want it to mention %q", st.Error, tc.errSubstr)
			}
			if tc.present && tc.readErr == nil && st.ContentHash != sha256hex([]byte(tc.raw)) {
				t.Errorf("content hash = %q", st.ContentHash)
			}
		})
	}
}

// TestCheckUserPolicyAgreesWithNew pins the derivation to the loader:
// a file CheckUserPolicy calls invalid is one New drops (load issue, no
// user layer state), and a valid one is one New loads.
func TestCheckUserPolicyAgreesWithNew(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"[[override]]\nrule = \"R-153\"\ndecision = \"deny\"\n",
		"[[override]]\nrule = R-153\n",
		"[[override]]\nrule = \"R-999\"\n",
	} {
		read := func(string) ([]byte, error) { return []byte(raw), nil }
		cfg := config.GuardConfig{Enabled: true, Mode: "observe"}
		cfg.Rules.UserPolicy = "/p/guard-policy.toml"
		st := CheckUserPolicy(cfg, "/home/u", read)
		g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: read})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		loaded := false
		for _, ps := range g.PolicyStates() {
			if ps.Layer == layerUser {
				loaded = true
			}
		}
		if loaded == st.Invalid() {
			t.Errorf("%q: CheckUserPolicy valid=%v but New loaded=%v (issues %v)", raw, st.Valid, loaded, g.LoadIssues())
		}
	}
}
