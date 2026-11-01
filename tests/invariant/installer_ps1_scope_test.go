package invariant

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestInstallPS1NoShadowedScriptNames refuses a function in
// scripts/install.ps1 that assigns (or loops over, or takes as a parameter)
// a variable whose name equals a script-scope variable. PowerShell names are
// case-insensitive and scoping is dynamic: a local `$mxcManifest = $null`
// inside Invoke-Install hid the script-scope `$MxcManifest` from Test-MxcSet,
// which it called next, and every install of an archive with an mxc\ folder
// failed with "the archive's mxc\ has no , so its sandbox files cannot be
// checked" (Windows 11 Pro live run, B3). A function that means to change a
// script-scope value writes `$script:Name`.
func TestInstallPS1NoShadowedScriptNames(t *testing.T) {
	for _, file := range []string{"scripts/install.ps1"} {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(file)))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for _, v := range ps1ShadowedNames(string(raw)) {
			t.Errorf("%s: %s", file, v)
		}
	}
}

// TestPS1ShadowCheckCatchesTheB3Shape pins the checker itself on the exact
// shape that broke the installer, plus the forms it must leave alone.
func TestPS1ShadowCheckCatchesTheB3Shape(t *testing.T) {
	bad := "param([string]$Edition = \"\")\n$MxcManifest = \"mxc-manifest.json\"\n" +
		"function Test-MxcSet([string]$src) { Join-Path $src $MxcManifest }\n" +
		"function Invoke-Install {\n  $mxcManifest = $null\n  $mxcManifest = Test-MxcSet $x\n" +
		"  foreach ($edition in @()) { }\n}\n"
	got := ps1ShadowedNames(bad)
	if len(got) != 2 {
		t.Fatalf("checker found %d shadows %v, want 2 ($mxcManifest, $edition)", len(got), got)
	}
	good := "$MxcDir = \"mxc\"\nfunction F([string]$dir) {\n  # $mxcdir = 1 in a comment\n" +
		"  $script:MxcDir = \"x\"\n  $mxcPath = Join-Path $dir $MxcDir\n  if ($a -eq $MxcDir) { }\n}\n"
	if got := ps1ShadowedNames(good); len(got) != 0 {
		t.Fatalf("checker flagged a clean script: %v", got)
	}
}

var (
	ps1Assign  = regexp.MustCompile(`(?:^|[^\w:$])\$([A-Za-z_]\w*)\s*(?:[+\-*/]?=)(?:[^=]|$)`)
	ps1Foreach = regexp.MustCompile(`(?i)\bforeach\s*\(\s*\$([A-Za-z_]\w*)\s+in\b`)
	ps1Var     = regexp.MustCompile(`\$([A-Za-z_]\w*)`)
	ps1FuncHdr = regexp.MustCompile(`(?i)^function\s+([\w-]+)\s*(\(([^)]*)\))?`)
)

// ps1ShadowedNames returns one line per function-local name that equals a
// script-scope name. The parse is line-based and deliberately narrow: the
// installers keep `function` at column 0 and their braces balanced per
// function, which the scripts themselves already follow.
func ps1ShadowedNames(src string) []string {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	code := make([]string, len(lines))
	inBlock := false
	for i, l := range lines {
		if inBlock {
			if j := strings.Index(l, "#>"); j >= 0 {
				inBlock = false
				l = l[j+2:]
			} else {
				continue
			}
		}
		if j := strings.Index(l, "<#"); j >= 0 {
			if k := strings.Index(l[j:], "#>"); k >= 0 {
				l = l[:j] + l[j+k+2:]
			} else {
				inBlock = true
				l = l[:j]
			}
		}
		code[i] = ps1StripComment(l)
	}

	script := map[string]string{}
	type local struct{ fn, name string }
	var locals []local
	fn, depth := "", 0
	inParam := false
	for _, l := range code {
		if fn == "" {
			if m := ps1FuncHdr.FindStringSubmatch(l); m != nil {
				fn = m[1]
				for _, v := range ps1Var.FindAllStringSubmatch(m[3], -1) {
					locals = append(locals, local{fn, v[1]})
				}
				depth = 0
			}
		}
		if fn == "" {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(strings.ToLower(t), "param(") {
				inParam = true
			}
			if inParam {
				for _, v := range ps1Var.FindAllStringSubmatch(l, -1) {
					script[strings.ToLower(v[1])] = v[1]
				}
				if strings.HasPrefix(t, ")") || strings.HasSuffix(t, ")") && !strings.Contains(t, "(") {
					inParam = false
				}
				continue
			}
			for _, m := range ps1Assign.FindAllStringSubmatch(l, -1) {
				script[strings.ToLower(m[1])] = m[1]
			}
			continue
		}
		for _, m := range ps1Assign.FindAllStringSubmatch(l, -1) {
			locals = append(locals, local{fn, m[1]})
		}
		for _, m := range ps1Foreach.FindAllStringSubmatch(l, -1) {
			locals = append(locals, local{fn, m[1]})
		}
		depth += strings.Count(l, "{") - strings.Count(l, "}")
		if depth <= 0 && strings.Contains(l, "}") {
			fn = ""
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, lc := range locals {
		if s, ok := script[strings.ToLower(lc.name)]; ok {
			msg := "function " + lc.fn + " sets $" + lc.name + ", which hides the script-scope $" + s + " from every function it calls (rename the local, or write $script:" + s + ")"
			if !seen[msg] {
				seen[msg] = true
				out = append(out, msg)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ps1StripComment drops a `#` comment that is not inside a quoted string.
func ps1StripComment(l string) string {
	var q rune
	for i, r := range l {
		switch {
		case q != 0:
			if r == q {
				q = 0
			}
		case r == '"' || r == '\'':
			q = r
		case r == '#':
			return l[:i]
		}
	}
	return l
}
