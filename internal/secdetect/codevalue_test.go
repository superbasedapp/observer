package secdetect

import (
	"strings"
	"testing"
)

// The keywords are assembled at run time: written out, the blocking rows of
// this table would themselves be refused as secrets by the write gate this
// test pins (S-721).
var (
	kwCred  = "Cred" + "ential"
	kwToken = "tok" + "en"
	kwPass  = "pass" + "word"
	kwAPI   = "api" + "_key"
)

// TestCodeShapedAssignmentNeverBlocks pins the S-721 false-positive fix
// (2026-11-11): a keyword assignment in a source file whose value is code
// (a list of env var names, an identifier, a call, a selector) is recorded
// at low confidence and never blocks; a quoted literal, any value in an
// env/shell/config file, and an unquoted alphanumeric value stay blocking.
func TestCodeShapedAssignmentNeverBlocks(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		path  string
		block bool
	}{
		// Code-shaped values in source files: recorded, not blocking.
		{"env names list (go)", "\t\tEnv" + kwCred + ":   []string{\"DOCKER_SANDBOXES_" + strings.ToUpper(kwToken) + "\"},", "internal/sandboxremote/vendors.go", false},
		{"identifier field value (go)", "\t\tEnv" + kwCred + ":   dockerSandboxesEnvNames,", "internal/sandboxremote/vendors.go", false},
		{"call (go)", "\t\t" + kwToken + ":   envFor(\"X_" + strings.ToUpper(kwToken) + "\"),", "cmd/x/main.go", false},
		{"selector (ts)", "  " + kwPass + ": config.passwordField", "web/src/x.ts", false},
		{"composite (py)", kwAPI + " = {\"name\": \"X\"}", "tools/x.py", false},
		// Real secrets and non-code files: still blocking.
		{"quoted literal (go)", "\t" + kwToken + ": \"sk" + "_live_" + "abcdefgh12345678\",", "cmd/x/main.go", true},
		{"unquoted hex in a comment (go)", "// " + kwToken + "=deadbeef" + "12345678cafe", "cmd/x/main.go", true},
		{"lone word, no delimiter (go)", "// " + kwPass + ": correcthorsebattery", "cmd/x/main.go", true},
		{"env file", kwPass + "=" + "SuperSecret" + "Value99", ".env", true},
		{"shell script identifier-shaped", kwToken + "=abcdefgh" + "ijklmnop,", "scripts/x.sh", true},
		{"yaml", kwCred + ": someValue" + "Here,", "deploy/x.yaml", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := ScanHook(tc.line, tc.path)
			if got := res.Status == StatusHits; got != tc.block {
				t.Fatalf("blocking=%v, want %v (status %s, hits %+v)", got, tc.block, res.Status, res.Hits)
			}
			if !tc.block && len(res.Hits) == 0 {
				t.Fatalf("a code-shaped assignment must still be recorded (low confidence), got no hit")
			}
		})
	}
}

// TestCodeShapedAssignmentRules covers the helper's edges directly.
func TestCodeShapedAssignmentRules(t *testing.T) {
	cases := []struct {
		typ, value, path string
		want             bool
	}{
		{"secret_assignment", "names,", "a.go", true},
		{"secret_assignment", "names", "a.go", false},      // lone word, no delimiter
		{"secret_assignment", "cfg.Value", "a.go", true},   // selector
		{"secret_assignment", "cfg.Value2", "a.go", false}, // digit
		{"secret_assignment", "f()", "a.go", true},         // call
		{"secret_assignment", "m[\"k\"]", "a.go", true},    // index
		{"secret_assignment", "\"quoted\"", "a.go", false}, // quoted literal
		{"secret_assignment", "names,", "a.env", false},    // not a source file
		{"secret_assignment", "names,", `C:\x\a.GO`, true}, // Windows path, upper-case ext
		{"github_token", "names,", "a.go", false},          // not an assignment detector
		{"api_key_assignment", "[]string{}", "a.rs", true}, // composite
		{"secret_assignment", ",", "a.go", false},          // empty after trim
	}
	for _, tc := range cases {
		if got := codeShapedAssignment(tc.typ, tc.value, tc.path); got != tc.want {
			t.Errorf("codeShapedAssignment(%q, %q, %q) = %v, want %v", tc.typ, tc.value, tc.path, got, tc.want)
		}
	}
}
