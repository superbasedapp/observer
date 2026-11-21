package pathnorm

import "testing"

// TestIsLocalAbsPathFor pins the stored-path open gate (ledger
// CLOUDSESS-12) for both OS families on any host: UNC, device and
// extended-length paths are refused everywhere, a Windows transcript path
// stays readable on Windows (the reason the readers moved from a SQL
// `LIKE '/%'` to an absoluteness check), and a non-path marker never opens.
func TestIsLocalAbsPathFor(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		windows bool
		posix   bool
	}{
		{"empty", "", false, false},
		{"UNC with backslashes", `\\attacker.example\share\a.jsonl`, false, false},
		{"UNC over WebDAV SSL", `\\host@SSL\s\a.jsonl`, false, false},
		{"UNC with forward slashes", `//host/s/a.jsonl`, false, false},
		{"mixed leading separators", `\/host/s/a.jsonl`, false, false},
		{"mixed leading separators reversed", `/\host\s\a.jsonl`, false, false},
		{"extended-length prefix", `\\?\C:\Users\me\a.jsonl`, false, false},
		{"device namespace", `\\.\pipe\x.jsonl`, false, false},
		{"NUL byte", "/home/me/a\x00.jsonl", false, false},
		{"cloud-session synthetic marker", "cloud-session:0123abcd", false, false},
		{"hook sentinel", "claude-code:hook", false, false},
		{"relative", "transcripts/a.jsonl", false, false},
		{"Windows transcript path", `C:\Users\me\.claude\projects\x\a.jsonl`, true, false},
		{"Windows path with forward slashes", `c:/Users/me/a.jsonl`, true, false},
		{"volume-less rooted Windows path", `\Users\me\a.jsonl`, false, false},
		{"drive-relative Windows path", `C:Users\me\a.jsonl`, false, false},
		{"alternate data stream", `C:\Users\me\a.jsonl:secret`, false, false},
		{"reserved device element", `C:\Users\me\NUL.jsonl`, false, false},
		{"reserved device element mid-path", `C:\x\com1\a.jsonl`, false, false},
		{"reserved-looking but longer name", `C:\x\console.jsonl`, true, false},
		{"POSIX transcript path", "/home/me/.claude/projects/x/a.jsonl", false, true},
		{"POSIX path with a colon", "/home/me/a:b.jsonl", false, true},
	}
	for _, tc := range cases {
		if got := isLocalAbsPathFor(tc.path, "windows"); got != tc.windows {
			t.Errorf("%s on windows: %q = %v, want %v", tc.name, tc.path, got, tc.windows)
		}
		for _, goos := range []string{"linux", "darwin"} {
			if got := isLocalAbsPathFor(tc.path, goos); got != tc.posix {
				t.Errorf("%s on %s: %q = %v, want %v", tc.name, goos, tc.path, got, tc.posix)
			}
		}
	}
}
