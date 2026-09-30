package orgcontract

import "testing"

// TestValidToolVersion pins the TOOLVERSION-1 grammar (docs/security.md):
// version-shaped (optional leading "v"/"V", then a digit, then up to 62
// more alphanumeric/"."/"_"/"+"/"-" characters, AND at least one "."
// anywhere) tokens pass; everything else — including the compact-secret
// class this grammar was tightened to exclude on 2026-09-23 — fails.
func TestValidToolVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		v    string
		want bool
	}{
		// Real vendor-stamped shapes (grepped from
		// internal/adapter/{claudecode,codex,cline,kilocode,qoder,
		// copilotcli,qwencode} 2026-09-22): all must still pass.
		{"plain semver", "1.2.3", true},
		{"CalVer", "2026.8.2", true},
		{"v-prefixed CLI version", "v0.130.0", true},
		{"V-prefixed (uppercase)", "V0.130.0", true},
		{"semver with prerelease", "1.8.1-rc.1", true},
		{"semver with build metadata", "0.45.0+build.7", true},
		{"underscore qualifier", "2.1.0_beta", true},
		{"two-part version", "3.17", true},

		// Compact secrets: the class this grammar was tightened to
		// exclude (finding 5, 2026-09-23 round-5 review). None of these
		// are digit-led-with-a-dot.
		{"AWS access key id", "AKIAIOSFODNN7EXAMPLE", false},
		{"GitHub PAT", "ghp_abcdefghijklmnopqrstuvwxyz1234567890", false},
		{"JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", false},
		{"hex sha (letter-leading, no dot)", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"hex sha (digit-leading, no dot)", "0d3b45c1a2f6e8b9c0d1e2f3a4b5c6d7e8f9a0b1", false},
		{"UUID (digit-leading, no dot)", "550e8400-e29b-41d4-a716-446655440000", false},
		{"email address", "user@example.com", false},

		// Previously-excluded attack shapes: must remain excluded.
		{"URL scheme", "https://x", false},
		{"URL with host and path", "https://attacker.example/collect", false},
		{"path traversal", "../../client", false},
		{"absolute path", "/etc/passwd", false},
		{"embedded colon", "sbo:secret-token", false},
		{"embedded slash", "1.2/3", false},
		{"base64-shaped with padding", "c2VjcmV0LXRva2VuLXZhbHVl=", false},

		// Structural edge cases specific to the new digit-led + dot rule.
		{"letter-leading, no v prefix", "abc.1.2", false},
		{"no dot at all", "v123456", false},
		{"dot but not digit-leading", "v.1.2.3", false},
		{"leading hyphen", "-1.2.3", false},
		{"leading dot", ".1.2.3", false},
		{"whitespace", "1.2.3 ", false},
		{"empty", "", false},
		{"over the length cap", "v9." + repeat9(MaxToolVersionRunes-3+1), false},
		{"at the length cap", "v9." + repeat9(MaxToolVersionRunes-3), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidToolVersion(tc.v); got != tc.want {
				t.Errorf("ValidToolVersion(%q) = %v, want %v", tc.v, got, tc.want)
			}
		})
	}
}

// repeat9 returns a string of n '9' runes, used to build length-boundary
// test values without importing strings.Repeat at every call site.
func repeat9(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '9'
	}
	return string(b)
}
