package workspace

import "testing"

func TestValidateRemoteURL(t *testing.T) {
	cases := []struct {
		name         string
		url          string
		allowedHosts []string
		wantErr      bool
	}{
		{"https-accept", "https://github.com/example/repo.git", nil, false},
		{"ssh-accept", "ssh://git@github.com/example/repo.git", nil, false},
		{"scp-form-accept", "git@github.com:example/repo.git", nil, false},
		{"scp-form-no-subdir-accept", "git@github.com:repo.git", nil, false},

		{"empty-reject", "", nil, true},
		{"ext-transport-reject", "ext::sh -c 'rm -rf /'", nil, true},
		// A whitespace-free ext:: payload: isolates the ext:: guard itself.
		// Without it hostOf() parses "ext::evil" as a valid host and the URL
		// is ACCEPTED (the whitespace guard above only catches the spaced
		// form) — so removing the ext:: check must fail HERE, not elsewhere.
		{"ext-transport-no-space-reject", "ext::evil", nil, true},
		// RB1 sweep S2: every <helper>::<address> form runs git-remote-<helper>.
		{"fd-helper-reject", "fd::0", nil, true},
		{"named-helper-reject", "testgit::x", nil, true},
		{"hg-helper-reject", "hg::https://example.com/r", nil, true},
		{"file-scheme-reject", "file:///etc/passwd", nil, true},
		{"leading-dash-reject", "-evilhost/repo.git", nil, true},
		{"upload-pack-embedded-reject", "https://github.com/x/--upload-pack=evil.git", nil, true},
		{"receive-pack-embedded-reject", "https://github.com/x/--receive-pack=evil.git", nil, true},
		{"nul-byte-reject", "https://github.com/x\x00y.git", nil, true},
		{"whitespace-reject", "https://github.com/x y.git", nil, true},
		{"control-char-reject", "https://github.com/x\ny.git", nil, true},
		{"unsupported-git-scheme-reject", "git://github.com/example/repo.git", nil, true},
		{"unsupported-http-scheme-reject", "http://github.com/example/repo.git", nil, true},
		{"windows-drive-letter-not-scp-form-reject", `C:\repo`, nil, true},
		{"bare-token-not-a-remote-reject", "repo.git", nil, true},

		{"host-allowlist-hit", "https://github.com/example/repo.git", []string{"github.com"}, false},
		{"host-allowlist-hit-case-insensitive", "https://GitHub.com/example/repo.git", []string{"github.com"}, false},
		{"host-allowlist-miss", "https://evil.example.com/x.git", []string{"github.com"}, true},
		{"host-allowlist-scp-form-hit", "git@github.com:example/repo.git", []string{"github.com"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRemoteURL(tc.url, tc.allowedHosts)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateRemoteURL(%q, %v): want error, got nil", tc.url, tc.allowedHosts)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateRemoteURL(%q, %v): unexpected error: %v", tc.url, tc.allowedHosts, err)
			}
		})
	}
}
