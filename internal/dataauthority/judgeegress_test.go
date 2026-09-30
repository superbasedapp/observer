package dataauthority

import "testing"

// TestJudgeEgressAllowed pins JUDGE-1's decision table (docs/security.md):
// personal data always allowed, org/unknown data allowed only over a
// loopback endpoint or an org-pinned judge config, refused otherwise with
// a non-empty operator-facing reason.
func TestJudgeEgressAllowed(t *testing.T) {
	tests := []struct {
		name      string
		authority Authority
		endpoint  string
		orgPinned bool
		wantOK    bool
	}{
		{"personal + remote + not pinned", AuthorityPersonal, "https://openrouter.ai/api/v1", false, true},
		{"personal + loopback", AuthorityPersonal, "http://127.0.0.1:11434/v1", false, true},
		{"personal + remote + pinned", AuthorityPersonal, "https://openrouter.ai/api/v1", true, true},
		{"org + loopback + not pinned", AuthorityOrg, "http://127.0.0.1:11434/v1", false, true},
		{"org + loopback via localhost", AuthorityOrg, "http://localhost:11434/v1", false, true},
		{"org + 0.0.0.0 is NOT loopback (bind-wildcard, reachable from the LAN)", AuthorityOrg, "http://0.0.0.0:11434/v1", false, false},
		{"org + loopback-looking host is NOT loopback (substring-bypass attack string)", AuthorityOrg, "https://localhost.attacker.example/v1", false, false},
		{"org + loopback via bracketed ipv6", AuthorityOrg, "http://[::1]:11434/v1", false, true},
		{"org + remote + org-pinned", AuthorityOrg, "https://openrouter.ai/api/v1", true, true},
		{"org + remote + not pinned", AuthorityOrg, "https://openrouter.ai/api/v1", false, false},
		{"org + empty endpoint (resolves to a remote default) + not pinned", AuthorityOrg, "", false, false},
		{"unknown authority (zero value) + remote + not pinned", Authority(""), "https://openrouter.ai/api/v1", false, false},
		{"unknown authority (zero value) + loopback", Authority(""), "http://127.0.0.1:1234", false, true},
		{"unknown authority (zero value) + org-pinned", Authority(""), "https://openrouter.ai/api/v1", true, true},
		{"unrecognized authority string + remote + not pinned", Authority("bogus"), "https://openrouter.ai/api/v1", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := JudgeEgressAllowed(tt.authority, tt.endpoint, tt.orgPinned)
			if ok != tt.wantOK {
				t.Fatalf("JudgeEgressAllowed(%q, %q, %v) ok = %v, want %v (reason=%q)",
					tt.authority, tt.endpoint, tt.orgPinned, ok, tt.wantOK, reason)
			}
			if !ok && reason == "" {
				t.Fatal("a refusal must carry a non-empty operator-facing reason")
			}
			if ok && reason != "" {
				t.Fatalf("an allowed call must carry no reason, got %q", reason)
			}
		})
	}
}

// TestIsLoopbackJudgeEndpoint pins the exact-host loopback grammar (JUDGE-1
// finding 2, docs/security.md): a parsed-URL host compared against an exact
// allow-list, never a substring test. cmd/observer/judgeclient.go's
// isLoopbackJudgeURL delegates to this function, so this table is the single
// source of truth for both the egress gate above and the live client.
func TestIsLoopbackJudgeEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     bool
	}{
		{"127.0.0.1 literal", "http://127.0.0.1:11434/v1", true},
		{"other 127.0.0.0/8 address", "http://127.5.5.5:11434/v1", true},
		{"localhost hostname", "http://localhost:11434/v1", true},
		{"localhost is case-insensitive", "HTTP://LOCALHOST:11434/v1", true},
		{"bracketed ipv6 loopback", "http://[::1]:11434/v1", true},
		{"0.0.0.0 is a bind-wildcard, not loopback", "http://0.0.0.0:8080/v1", false},
		{"substring-bypass: localhost as a subdomain of an attacker host", "https://localhost.attacker.example/v1", false},
		{"substring-bypass: 127.0.0.1 embedded in an attacker hostname", "https://127.0.0.1.attacker.example/v1", false},
		{"substring-bypass: loopback text in the path, remote host", "https://api.openai.com/127.0.0.1/localhost", false},
		{"ordinary remote host", "https://openrouter.ai/api/v1", false},
		{"empty endpoint", "", false},
		{"unparseable endpoint", "http://[bad", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLoopbackJudgeEndpoint(tt.endpoint); got != tt.want {
				t.Errorf("IsLoopbackJudgeEndpoint(%q) = %v, want %v", tt.endpoint, got, tt.want)
			}
		})
	}
}
