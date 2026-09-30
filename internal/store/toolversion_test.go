package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestSetSessionToolVersion pins the captured tool/CLI version column
// (migration 125) under FIRST-WINS-UNLESS-EMPTY: the first grounded
// stamp lands, an identical re-stamp reports no change, an empty version
// preserves what is stored, a DIFFERING later stamp is a no-op (a
// re-parse never rewrites a captured origin), and a stamp that fills a
// still-empty column IS a change.
func TestSetSessionToolVersion(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/toolver", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "tv-sess", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	read := func() string {
		var v string
		if err := database.QueryRowContext(ctx,
			`SELECT COALESCE(tool_version,'') FROM sessions WHERE id='tv-sess'`,
		).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	cases := []struct {
		name        string
		in          models.SessionToolVersion
		wantChanged bool
		wantErr     bool
		want        string
	}{
		{
			name:        "first stamp lands",
			in:          models.SessionToolVersion{SessionID: "tv-sess", Version: "0.150.0"},
			wantChanged: true, want: "0.150.0",
		},
		{
			name:        "identical re-stamp is a no-op",
			in:          models.SessionToolVersion{SessionID: "tv-sess", Version: "0.150.0"},
			wantChanged: false, want: "0.150.0",
		},
		{
			name:        "empty version preserves",
			in:          models.SessionToolVersion{SessionID: "tv-sess"},
			wantChanged: false, want: "0.150.0",
		},
		{
			// First-wins: a later parse re-deriving a different version
			// must not rewrite the captured origin.
			name:        "differing later version does NOT overwrite",
			in:          models.SessionToolVersion{SessionID: "tv-sess", Version: "0.151.0"},
			wantChanged: false, want: "0.150.0",
		},
		{
			name:    "missing session id is an error",
			in:      models.SessionToolVersion{Version: "1.0.0"},
			wantErr: true, want: "0.150.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed, err := s.SetSessionToolVersion(ctx, tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantErr && changed != tc.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tc.wantChanged)
			}
			if got := read(); got != tc.want {
				t.Errorf("stored version = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSetSessionToolVersionRejectsMalformed pins the bounded-token
// validation: a value that is whitespace-bearing, control-bearing,
// prose, or over the length cap is SKIPPED (returns false, nil) and
// never persisted — the honest "unknown" empty is preserved.
func TestSetSessionToolVersionRejectsMalformed(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()

	pid, _ := s.UpsertProject(ctx, "/tmp/toolver-bad", "")
	if err := s.UpsertSession(ctx, models.Session{
		ID: "tv-bad", ProjectID: pid, Tool: models.ToolClaudeCode,
		StartedAt: time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
	read := func() string {
		var v string
		if err := database.QueryRowContext(ctx,
			`SELECT COALESCE(tool_version,'') FROM sessions WHERE id='tv-bad'`,
		).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	bad := []struct {
		name    string
		version string
	}{
		{"has a space", "version 1.2.3"},
		{"has a tab", "1.2.3\t"},
		{"has a newline", "1.2.3\n"},
		{"has a control byte", "1.2.\x00"},
		{"prose", "the latest build as of tuesday"},
		{"over the length cap", strings.Repeat("9", maxToolVersionRunes+1)},
		{"empty", ""},
		// TOOLVERSION-1 (docs/security.md): the grammar rejects shapes a
		// URL/email/path/compact-secret needs but a real version never does.
		{"url scheme", "https://x"},
		{"url with host and path", "https://attacker.example/collect"},
		{"email-shaped", "user@example"},
		{"path traversal", "../../client"},
		{"absolute path", "/etc/passwd"},
		{"leading dot", ".hidden"},
		{"leading hyphen", "-1.2.3"},
		{"embedded colon", "sbo:secret-token"},
		{"embedded slash", "1.2/3"},
		{"compact base64-shaped secret with padding", "c2VjcmV0LXRva2VuLXZhbHVl="},
		// TOOLVERSION-1 follow-up (2026-09-23): the grammar now requires a
		// leading digit (after an optional "v"/"V") AND at least one ".",
		// which a compact secret's alphanumeric noise never has.
		{"AWS access key id", "AKIAIOSFODNN7EXAMPLE"},
		{"GitHub PAT", "ghp_abcdefghijklmnopqrstuvwxyz1234567890"},
		{"JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
		{"hex sha (no dot)", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"hex sha, digit-leading (no dot)", "0d3b45c1a2f6e8b9c0d1e2f3a4b5c6d7e8f9a0b1"},
		{"UUID (no dot)", "550e8400-e29b-41d4-a716-446655440000"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			changed, err := s.SetSessionToolVersion(ctx, models.SessionToolVersion{
				SessionID: "tv-bad", Version: tc.version,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if changed {
				t.Errorf("malformed value reported changed=true; want false")
			}
			if got := read(); got != "" {
				t.Errorf("malformed value was persisted: %q", got)
			}
		})
	}

	// A value at exactly the length cap, version-shaped (leading "v", a
	// digit, and a "."), with no whitespace/control, IS accepted — the cap
	// is inclusive. "v9." (3 runes) + 61 more digits = 64 runes total.
	okVer := "v9." + strings.Repeat("9", maxToolVersionRunes-3)
	if len(okVer) != maxToolVersionRunes {
		t.Fatalf("test setup bug: okVer length = %d, want %d", len(okVer), maxToolVersionRunes)
	}
	changed, err := s.SetSessionToolVersion(ctx, models.SessionToolVersion{SessionID: "tv-bad", Version: okVer})
	if err != nil || !changed {
		t.Fatalf("value at length cap should be accepted: changed=%v err=%v", changed, err)
	}
	if got := read(); got != okVer {
		t.Errorf("stored = %q, want %q", got, okVer)
	}
}

// TestValidToolVersionAdmitsRealVendorShapes pins that the TOOLVERSION-1
// grammar (delegated to orgcontract.ValidToolVersion) admits every shape a
// real adapter actually stamps: plain semver, a "v"-prefixed CLI version, a
// date-based CalVer release, and semver with a prerelease or build-metadata
// suffix (grepped from internal/adapter/{claudecode,codex,cline,kilocode,
// qoder,copilotcli,qwencode} 2026-09-22).
func TestValidToolVersionAdmitsRealVendorShapes(t *testing.T) {
	t.Parallel()
	good := []string{
		"1.2.3",
		"2026.8.2",
		"v0.130.0",
		"1.8.1-rc.1",
		"0.45.0+build.7",
		"2.1.0_beta",
		"0.150.0",
		"3.17.4-beta.1",
	}
	for _, v := range good {
		if !validToolVersion(v) {
			t.Errorf("validToolVersion(%q) = false, want true (a real vendor-stamped shape)", v)
		}
	}
}
