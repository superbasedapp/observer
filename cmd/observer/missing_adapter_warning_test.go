package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// stubAdapter is a minimal adapter.Adapter used only to exercise the
// warning emitter. The real adapter set is checked by the
// internal/adapter/defaults invariant tests, so this avoids importing
// the full default set + its transitive dependencies here.
type stubAdapter struct{ name string }

func (s *stubAdapter) Name() string              { return s.name }
func (s *stubAdapter) WatchPaths() []string      { return nil }
func (s *stubAdapter) IsSessionFile(string) bool { return false }
func (s *stubAdapter) ParseSessionFile(context.Context, string, int64) (adapter.ParseResult, error) {
	panic("unused")
}

// TestWarnMissingDefaultsFromAllowList_NamesEveryGap pins the
// long-term Invariant #51 fix: when the user's config.toml carries an
// explicit `enabled_adapters` list from a prior release and one or
// more registered defaults are absent, observer start logs a WARN
// naming each missing tool and the exact remediation. Silent when
// the allow-list is empty (fresh installs let Default() populate the
// full set) or when every default is present.
func TestWarnMissingDefaultsFromAllowList_NamesEveryGap(t *testing.T) {
	defaults := []adapter.Adapter{
		&stubAdapter{name: "claude-code"},
		&stubAdapter{name: "cowork"},
		&stubAdapter{name: "codex"},
	}
	cases := []struct {
		name     string
		allow    []string
		wantWarn bool
		mustHave []string // substrings the WARN log line must contain
		mustOmit []string // substrings the WARN log line must NOT contain
	}{
		{
			name:     "fresh install — empty allow-list — no warning",
			allow:    nil,
			wantWarn: false,
		},
		{
			name:     "every default present — no warning",
			allow:    []string{"claude-code", "cowork", "codex"},
			wantWarn: false,
		},
		{
			name:     "one missing — names that one",
			allow:    []string{"claude-code", "codex"},
			wantWarn: true,
			mustHave: []string{"cowork", "enabled_adapters", "config.toml"},
			mustOmit: []string{"\"missing\":\"claude-code\"", "\"missing\":\"codex\""},
		},
		{
			name:     "one missing — names the exact remedy command",
			allow:    []string{"claude-code", "codex"},
			wantWarn: true,
			mustHave: []string{
				"observer config adopt-defaults",
				"--write",
				"not be captured",
			},
		},
		{
			name:     "multiple missing — names all in stable order",
			allow:    []string{"codex"},
			wantWarn: true,
			mustHave: []string{"claude-code", "cowork", "observer config adopt-defaults"},
		},
		{
			name:     "user list has extra unknown tool — only reports missing-from-defaults",
			allow:    []string{"claude-code", "cowork", "codex", "future-tool"},
			wantWarn: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			warnMissingDefaultsFromAllowList(logger, defaults, tc.allow)
			out := buf.String()
			gotWarn := strings.Contains(out, `level=WARN`)
			if gotWarn != tc.wantWarn {
				t.Fatalf("wantWarn=%v got=%v; log=%q", tc.wantWarn, gotWarn, out)
			}
			for _, need := range tc.mustHave {
				if !strings.Contains(out, need) {
					t.Errorf("log missing %q; got %q", need, out)
				}
			}
			for _, bad := range tc.mustOmit {
				if strings.Contains(out, bad) {
					t.Errorf("log should not contain %q; got %q", bad, out)
				}
			}
		})
	}
}
