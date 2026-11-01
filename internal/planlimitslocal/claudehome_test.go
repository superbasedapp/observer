package planlimitslocal

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/planlimits"
)

// TestClaudeHomeFollowsTheOneResolver pins FU-131 / FU-138 for the local
// plan-limits reader: the Claude base resolves through
// agentconfig.ClaudeConfigDir, so ANTHROPIC_CONFIG_DIR is honoured after
// CLAUDE_CONFIG_DIR and a relative value names no directory (the read is
// unavailable, never the ~/.claude default).
func TestClaudeHomeFollowsTheOneResolver(t *testing.T) {
	home, cfg, alt := t.TempDir(), t.TempDir(), t.TempDir()
	src, _ := planlimits.SourceByID(planlimits.SourceClaudeOAuth)
	spec := src.Local[0]

	r := fakeReader(home, cfg, map[string]string{"ANTHROPIC_CONFIG_DIR": alt})
	if p, err := r.Path(spec); err != nil || p != filepath.Join(alt, ".credentials.json") {
		t.Errorf("ANTHROPIC_CONFIG_DIR: Path = (%q, %v)", p, err)
	}
	for _, env := range []map[string]string{
		{"CLAUDE_CONFIG_DIR": filepath.Join("rel", "cfg")},
		{"ANTHROPIC_CONFIG_DIR": "rel"},
		{"CLAUDE_CONFIG_DIR": "rel", "ANTHROPIC_CONFIG_DIR": alt},
	} {
		r := fakeReader(home, cfg, env)
		if p, err := r.Path(spec); !errors.Is(err, planlimits.ErrUnavailable) || p != "" {
			t.Errorf("%v: Path = (%q, %v), want unavailable", env, p, err)
		}
	}
	// A set absolute variable needs no home.
	r = Reader{
		Getenv:    func(k string) string { return map[string]string{"CLAUDE_CONFIG_DIR": alt}[k] },
		Home:      func() (string, error) { return "", errors.New("no home") },
		ConfigDir: func() (string, error) { return cfg, nil },
	}
	if p, err := r.Path(spec); err != nil || p != filepath.Join(alt, ".credentials.json") {
		t.Errorf("no home, absolute CLAUDE_CONFIG_DIR: Path = (%q, %v)", p, err)
	}
}
