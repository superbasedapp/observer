package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// TestRescanPassesTable pins buildRescanPasses' flag/adapter/label/note
// strings so the table-driven refactor of the `--<adapter>-rescan`
// ladder (cmd/observer/backfill.go) stays byte-identical to the
// pre-refactor per-flag if-blocks it replaced: same error-wrap prefix,
// same adapterFilter passed to buildWatcherWithOverride, and same
// stdout summary line. A future edit that silently changes one of
// these strings — breaking a script or doc example that greps for the
// exact text — fails here instead of only showing up live.
func TestRescanPassesTable(t *testing.T) {
	var (
		cowork, codex, antigravity, antigravityCli bool
		geminiCli, copilotCli, hermes, clinecli    bool
		cache, zed                                 bool
	)
	passes := buildRescanPasses(
		&cowork, &codex, &antigravity, &antigravityCli,
		&geminiCli, &copilotCli, &hermes, &clinecli,
		&cache, &zed,
	)

	type want struct {
		enabledPtr *bool
		flag       string
		adapter    string
		label      string
		note       string
	}
	wants := []want{
		{&cowork, "--cowork-rescan", "cowork", "cowork", "cowork audit.jsonl only"},
		{&codex, "--codex-rescan", "codex", "codex", "codex rollouts only"},
		{&antigravity, "--antigravity-rescan", "antigravity", "antigravity", "antigravity .pb / state.vscdb only"},
		{&antigravityCli, "--antigravity-cli-rescan", "antigravity-cli", "antigravity-cli", "antigravity-cli .pb / .db only"},
		{&geminiCli, "--gemini-cli-rescan", "gemini-cli", "gemini-cli", "~/.gemini/tmp only"},
		{&copilotCli, "--copilot-cli-rescan", "copilot-cli", "copilot-cli", "~/.copilot/{session-state,logs} only"},
		{&hermes, "--hermes-rescan", "hermes", "hermes", "~/.hermes/state.db only"},
		{&clinecli, "--clinecli-rescan", "cline-cli", "cline-cli", "~/.cline/data/db/sessions.db only"},
		{&cache, "--cache-rescan", "claude-code", "cache", "claude-code transcripts through the Tier-2 cache engine; idempotent via CacheEventExistsForMessage"},
		{&zed, "--zed-rescan", "zed", "zed", "threads.db only; watermark reset (fromOffset=0) re-reads every thread regardless of updated_at"},
	}

	if len(passes) != len(wants) {
		t.Fatalf("len(passes) = %d, want %d", len(passes), len(wants))
	}
	for i, w := range wants {
		p := passes[i]
		if p.enabled != w.enabledPtr {
			t.Errorf("passes[%d].enabled does not point at the expected flag var (order/wiring drifted)", i)
		}
		if p.flag != w.flag {
			t.Errorf("passes[%d].flag = %q, want %q", i, p.flag, w.flag)
		}
		if p.adapter != w.adapter {
			t.Errorf("passes[%d].adapter = %q, want %q", i, p.adapter, w.adapter)
		}
		if p.label != w.label {
			t.Errorf("passes[%d].label = %q, want %q", i, p.label, w.label)
		}
		if p.note != w.note {
			t.Errorf("passes[%d].note = %q, want %q", i, p.note, w.note)
		}
	}
}

// TestRescanPassesStdoutFormat pins the exact stdout line shape
// rescanPass.summaryLine (cmd/observer/backfill.go) produces — calling
// the PRODUCTION method directly rather than re-implementing its
// fmt.Sprintf template here, so a future edit to summaryLine that
// silently changes the line shape fails THIS test instead of both this
// test and summaryLine drifting together, undetected. Checked against
// the nine pre-existing flags' known-good literal strings (the tenth,
// --zed-rescan, is new and has no pre-refactor literal to match).
func TestRescanPassesStdoutFormat(t *testing.T) {
	cases := []struct {
		label, note string
		want        string
	}{
		{"cowork", "cowork audit.jsonl only", "cowork rescan complete: files_processed=3 errors=1 (cowork audit.jsonl only)\n"},
		{"codex", "codex rollouts only", "codex rescan complete: files_processed=3 errors=1 (codex rollouts only)\n"},
		{"antigravity", "antigravity .pb / state.vscdb only", "antigravity rescan complete: files_processed=3 errors=1 (antigravity .pb / state.vscdb only)\n"},
		{"antigravity-cli", "antigravity-cli .pb / .db only", "antigravity-cli rescan complete: files_processed=3 errors=1 (antigravity-cli .pb / .db only)\n"},
		{"gemini-cli", "~/.gemini/tmp only", "gemini-cli rescan complete: files_processed=3 errors=1 (~/.gemini/tmp only)\n"},
		{"copilot-cli", "~/.copilot/{session-state,logs} only", "copilot-cli rescan complete: files_processed=3 errors=1 (~/.copilot/{session-state,logs} only)\n"},
		{"hermes", "~/.hermes/state.db only", "hermes rescan complete: files_processed=3 errors=1 (~/.hermes/state.db only)\n"},
		{"cline-cli", "~/.cline/data/db/sessions.db only", "cline-cli rescan complete: files_processed=3 errors=1 (~/.cline/data/db/sessions.db only)\n"},
		{"cache", "claude-code transcripts through the Tier-2 cache engine; idempotent via CacheEventExistsForMessage", "cache rescan complete: files_processed=3 errors=1 (claude-code transcripts through the Tier-2 cache engine; idempotent via CacheEventExistsForMessage)\n"},
	}
	for _, c := range cases {
		p := rescanPass{label: c.label, note: c.note}
		got := p.summaryLine(watcher.ScanResult{FilesProcessed: 3, Errors: 1})
		if got != c.want {
			t.Errorf("summaryLine(label=%q, note=%q) = %q, want %q", c.label, c.note, got, c.want)
		}
	}
}
