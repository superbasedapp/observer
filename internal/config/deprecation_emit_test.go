package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeprecationEmitsOncePerProcess pins the log-noise fix: config.Load
// runs at ~20 call sites during a single `observer start` (proxy, watcher,
// dashboard, every feature goroutine, hooks auto-register), each re-parsing
// the same file. Before the dedup, every Load re-printed the identical block
// of deprecation lines, drowning the readiness banner. This test proves each
// distinct deprecation message is printed AT MOST ONCE across many Load calls
// in one process, and the follow-up hint prints exactly once — while the
// mapping itself still runs on every Load.
func TestDeprecationEmitsOncePerProcess(t *testing.T) {
	// A config carrying a removed codeintel key (warns) plus two of the
	// removed flat org_client.share obs_* aliases, which no longer warn: the
	// fields are gone and the config-migrate registry owns them on disk.
	body := `
[codeintel.index]
disk_budget_mb = 500

[org_client.share]
obs_summary = true
obs_traces = true
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Isolate from any deprecation state a prior test in this process left.
	resetDeprecationEmitForTest()
	t.Cleanup(resetDeprecationEmitForTest)

	// Capture os.Stderr (emitDeprecationOnce writes there directly).
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = origStderr })

	// Drain the pipe concurrently so writes never block on a full buffer.
	lines := make(chan string, 256)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()

	const loads = 20
	for i := 0; i < loads; i++ {
		if _, err := Load(LoadOptions{GlobalPath: path, Env: func(string) string { return "" }}); err != nil {
			t.Fatalf("Load #%d: %v", i, err)
		}
	}
	_ = w.Close()
	os.Stderr = origStderr

	counts := map[string]int{}
	total := 0
	for l := range lines {
		if strings.Contains(l, "obs_summary") || strings.Contains(l, "obs_traces") {
			t.Errorf("removed flat obs alias must not print a deprecation line: %q", l)
		}
		if strings.HasPrefix(l, "config: deprecation: ") {
			counts[l]++
			total++
		}
	}

	if len(counts) == 0 {
		t.Fatalf("expected deprecation lines, got none across %d Loads", loads)
	}
	for msg, n := range counts {
		if n != 1 {
			t.Errorf("deprecation line printed %d times (want 1): %q", n, msg)
		}
	}

	// Distinct per-key messages present (1 removed codeintel key; the flat
	// obs aliases are silent) plus exactly one hint line. Assert the hint fired once and that the
	// total equals the distinct count (i.e. nothing repeated).
	hintCount := 0
	for msg, n := range counts {
		if strings.Contains(msg, "deprecated aliases still honored") {
			hintCount += n
		}
	}
	if hintCount != 1 {
		t.Errorf("remediation hint printed %d times (want exactly 1)", hintCount)
	}
	if total != len(counts) {
		t.Errorf("total deprecation lines %d != distinct %d — something repeated", total, len(counts))
	}
	if total >= loads {
		t.Errorf("printed %d deprecation lines across %d Loads — dedup ineffective", total, loads)
	}
}
