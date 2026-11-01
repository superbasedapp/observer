package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/claudecode"
	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/oneshot"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// usageTestEnv is one hermetic one-shot environment: a fake HOME, a fake
// TMPDIR (so the scratch-dir lifecycle can be asserted), and the injected
// seams the command runs against.
type usageTestEnv struct {
	home   string
	tmpdir string
	deps   usageDeps
}

// newUsageTestEnv builds the fake environment. adapters is the EXACT
// adapter set the scan will see — never adapterdefaults.Adapters(), which
// on a WSL host would walk the operator's real Linux AND Windows homes.
func newUsageTestEnv(t *testing.T, adapters ...adapter.Adapter) *usageTestEnv {
	t.Helper()
	home := t.TempDir()
	tmpdir := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // windows equivalent
	setTestTempDir(t, tmpdir)
	t.Setenv("NO_COLOR", "1")
	return &usageTestEnv{
		home:   home,
		tmpdir: tmpdir,
		deps: usageDeps{
			adapters: func() []adapter.Adapter { return adapters },
			homeDir:  func() (string, error) { return home, nil },
			getenv:   os.Getenv,
			now:      func() time.Time { return time.Now().UTC() },
		},
	}
}

// run executes `observer usage` with args and returns (stdout, stderr, err).
func (e *usageTestEnv) run(t *testing.T, args ...string) (string, string, error) {
	// Not nil: nil makes cobra read the test binary's own os.Args (a
	// `-test.run X` given as two arguments became an unknown command).
	if args == nil {
		args = []string{}
	}
	t.Helper()
	cmd := newUsageCmd(e.deps)
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

// seedClaudeCode writes the repo's claude-code fixture under the fake HOME
// at the path the adapter's WatchPaths expect, with its timestamps shifted
// into the default 30-day window. Returns the watch root.
func seedClaudeCode(t *testing.T, home string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	recent := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	body := strings.ReplaceAll(string(raw), "2026-04-16", recent)

	root := filepath.Join(home, ".claude", "projects")
	dir := filepath.Join(root, "-tmp-superbased-fixture-simple")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir fixture dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sess-001.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return root
}

// assertNoObserverHome is the trust assertion: the one-shot path must
// never create anything under $HOME/.observer.
func assertNoObserverHome(t *testing.T, home string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(home, ".observer")); !os.IsNotExist(err) {
		t.Fatalf("$HOME/.observer must not exist after a one-shot run (stat err=%v)", err)
	}
}

// assertScratchDirsGone asserts every observer-usage-* scratch dir under
// tmpdir was removed.
func assertScratchDirsGone(t *testing.T, tmpdir string) {
	t.Helper()
	entries, err := os.ReadDir(tmpdir)
	if err != nil {
		t.Fatalf("read tmpdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), oneShotDirPrefix) {
			t.Fatalf("scratch dir %q survived the run", e.Name())
		}
	}
}

// seedClaudeCodeMultiDay writes N copies of the claude-code fixture into
// one watch root, each shifted to a distinct day within the reporting
// window — same tool, same model, spread across multiple days. Used to
// pin the difference between "distinct day count" and "distinct tool/
// model count" (F11).
func seedClaudeCodeMultiDay(t *testing.T, home string, dayOffsets []int) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "simple-session.jsonl"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	root := filepath.Join(home, ".claude", "projects")
	dir := filepath.Join(root, "-tmp-superbased-fixture-simple")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir fixture dir: %v", err)
	}
	for i, off := range dayOffsets {
		day := time.Now().UTC().AddDate(0, 0, off).Format("2006-01-02")
		body := strings.ReplaceAll(string(raw), "2026-04-16", day)
		name := fmt.Sprintf("sess-%03d.jsonl", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write fixture %d: %v", i, err)
		}
	}
	return root
}

// mirrorProbeAdapter is a minimal adapter.Adapter double whose WatchPaths
// queries internal/adapter/mirrorbase.Base() as a side effect and records
// every value it observed — standing in for the 7 real adapters
// (opencode, kilocode, clinecli, devin, kirocli, goose, crush) that stage
// a foreign-mount SQLite mirror through that same seam (F1). It reports a
// real, existing directory so adapter.Registry.Detected considers it
// present.
type mirrorProbeAdapter struct {
	dir string
	mu  sync.Mutex
	obs []string
}

func newMirrorProbeAdapter(t *testing.T) *mirrorProbeAdapter {
	t.Helper()
	return &mirrorProbeAdapter{dir: t.TempDir()}
}

func (a *mirrorProbeAdapter) Name() string { return "mirror-probe" }

func (a *mirrorProbeAdapter) WatchPaths() []string {
	if base, err := mirrorbase.Base(); err == nil {
		a.mu.Lock()
		a.obs = append(a.obs, base)
		a.mu.Unlock()
	}
	return []string{a.dir}
}

func (a *mirrorProbeAdapter) IsSessionFile(string) bool { return false }

func (a *mirrorProbeAdapter) ParseSessionFile(context.Context, string, int64) (adapter.ParseResult, error) {
	return adapter.ParseResult{}, nil
}

// observedBases returns every mirrorbase.Base() value seen so far.
func (a *mirrorProbeAdapter) observedBases() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.obs...)
}

// ---------------------------------------------------------------------------
// the table
// ---------------------------------------------------------------------------

// TestUsageCmd_TableAndZeroSideEffects is the headline case: a seeded
// claude-code corpus produces the expected tool×model row, the honesty
// footer is present, $HOME/.observer is never created, and the scratch
// directory is gone.
func TestUsageCmd_TableAndZeroSideEffects(t *testing.T) {
	env := newUsageTestEnv(t)
	root := seedClaudeCode(t, env.home)
	env.deps.adapters = func() []adapter.Adapter {
		return []adapter.Adapter{claudecode.NewWithOptions(nil, root)}
	}

	out, errOut, err := env.run(t)
	if err != nil {
		t.Fatalf("usage: %v (stderr=%s)", err, errOut)
	}
	for _, want := range []string{
		"SuperBased - observed agent spend, last 30 days",
		"one-shot · no daemon",
		"TOOL", "MODEL", "CACHE_R", "CACHE_W", "TURNS", "USD",
		"claude-code",
		"claude-sonnet-4-20250514",
		"TOTAL",
		oneshot.PriceBasis,
		"observer start",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q:\n%s", want, out)
		}
	}
	// Honesty negatives (the retracted-savings class).
	for _, forbidden := range []string{"saved", "%"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("stdout must not contain %q:\n%s", forbidden, out)
		}
	}
	if !strings.Contains(errOut, "detected 1 of 1 adapters: claude-code") {
		t.Errorf("stderr missing the detected-tools line:\n%s", errOut)
	}
	assertNoObserverHome(t, env.home)
	assertScratchDirsGone(t, env.tmpdir)
}

// TestUsageCmd_KeepDB pins --keep-db: the scratch database is moved to the
// requested path (exactly one file), the path is echoed, and the scratch
// dir is still cleaned up.
func TestUsageCmd_KeepDB(t *testing.T) {
	env := newUsageTestEnv(t)
	root := seedClaudeCode(t, env.home)
	env.deps.adapters = func() []adapter.Adapter {
		return []adapter.Adapter{claudecode.NewWithOptions(nil, root)}
	}
	dest := filepath.Join(t.TempDir(), "kept", "usage.db")

	out, errOut, err := env.run(t, "--keep-db", dest)
	if err != nil {
		t.Fatalf("usage --keep-db: %v (stderr=%s)", err, errOut)
	}
	if !strings.Contains(out, "kept the scratch database at "+dest) {
		t.Errorf("stdout missing the kept-db line:\n%s", out)
	}
	if fi, serr := os.Stat(dest); serr != nil || fi.IsDir() || fi.Size() == 0 {
		t.Fatalf("kept db missing/empty at %s (err=%v)", dest, serr)
	}
	entries, err := os.ReadDir(filepath.Dir(dest))
	if err != nil {
		t.Fatalf("read kept dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly one kept DB file, got %d: %v", len(entries), entries)
	}
	assertNoObserverHome(t, env.home)
	assertScratchDirsGone(t, env.tmpdir)
}

// TestUsageCmd_BudgetPartial pins the wall-clock budget: an absurdly small
// budget stops the scan, the footer says so honestly, and the command
// still exits nil.
func TestUsageCmd_BudgetPartial(t *testing.T) {
	env := newUsageTestEnv(t)
	root := seedClaudeCode(t, env.home)
	env.deps.adapters = func() []adapter.Adapter {
		return []adapter.Adapter{claudecode.NewWithOptions(nil, root)}
	}

	out, errOut, err := env.run(t, "--budget", "1ns")
	if err != nil {
		t.Fatalf("usage --budget 1ns must exit nil, got %v (stderr=%s)", err, errOut)
	}
	if !strings.Contains(out, "scan stopped at the 1ns budget") {
		t.Errorf("stdout missing the partial-scan note:\n%s", out)
	}
	assertNoObserverHome(t, env.home)
	assertScratchDirsGone(t, env.tmpdir)
}

// TestUsageCmd_EmptyCorpus pins the empty state: an empty HOME is not an
// error, and the output says where we looked.
func TestUsageCmd_EmptyCorpus(t *testing.T) {
	env := newUsageTestEnv(t)
	env.deps.adapters = func() []adapter.Adapter {
		return []adapter.Adapter{claudecode.NewWithOptions(nil, filepath.Join(env.home, ".claude", "projects"))}
	}

	out, errOut, err := env.run(t)
	if err != nil {
		t.Fatalf("empty corpus must exit nil, got %v (stderr=%s)", err, errOut)
	}
	if !strings.Contains(out, "no session activity found under "+env.home) {
		t.Errorf("stdout missing the empty-state line:\n%s", out)
	}
	if !strings.Contains(errOut, "no AI coding tools detected") {
		t.Errorf("stderr missing the no-tools progress line:\n%s", errOut)
	}
	assertNoObserverHome(t, env.home)
	assertScratchDirsGone(t, env.tmpdir)
}

// TestUsageCmd_JSON pins the --json envelope: it unmarshals, carries the
// stable schema discriminator, the price basis, and at least one row.
func TestUsageCmd_JSON(t *testing.T) {
	env := newUsageTestEnv(t)
	root := seedClaudeCode(t, env.home)
	env.deps.adapters = func() []adapter.Adapter {
		return []adapter.Adapter{claudecode.NewWithOptions(nil, root)}
	}

	out, errOut, err := env.run(t, "--json")
	if err != nil {
		t.Fatalf("usage --json: %v (stderr=%s)", err, errOut)
	}
	var env2 struct {
		Schema string `json:"schema"`
		Window struct {
			Since   string `json:"since"`
			Label   string `json:"label"`
			Partial bool   `json:"partial"`
		} `json:"window"`
		Tier       string `json:"tier"`
		PriceBasis string `json:"price_basis"`
		Rows       []struct {
			Tool  string  `json:"tool"`
			Model string  `json:"model"`
			USD   float64 `json:"usd"`
		} `json:"rows"`
		Total struct {
			Tools int `json:"tools"`
			Turns int `json:"turns"`
		} `json:"total"`
	}
	if err := json.Unmarshal([]byte(out), &env2); err != nil {
		t.Fatalf("unmarshal --json output: %v\n%s", err, out)
	}
	if env2.Schema != oneShotSchema {
		t.Errorf("schema = %q, want %q", env2.Schema, oneShotSchema)
	}
	if env2.PriceBasis != oneshot.PriceBasis {
		t.Errorf("price_basis = %q, want %q", env2.PriceBasis, oneshot.PriceBasis)
	}
	if env2.Tier != "log" {
		t.Errorf("tier = %q, want %q", env2.Tier, "log")
	}
	if env2.Window.Label != "last 30 days" || env2.Window.Since == "" || env2.Window.Partial {
		t.Errorf("window = %+v", env2.Window)
	}
	if len(env2.Rows) == 0 || env2.Rows[0].Tool != "claude-code" {
		t.Fatalf("rows = %+v", env2.Rows)
	}
	if env2.Total.Tools != 1 || env2.Total.Turns == 0 {
		t.Errorf("total = %+v", env2.Total)
	}
	// --json suppresses progress on stderr.
	if errOut != "" {
		t.Errorf("--json must silence progress, stderr=%q", errOut)
	}
	assertNoObserverHome(t, env.home)
	assertScratchDirsGone(t, env.tmpdir)
}

// TestUsageCmd_IgnoresObserverEnvAndConfig pins the two zero-config
// promises end to end: an OBSERVER_OBSERVER_DB_PATH in the environment
// never gets opened, and an existing ~/.observer/config.toml is reported
// as ignored (with the --config opt-in).
func TestUsageCmd_IgnoresObserverEnvAndConfig(t *testing.T) {
	env := newUsageTestEnv(t)
	root := seedClaudeCode(t, env.home)
	env.deps.adapters = func() []adapter.Adapter {
		return []adapter.Adapter{claudecode.NewWithOptions(nil, root)}
	}
	live := filepath.Join(t.TempDir(), "live.db")
	t.Setenv("OBSERVER_OBSERVER_DB_PATH", live)

	// A real config on disk — deliberately NOT read (and its existence is
	// what the footer note reports). Written directly, not via the
	// command, so $HOME/.observer existing here is the test's doing.
	cfgDir := filepath.Join(env.home, ".observer")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	cfgPath := filepath.Join(cfgDir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(live)+"\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	out, errOut, err := env.run(t)
	if err != nil {
		t.Fatalf("usage: %v (stderr=%s)", err, errOut)
	}
	if _, serr := os.Stat(live); !os.IsNotExist(serr) {
		t.Fatalf("OBSERVER_OBSERVER_DB_PATH must never be opened, stat err=%v", serr)
	}
	if !strings.Contains(out, cfgPath+" was NOT read") {
		t.Errorf("stdout missing the ignored-config note:\n%s", out)
	}
	if !strings.Contains(out, "--config "+cfgPath) {
		t.Errorf("stdout missing the --config opt-in hint:\n%s", out)
	}
	if !strings.Contains(out, "claude-code") {
		t.Errorf("the scratch DB should still have been used and populated:\n%s", out)
	}
	assertScratchDirsGone(t, env.tmpdir)
}

// TestUsageCmd_MirrorBaseRedirectedIntoScratchDir pins F1: every
// foreign-mount SQLite mirror write (the seam internal/adapter/mirrorbase
// exposes) must be redirected into THIS run's scratch dir for its
// duration, never left pointed at the operator's persistent
// os.UserCacheDir() — a persistent write there would violate the
// one-shot's "nothing survives outside the temp dir" contract. Hermetic:
// XDG_CACHE_HOME points os.UserCacheDir() at a throwaway dir so the
// assertion that nothing was created there can never depend on this
// machine's real cache.
func TestUsageCmd_MirrorBaseRedirectedIntoScratchDir(t *testing.T) {
	fakeCache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", fakeCache)

	env := newUsageTestEnv(t)
	probe := newMirrorProbeAdapter(t)
	env.deps.adapters = func() []adapter.Adapter { return []adapter.Adapter{probe} }

	if _, errOut, err := env.run(t); err != nil {
		t.Fatalf("usage: %v (stderr=%s)", err, errOut)
	}

	bases := probe.observedBases()
	if len(bases) == 0 {
		t.Fatal("mirrorbase.Base() was never queried during the scan - the probe adapter did not run")
	}
	for _, b := range bases {
		if !strings.HasPrefix(b, env.tmpdir) {
			t.Errorf("mirrorbase.Base() = %q during the scan, want it under the scratch TMPDIR (%s) - F1", b, env.tmpdir)
		}
		if strings.HasPrefix(b, fakeCache) {
			t.Errorf("mirrorbase.Base() = %q leaked the real os.UserCacheDir() (%s) during a one-shot run - F1", b, fakeCache)
		}
	}
	if _, serr := os.Stat(filepath.Join(fakeCache, "superbased-observer")); !os.IsNotExist(serr) {
		t.Fatalf("os.UserCacheDir()/superbased-observer must never be created by a one-shot run (stat err=%v)", serr)
	}
}

// TestOneShotMirrorBaseSetBeforeScan is the direct unit assertion (as
// opposed to the end-to-end trust assertion above) that the one-shot
// assembly calls mirrorbase.SetBaseForProcess BEFORE the scan can query
// it: the very first observed base must already be the scratch dir's
// "mirror" subdirectory, never the zero value (an override not yet set)
// and never the production os.UserCacheDir() path.
func TestOneShotMirrorBaseSetBeforeScan(t *testing.T) {
	env := newUsageTestEnv(t)
	probe := newMirrorProbeAdapter(t)
	env.deps.adapters = func() []adapter.Adapter { return []adapter.Adapter{probe} }

	if _, errOut, err := env.run(t); err != nil {
		t.Fatalf("usage: %v (stderr=%s)", err, errOut)
	}

	bases := probe.observedBases()
	if len(bases) == 0 {
		t.Fatal("mirrorbase.Base() was never queried during the scan")
	}
	first := bases[0]
	if first == "" {
		t.Fatal("the first observed mirrorbase.Base() was empty - SetBaseForProcess had not run yet")
	}
	if filepath.Base(first) != oneShotMirrorDirName {
		t.Errorf("first observed base = %q, want its final path element to be %q (the scratch dir's mirror subdir, set before scanning)", first, oneShotMirrorDirName)
	}
}

// TestUsageCmd_GroupByDayDistinctCountsAreNeverDayCounts pins F11: the
// TOTAL line's distinct tool/model counts come from the corpus's actual
// tool/model set, never from the number of --group-by day buckets. The
// old bug read "N tools · 0 models" with N equal to the day count.
func TestUsageCmd_GroupByDayDistinctCountsAreNeverDayCounts(t *testing.T) {
	env := newUsageTestEnv(t)
	root := seedClaudeCodeMultiDay(t, env.home, []int{-1, -5, -10})
	env.deps.adapters = func() []adapter.Adapter {
		return []adapter.Adapter{claudecode.NewWithOptions(nil, root)}
	}

	out, errOut, err := env.run(t, "--group-by", "day", "--json")
	if err != nil {
		t.Fatalf("usage --group-by day --json: %v (stderr=%s)", err, errOut)
	}
	var env2 struct {
		Rows []struct {
			Tool string `json:"tool"`
		} `json:"rows"`
		Total struct {
			Tools  int `json:"tools"`
			Models int `json:"models"`
		} `json:"total"`
	}
	if uerr := json.Unmarshal([]byte(out), &env2); uerr != nil {
		t.Fatalf("unmarshal --json output: %v\n%s", uerr, out)
	}
	if len(env2.Rows) < 3 {
		t.Fatalf("expected at least 3 day-buckets, got %d: %+v", len(env2.Rows), env2.Rows)
	}
	if env2.Total.Tools != 1 {
		t.Errorf("total.tools = %d, want 1 (one tool spread across %d days) - F11 regression", env2.Total.Tools, len(env2.Rows))
	}
	if env2.Total.Models != 1 {
		t.Errorf("total.models = %d, want 1 (day-grouping must not zero out the model count) - F11 regression", env2.Total.Models)
	}
}

// TestUsageCmd_KeepDBFailurePreservesScratchDir pins F9: when --keep-db
// cannot move OR copy the scratch database anywhere, the scratch dir
// (and the database inside it — the only intact copy of this run's data)
// must survive, not be destroyed by the deferred cleanup on the way out
// of an error return.
func TestUsageCmd_KeepDBFailurePreservesScratchDir(t *testing.T) {
	t.Cleanup(func() { oneShotRenameFile = os.Rename })
	oneShotRenameFile = func(string, string) error { return errors.New("simulated cross-device rename failure") }

	env := newUsageTestEnv(t)
	root := seedClaudeCode(t, env.home)
	env.deps.adapters = func() []adapter.Adapter {
		return []adapter.Adapter{claudecode.NewWithOptions(nil, root)}
	}
	// Make the copy fallback's publish step fail without relying on file
	// permissions (a root-mapped test namespace ignores a 0o500 dir): dest
	// is an existing non-empty DIRECTORY, so the same-directory temp file
	// can be written but never renamed over it, for any uid.
	destDir := t.TempDir()
	dest := filepath.Join(destDir, "kept.db")
	if err := os.MkdirAll(filepath.Join(dest, "occupied"), 0o700); err != nil {
		t.Fatalf("occupy dest: %v", err)
	}

	if _, _, err := env.run(t, "--keep-db", dest); err == nil {
		t.Fatal("expected an error when --keep-db can neither move nor copy the scratch database")
	}

	entries, rerr := os.ReadDir(env.tmpdir)
	if rerr != nil {
		t.Fatalf("read tmpdir: %v", rerr)
	}
	var survivors []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), oneShotDirPrefix) {
			survivors = append(survivors, e.Name())
		}
	}
	if len(survivors) != 1 {
		t.Fatalf("expected exactly one surviving scratch dir on a --keep-db failure (F9), got %v", survivors)
	}
	if _, serr := os.Stat(filepath.Join(env.tmpdir, survivors[0], oneShotDBName)); serr != nil {
		t.Errorf("the scratch database itself must survive inside the preserved dir: %v", serr)
	}
}

// ---------------------------------------------------------------------------
// units
// ---------------------------------------------------------------------------

// TestOneShotEnv pins the OBSERVER_* filter both ways.
func TestOneShotEnv(t *testing.T) {
	get := func(key string) string {
		switch key {
		case "OBSERVER_OBSERVER_DB_PATH":
			return "/live/observer.db"
		case "OBSERVER_OBSERVER_ANTIGRAVITY_NETWORK_RECOVERY":
			return "local"
		case "NO_COLOR":
			return "1"
		}
		return ""
	}
	filtered := oneShotEnv(get, false)
	if got := filtered("OBSERVER_OBSERVER_DB_PATH"); got != "" {
		t.Errorf("filtered OBSERVER_* = %q, want empty", got)
	}
	if got := filtered("OBSERVER_OBSERVER_ANTIGRAVITY_NETWORK_RECOVERY"); got != "" {
		t.Errorf("filtered network_recovery = %q, want empty", got)
	}
	if got := filtered("NO_COLOR"); got != "1" {
		t.Errorf("non-OBSERVER key = %q, want %q", got, "1")
	}
	honored := oneShotEnv(get, true)
	if got := honored("OBSERVER_OBSERVER_DB_PATH"); got != "/live/observer.db" {
		t.Errorf("honored OBSERVER_* = %q, want the env value", got)
	}
}

// TestLoadOneShotConfig pins the config seam: the default path yields pure
// defaults with every OBSERVER_* var blanked, and --config opts back into
// both the file and the environment.
func TestLoadOneShotConfig(t *testing.T) {
	env := newUsageTestEnv(t)
	live := filepath.Join(t.TempDir(), "live.db")
	t.Setenv("OBSERVER_OBSERVER_DB_PATH", live)

	tmp := t.TempDir()
	cfg, err := loadOneShotConfig("", tmp, env.deps)
	if err != nil {
		t.Fatalf("loadOneShotConfig(default): %v", err)
	}
	if cfg.Observer.DBPath == live {
		t.Errorf("default path honored OBSERVER_OBSERVER_DB_PATH (%q)", cfg.Observer.DBPath)
	}
	if len(cfg.Observer.Watch.EnabledAdapters) == 0 {
		t.Errorf("default path should carry config.Default()'s adapter allow-list")
	}
	if _, serr := os.Stat(filepath.Join(tmp, "absent.toml")); !os.IsNotExist(serr) {
		t.Errorf("the absent-config sentinel must never be created (err=%v)", serr)
	}

	real := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(real, []byte("[observer]\nlog_level = \"warn\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg2, err := loadOneShotConfig(real, tmp, env.deps)
	if err != nil {
		t.Fatalf("loadOneShotConfig(--config): %v", err)
	}
	if cfg2.Observer.LogLevel != "warn" {
		t.Errorf("--config did not read the file: log_level=%q", cfg2.Observer.LogLevel)
	}
	if cfg2.Observer.DBPath != live {
		t.Errorf("--config should honor the environment too: db_path=%q want %q", cfg2.Observer.DBPath, live)
	}
}

// TestParseUsageGroupBy pins the --group-by vocabulary mapping.
func TestParseUsageGroupBy(t *testing.T) {
	cases := []struct {
		in   string
		want cost.GroupBy
		err  bool
	}{
		{"", cost.GroupByModelTool, false},
		{"tool-model", cost.GroupByModelTool, false},
		{"TOOL-MODEL", cost.GroupByModelTool, false},
		{"model-tool", cost.GroupByModelTool, false},
		{"tool", cost.GroupByTool, false},
		{"model", cost.GroupByModel, false},
		{"day", cost.GroupByDay, false},
		{"session", "", true},
		{"banana", "", true},
	}
	for _, tc := range cases {
		got, err := parseUsageGroupBy(tc.in)
		if (err != nil) != tc.err {
			t.Errorf("parseUsageGroupBy(%q): err=%v want err=%v", tc.in, err, tc.err)
			continue
		}
		if !tc.err && got != tc.want {
			t.Errorf("parseUsageGroupBy(%q) = %q want %q", tc.in, got, tc.want)
		}
	}
}

// TestSummaryToTable pins the one mapping seam: key unpacking per GroupBy,
// the 5m+1h cache-write merge, and totals taken from the summary (not the
// possibly row-limited rows).
func TestSummaryToTable(t *testing.T) {
	sum := cost.Summary{
		Rows: []cost.Row{{
			Key: "claude-opus-4-8" + "||" + "claude-code",
			Tokens: cost.TokenBundle{
				Input: 100, Output: 20, CacheRead: 300,
				CacheCreation: 40, CacheCreation1h: 2,
			},
			CostUSD: 1.5, TurnCount: 3,
			Reliability: "approximate", PricingSource: "exact",
		}},
		TotalTokens: cost.TokenBundle{Input: 999, Output: 20, CacheRead: 300, CacheCreation: 40, CacheCreation1h: 2},
		TotalCost:   9.75,
		TurnCount:   7,
		Reliability: "approximate",
	}
	since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	got := summaryToTable(sum, cost.GroupByModelTool, since, "last 30 days")
	if len(got.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(got.Rows))
	}
	r := got.Rows[0]
	if r.Tool != "claude-code" || r.Model != "claude-opus-4-8" {
		t.Errorf("key unpack: tool=%q model=%q", r.Tool, r.Model)
	}
	if r.CacheCreation != 42 {
		t.Errorf("CACHE_W should merge 5m+1h writes: got %d want 42", r.CacheCreation)
	}
	if !r.Approx() {
		t.Errorf("approximate reliability should earn the ~ marker")
	}
	if got.Tier != "log" {
		t.Errorf("tier = %q, want log", got.Tier)
	}
	if got.TotalInput != 999 || got.TotalTurns != 7 || got.TotalUSD != 9.75 {
		t.Errorf("totals must come from the summary: %+v", got)
	}
	if got.ToolCount != 1 || got.ModelCount != 1 {
		t.Errorf("counts: tools=%d models=%d", got.ToolCount, got.ModelCount)
	}
	if !got.WindowSince.Equal(since) || got.WindowLabel != "last 30 days" {
		t.Errorf("window: %v / %q", got.WindowSince, got.WindowLabel)
	}

	// tool / model / day keys land in the cell the report has room for.
	byTool := summaryToTable(cost.Summary{Rows: []cost.Row{{Key: "codex"}}}, cost.GroupByTool, since, "l")
	if byTool.Rows[0].Tool != "codex" || byTool.Rows[0].Model != "" {
		t.Errorf("group-by tool: %+v", byTool.Rows[0])
	}
	byModel := summaryToTable(cost.Summary{Rows: []cost.Row{{Key: "gpt-5.6"}}}, cost.GroupByModel, since, "l")
	if byModel.Rows[0].Model != "gpt-5.6" || byModel.Rows[0].Tool != "" {
		t.Errorf("group-by model: %+v", byModel.Rows[0])
	}
	byDay := summaryToTable(cost.Summary{Rows: []cost.Row{{Key: "2026-07-29"}}}, cost.GroupByDay, since, "l")
	if byDay.Rows[0].Tool != "2026-07-29" {
		t.Errorf("group-by day: %+v", byDay.Rows[0])
	}
}

// TestApplyScanState pins the partial-vs-empty distinction: a
// budget-truncated scan is never reported as "nothing found".
func TestApplyScanState(t *testing.T) {
	truncated := oneshot.Table{}
	applyScanState(&truncated, scanOneShotResult{
		budgetHit: true, filesProcessed: 4, filesTotal: 9,
		adaptersConsidered: 3, rootsChecked: []string{"/a"},
	}, "/home/u", 30*time.Second)
	if truncated.Partial == nil || truncated.Partial.FilesWalked != 4 || truncated.Partial.FilesTotal != 9 {
		t.Errorf("partial = %+v", truncated.Partial)
	}
	if truncated.Empty != nil {
		t.Errorf("a budget-truncated scan must not claim an empty corpus: %+v", truncated.Empty)
	}

	empty := oneshot.Table{}
	applyScanState(&empty, scanOneShotResult{
		adaptersConsidered: 3, rootsChecked: []string{"/a", "/b"},
	}, "/home/u", 30*time.Second)
	if empty.Partial != nil {
		t.Errorf("partial = %+v, want nil", empty.Partial)
	}
	if empty.Empty == nil || empty.Empty.Home != "/home/u" ||
		len(empty.Empty.Looked) != 2 || empty.Empty.AdapterCount != 3 {
		t.Errorf("empty = %+v", empty.Empty)
	}

	nonEmpty := oneshot.Table{Rows: []oneshot.Row{{Tool: "codex"}}}
	applyScanState(&nonEmpty, scanOneShotResult{adaptersConsidered: 1}, "/home/u", 0)
	if nonEmpty.Empty != nil || nonEmpty.Partial != nil {
		t.Errorf("a complete, non-empty scan needs neither note: %+v", nonEmpty)
	}

	// F10: files WERE read (e.g. every one failed to parse, or --tool
	// filtered the whole corpus out) but zero cost rows resulted. This is
	// NOT "we looked and found nothing" — that phrasing implies zero
	// session files existed at all, which is false here.
	filesReadNoRows := oneshot.Table{}
	applyScanState(&filesReadNoRows, scanOneShotResult{
		filesProcessed: 3, errors: 3, adaptersConsidered: 1, rootsChecked: []string{"/a"},
	}, "/home/u", 30*time.Second)
	if filesReadNoRows.Empty != nil {
		t.Errorf("a scan that read files (even if all failed) must not claim an empty corpus (F10): %+v", filesReadNoRows.Empty)
	}
	if filesReadNoRows.Partial != nil {
		t.Errorf("partial = %+v, want nil (the budget was not hit)", filesReadNoRows.Partial)
	}
}

// TestSweepStaleOneShotDirs pins the orphan sweep: an old scratch dir
// whose pidfile names a genuinely dead process goes; fresh ones, foreign
// names, and dirs still recording a live owner all stay. "stale" here
// carries a pidfile naming an implausible PID — the shape of a real
// kill -9 orphan (the process wrote its PID once and is now gone), not
// the "no pidfile at all" unknown-liveness case (covered separately below,
// F13).
func TestSweepStaleOneShotDirs(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, oneShotDirPrefix+"stale")
	fresh := filepath.Join(dir, oneShotDirPrefix+"fresh")
	foreign := filepath.Join(dir, "observer-demo-xyz")
	for _, d := range []string{stale, fresh, foreign} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(stale, oneShotPIDFileName), []byte("999999999"), 0o600); err != nil {
		t.Fatalf("write stale pidfile: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	sweepStaleOneShotDirs(dir, 24*time.Hour)

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale scratch dir (dead pidfile owner) survived (err=%v)", err)
	}
	for _, d := range []string{fresh, foreign} {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("%s should have been left alone: %v", d, err)
		}
	}
}

// TestSweepStaleOneShotDirs_PreservesLiveOwner pins F13: an old scratch
// dir whose pidfile names THIS (definitely still running) test process
// must survive the sweep even though its mtime is well past maxAge — a
// long --budget 0 scan can leave its scratch dir's mtime stale while
// still actively running.
func TestSweepStaleOneShotDirs_PreservesLiveOwner(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, oneShotDirPrefix+"live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(live, oneShotPIDFileName), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatalf("write pidfile: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(live, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	sweepStaleOneShotDirs(dir, 24*time.Hour)

	if _, err := os.Stat(live); err != nil {
		t.Errorf("a scratch dir whose pidfile names a live process must survive the sweep: %v", err)
	}
}

// TestSweepStaleOneShotDirs_UnknownLivenessRespectsHardCap pins F13's
// fallback: a scratch dir with NO pidfile at all (a pre-F13 binary's
// orphan, or a corrupted write) is preserved past the normal maxAge —
// deleting it on an unknown liveness read risks destroying a live run's
// only scratch database — but is swept once it crosses
// oneShotStaleHardCap, so unknown-liveness orphans don't accumulate
// forever.
func TestSweepStaleOneShotDirs_UnknownLivenessRespectsHardCap(t *testing.T) {
	dir := t.TempDir()
	unknown := filepath.Join(dir, oneShotDirPrefix+"nopid")
	if err := os.MkdirAll(unknown, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	withinCap := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(unknown, withinCap, withinCap); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	sweepStaleOneShotDirs(dir, 24*time.Hour)
	if _, err := os.Stat(unknown); err != nil {
		t.Errorf("unknown-liveness dir within the hard cap must be preserved, not swept: %v", err)
	}

	pastCap := time.Now().Add(-(oneShotStaleHardCap + time.Hour))
	if err := os.Chtimes(unknown, pastCap, pastCap); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	sweepStaleOneShotDirs(dir, 24*time.Hour)
	if _, err := os.Stat(unknown); !os.IsNotExist(err) {
		t.Errorf("unknown-liveness dir past the hard cap must be swept regardless (err=%v)", err)
	}
}

// TestWriteOneShotPIDFile pins the pidfile writer: it records this
// process's own PID, parseable back out.
func TestWriteOneShotPIDFile(t *testing.T) {
	dir := t.TempDir()
	writeOneShotPIDFile(dir)
	raw, err := os.ReadFile(filepath.Join(dir, oneShotPIDFileName))
	if err != nil {
		t.Fatalf("read pidfile: %v", err)
	}
	pid, perr := strconv.Atoi(strings.TrimSpace(string(raw)))
	if perr != nil {
		t.Fatalf("pidfile does not contain a plain integer: %q", raw)
	}
	if pid != os.Getpid() {
		t.Errorf("pidfile pid = %d, want %d", pid, os.Getpid())
	}
}

// TestOneShotProcessAlive pins the cross-platform liveness probe: this
// process is alive, pid 0 and an implausible pid are not.
func TestOneShotProcessAlive(t *testing.T) {
	if !oneShotProcessAlive(os.Getpid()) {
		t.Error("the current process should be reported alive")
	}
	if oneShotProcessAlive(0) {
		t.Error("pid 0 should never be reported alive")
	}
	if oneShotProcessAlive(999999999) {
		t.Error("an implausible pid should be reported dead")
	}
}

// TestKeepScratchDB pins --keep-db's move semantics, including the empty
// (no-op) case.
func TestKeepScratchDB(t *testing.T) {
	if got, err := keepScratchDB("/nonexistent/usage.db", ""); err != nil || got != "" {
		t.Errorf("no --keep-db should be a no-op: %q / %v", got, err)
	}
	src := filepath.Join(t.TempDir(), "usage.db")
	if err := os.WriteFile(src, []byte("db"), 0o600); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "nested", "kept.db")
	got, err := keepScratchDB(src, dest)
	if err != nil {
		t.Fatalf("keepScratchDB: %v", err)
	}
	if got != dest {
		t.Errorf("returned %q, want %q", got, dest)
	}
	if body, rerr := os.ReadFile(dest); rerr != nil || string(body) != "db" {
		t.Errorf("kept file: %q / %v", body, rerr)
	}
}

// TestKeepScratchDB_StreamCopyFallback pins F9's cross-device path: when
// the rename fails (forced here via oneShotRenameFile, standing in for a
// real EXDEV without needing a second filesystem), keepScratchDB falls
// back to a stream copy rather than reading the whole database into
// memory, and the destination ends up byte-identical.
func TestKeepScratchDB_StreamCopyFallback(t *testing.T) {
	t.Cleanup(func() { oneShotRenameFile = os.Rename })
	oneShotRenameFile = func(string, string) error { return errors.New("simulated cross-device rename failure") }

	src := filepath.Join(t.TempDir(), "usage.db")
	body := bytes.Repeat([]byte("sqlite-scratch-db-bytes"), 4096)
	if err := os.WriteFile(src, body, 0o600); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	dest := filepath.Join(t.TempDir(), "nested", "kept.db")

	got, err := keepScratchDB(src, dest)
	if err != nil {
		t.Fatalf("keepScratchDB (stream-copy fallback): %v", err)
	}
	if got != dest {
		t.Errorf("returned %q, want %q", got, dest)
	}
	kept, rerr := os.ReadFile(dest)
	if rerr != nil || !bytes.Equal(kept, body) {
		t.Errorf("kept file mismatch: err=%v len=%d want=%d", rerr, len(kept), len(body))
	}
	// No stray temp file should be left behind next to the published copy.
	entries, derr := os.ReadDir(filepath.Dir(dest))
	if derr != nil {
		t.Fatalf("read dest dir: %v", derr)
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly one file in the destination dir, got %v", entries)
	}
}

// TestCountOneShotSessionFiles_RespectsSinceWindow pins F12: the file
// count that turns "read N files" into "read N of M" must apply the same
// mtime cutoff the scan itself honors — an out-of-window file must not
// inflate the denominator.
func TestCountOneShotSessionFiles_RespectsSinceWindow(t *testing.T) {
	root := t.TempDir()
	recent := filepath.Join(root, "recent.jsonl")
	old := filepath.Join(root, "old.jsonl")
	for _, p := range []string{recent, old} {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	oldTime := time.Now().Add(-60 * 24 * time.Hour)
	if err := os.Chtimes(old, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	a := claudecode.NewWithOptions(nil, root)
	since := time.Now().Add(-30 * 24 * time.Hour)

	if got := countOneShotSessionFiles(context.Background(), []adapter.Adapter{a}, since, 0); got != 1 {
		t.Errorf("countOneShotSessionFiles(since=30d) = %d, want 1 - the backdated file must be excluded (F12)", got)
	}
	if got := countOneShotSessionFiles(context.Background(), []adapter.Adapter{a}, time.Time{}, 0); got != 2 {
		t.Errorf("countOneShotSessionFiles(since=zero) = %d, want 2 (no window filter at all)", got)
	}
	// floor is still respected regardless of the window.
	if got := countOneShotSessionFiles(context.Background(), []adapter.Adapter{a}, since, 5); got != 5 {
		t.Errorf("countOneShotSessionFiles must never report below floor: got %d, want 5", got)
	}
}

// TestRunUsageInstallsSignalHandlerBeforeScratchDir pins F4's ordering: a
// ^C landing in the gap between os.MkdirTemp and the signal handler being
// installed would leak the scratch dir under the OS's default signal
// disposition (no Go defer runs on that path). Actually delivering a real
// SIGTERM mid-scan is not reliably race-free in a unit test, so this pins
// the ordering the source guarantees instead: signal.NotifyContext is
// installed textually (and therefore executes) before os.MkdirTemp inside
// runUsage.
func TestRunUsageInstallsSignalHandlerBeforeScratchDir(t *testing.T) {
	src, err := os.ReadFile("usage.go")
	if err != nil {
		t.Fatalf("read usage.go: %v", err)
	}
	body := string(src)
	fnStart := strings.Index(body, "func runUsage(")
	if fnStart < 0 {
		t.Fatal("runUsage not found in usage.go")
	}
	fnBody := body[fnStart:]
	sigIdx := strings.Index(fnBody, "signal.NotifyContext(")
	mkdirIdx := strings.Index(fnBody, "os.MkdirTemp(")
	if sigIdx < 0 || mkdirIdx < 0 {
		t.Fatalf("expected both signal.NotifyContext(...) and os.MkdirTemp(...) inside runUsage (sigIdx=%d mkdirIdx=%d)", sigIdx, mkdirIdx)
	}
	if sigIdx > mkdirIdx {
		t.Errorf("signal.NotifyContext (offset %d) must precede os.MkdirTemp (offset %d) inside runUsage - F4", sigIdx, mkdirIdx)
	}
}

// ---------------------------------------------------------------------------
// bare-root fallthrough
// ---------------------------------------------------------------------------

// TestOneShotFallthroughEligible walks the gate's whole truth table. F2
// removed the two loopback port probes entirely — eligibility now rests
// on exactly three filesystem-only conditions.
func TestOneShotFallthroughEligible(t *testing.T) {
	cases := []struct {
		name     string
		oneshot  string
		haveDB   bool
		haveCfg  bool
		homeErr  bool
		eligible bool
	}{
		{name: "fresh machine", eligible: true},
		{name: "OBSERVER_ONESHOT=off", oneshot: "off"},
		{name: "OBSERVER_ONESHOT=OFF mixed case", oneshot: "OFF"},
		{name: "OBSERVER_ONESHOT=on", oneshot: "on", eligible: true},
		{name: "observer.db present", haveDB: true},
		{name: "config.toml present", haveCfg: true},
		{name: "home unresolvable", homeErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if tc.haveDB || tc.haveCfg {
				if err := os.MkdirAll(filepath.Join(home, ".observer"), 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
			}
			if tc.haveDB {
				if err := os.WriteFile(filepath.Join(home, ".observer", "observer.db"), []byte("x"), 0o600); err != nil {
					t.Fatalf("write db: %v", err)
				}
			}
			if tc.haveCfg {
				if err := os.WriteFile(filepath.Join(home, ".observer", "config.toml"), []byte("x"), 0o600); err != nil {
					t.Fatalf("write cfg: %v", err)
				}
			}
			deps := usageDeps{
				homeDir: func() (string, error) { return home, nil },
				getenv: func(k string) string {
					if k == "OBSERVER_ONESHOT" {
						return tc.oneshot
					}
					return ""
				},
			}
			if tc.homeErr {
				deps.homeDir = func() (string, error) { return "", os.ErrNotExist }
			}
			if got := oneShotFallthroughEligible(deps); got != tc.eligible {
				t.Errorf("eligible = %v, want %v", got, tc.eligible)
			}
		})
	}
}

// TestOneShotFallthroughEligible_IgnoresListeningPort pins the F2 fix
// directly: a real, live listener on the daemon's well-known dashboard
// port must not change eligibility now that the port probes are gone.
// (On the pre-fix code this test would need deps.portUp to force the
// result — that seam no longer exists, which is itself the point: the
// probe was removed, not merely stubbed.)
func TestOneShotFallthroughEligible_IgnoresListeningPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:8820")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:8820 to prove the point on this machine: %v", err)
	}
	defer ln.Close()

	home := t.TempDir()
	deps := usageDeps{
		homeDir: func() (string, error) { return home, nil },
		getenv:  func(string) string { return "" },
	}
	if !oneShotFallthroughEligible(deps) {
		t.Error("a listening daemon port must not affect eligibility (F2) - only ~/.observer state does")
	}
}

// TestBareRootFallthroughMatrix drives the REAL root command with no args
// across the three states that matter: fresh machine → the usage table,
// existing observer.db → the unchanged welcome screen, OBSERVER_ONESHOT=off
// → the welcome screen.
func TestBareRootFallthroughMatrix(t *testing.T) {
	runRoot := func(t *testing.T, env *usageTestEnv) (string, string, error) {
		t.Helper()
		root := newRootCmdWith(env.deps)
		var out, errOut bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&errOut)
		// Not nil: nil makes cobra read the test binary's own os.Args.
		root.SetArgs([]string{})
		err := root.Execute()
		return out.String(), errOut.String(), err
	}

	t.Run("fresh machine runs the one-shot", func(t *testing.T) {
		env := newUsageTestEnv(t)
		root := seedClaudeCode(t, env.home)
		env.deps.adapters = func() []adapter.Adapter {
			return []adapter.Adapter{claudecode.NewWithOptions(nil, root)}
		}
		out, errOut, err := runRoot(t, env)
		if err != nil {
			t.Fatalf("bare root: %v (stderr=%s)", err, errOut)
		}
		if !strings.Contains(out, "SuperBased - observed agent spend") || !strings.Contains(out, "claude-code") {
			t.Errorf("bare root should print the usage table:\n%s", out)
		}
		if !strings.Contains(errOut, "no local SuperBased state found") {
			t.Errorf("bare root should explain itself on stderr:\n%s", errOut)
		}
		assertNoObserverHome(t, env.home)
		assertScratchDirsGone(t, env.tmpdir)
	})

	t.Run("existing observer.db keeps the welcome screen", func(t *testing.T) {
		env := newUsageTestEnv(t)
		if err := os.MkdirAll(filepath.Join(env.home, ".observer"), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(env.home, ".observer", "observer.db"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write db: %v", err)
		}
		out, _, err := runRoot(t, env)
		if err != nil {
			t.Fatalf("bare root: %v", err)
		}
		if !strings.Contains(out, "SuperBased Observer") || !strings.Contains(out, "observer usage") {
			t.Errorf("expected the welcome screen (with the new usage hint):\n%s", out)
		}
		if strings.Contains(out, "observed agent spend") {
			t.Errorf("the one-shot must not run when state exists:\n%s", out)
		}
	})

	t.Run("OBSERVER_ONESHOT=off keeps the welcome screen", func(t *testing.T) {
		env := newUsageTestEnv(t)
		t.Setenv("OBSERVER_ONESHOT", "off")
		seedClaudeCode(t, env.home)
		out, _, err := runRoot(t, env)
		if err != nil {
			t.Fatalf("bare root: %v", err)
		}
		if !strings.Contains(out, "SuperBased Observer") {
			t.Errorf("expected the welcome screen:\n%s", out)
		}
		if strings.Contains(out, "observed agent spend") {
			t.Errorf("OBSERVER_ONESHOT=off must suppress the one-shot:\n%s", out)
		}
		assertNoObserverHome(t, env.home)
	})
}

// TestUsageCmdRegistered pins that `observer usage` (and, for free, the
// deprecated `observer observer usage` alias) exist on the assembled CLI.
func TestUsageCmdRegistered(t *testing.T) {
	var found bool
	for _, c := range observerSubcommands() {
		if c.Name() == "usage" {
			found = true
		}
	}
	if !found {
		t.Fatal("`usage` is not registered in observerSubcommands()")
	}
}
