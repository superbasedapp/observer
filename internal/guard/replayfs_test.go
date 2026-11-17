package guard

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestReplayFSMemoizesEachLookupOnce pins demo bug #14's memo: a replay asks
// the filesystem once per distinct key per reader, the answer (found or not)
// is replayed verbatim, and the three readers keep separate maps.
func TestReplayFSMemoizesEachLookupOnce(t *testing.T) {
	cases := []struct {
		name  string
		calls []string
		want  int // distinct reader calls
	}{
		{"one path asked many times", []string{"/a", "/a", "/a"}, 1},
		{"distinct paths each asked once", []string{"/a", "/b", "/a", "/c", "/b"}, 3},
		{"a miss is memoized too", []string{"/missing", "/missing"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := NewReplayFS()
			var mu sync.Mutex
			links, files := map[string]int{}, map[string]int{}
			resolve := m.resolveLinks(func(p string) string {
				mu.Lock()
				defer mu.Unlock()
				links[p]++
				if p == "/missing" {
					return ""
				}
				return "/real" + p
			})
			read := m.readFile(func(r *ReplayFS) map[string]memoFile { return r.hookFiles }, func(p string) ([]byte, bool) {
				mu.Lock()
				defer mu.Unlock()
				files[p]++
				return []byte(p), p != "/missing"
			})
			for _, p := range c.calls {
				got := resolve(p)
				if p == "/missing" && got != "" || p != "/missing" && got != "/real"+p {
					t.Fatalf("resolve(%q) = %q", p, got)
				}
				b, ok := read(p)
				if string(b) != p || ok != (p != "/missing") {
					t.Fatalf("read(%q) = %q %v", p, b, ok)
				}
			}
			if len(links) != c.want || len(files) != c.want {
				t.Fatalf("distinct lookups: links %d files %d, want %d", len(links), len(files), c.want)
			}
			for p, n := range links {
				if n != 1 {
					t.Errorf("resolve(%q) reached the filesystem %d times", p, n)
				}
			}
			for p, n := range files {
				if n != 1 {
					t.Errorf("read(%q) reached the filesystem %d times", p, n)
				}
			}
			if len(m.sqlFiles) != 0 {
				t.Errorf("the SQL reader's map was touched by the hook reader: %v", m.sqlFiles)
			}
		})
	}
}

// TestReplayFSIsBounded: past the entry bound a lookup is answered but not
// stored, so a pathological corpus costs time, never unbounded memory.
func TestReplayFSIsBounded(t *testing.T) {
	m := NewReplayFS()
	calls := 0
	resolve := m.resolveLinks(func(p string) string { calls++; return p })
	for i := 0; i < replayFSMaxEntries+10; i++ {
		resolve("/p/" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + "/" + time.Duration(i).String())
	}
	if len(m.links) != replayFSMaxEntries {
		t.Fatalf("memo holds %d entries, bound %d", len(m.links), replayFSMaxEntries)
	}
	before := calls
	resolve("/never-seen")
	resolve("/never-seen")
	if calls != before+2 {
		t.Fatalf("a full memo must still answer by asking: %d calls, want %d", calls, before+2)
	}
}

// TestReplayFSVerdictsMatchLiveGuard: a guard with the memo reaches the same
// verdicts as one without, over actions that exercise the symlink resolver
// (recursive deletes) and the hook-switch reader (a settings-file edit).
func TestReplayFSVerdictsMatchLiveGuard(t *testing.T) {
	home := t.TempDir()
	root := filepath.ToSlash(filepath.Join(home, "proj"))
	now := time.Now()
	var inputs []ActionInput
	for i := 0; i < 30; i++ {
		inputs = append(inputs,
			ActionInput{ActionID: int64(i*3 + 1), SessionID: "s1", ProjectRoot: root, Tool: "claude-code", ActionType: "run_command", Target: "rm -rf " + home, Timestamp: now, TurnIndex: i},
			ActionInput{ActionID: int64(i*3 + 2), SessionID: "s1", ProjectRoot: root, Tool: "claude-code", ActionType: "run_command", Target: "rm -rf build/out", Timestamp: now, TurnIndex: i},
			ActionInput{ActionID: int64(i*3 + 3), SessionID: "s1", ProjectRoot: root, Tool: "claude-code", ActionType: "edit_file", Target: filepath.ToSlash(filepath.Join(home, ".claude", "settings.json")), Timestamp: now, TurnIndex: i},
		)
	}
	cfg := config.Default().Guard
	cfg.Enabled = true
	verdicts := func(rfs *ReplayFS) []string {
		g, err := New(Options{Config: cfg, Home: home, ReplayFS: rfs})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, v := range g.EvaluateActions(append([]ActionInput(nil), inputs...)) {
			out = append(out, v.Verdict.RuleID+"/"+v.Verdict.Decision.String())
		}
		return out
	}
	live, memo := verdicts(nil), verdicts(NewReplayFS())
	if strings.Join(live, ",") != strings.Join(memo, ",") {
		t.Fatalf("memo changed the verdicts:\nlive %v\nmemo %v", live, memo)
	}
	if len(live) == 0 {
		t.Fatal("the fixture produced no verdicts, so it pins nothing")
	}
}
