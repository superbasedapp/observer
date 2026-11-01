package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/BurntSushi/toml"
)

// This file pins the three-item defect ledger deferred out of the WP9
// adversarial-review round (commit ca520d20): hook_checksums.json's
// unlocked non-atomic write, the Codex TOML/JSON writers' fixed `.tmp`
// names, and the unregister-path symlink edge in the empty-file
// removal branch. See docs/handovers/session-parking-2026-07-30-
// growth-session1-close.md §3.6.

// TestConcurrentChecksumWritersDoNotCorrupt pins the ledger's item 1:
// recordChecksum's read-modify-write of hook_checksums.json takes no
// cross-process lock and writes via a plain os.WriteFile (no atomic
// temp+rename), unlike every settings/config writer in this package
// since WP9. Many observer processes registering DIFFERENT tools
// concurrently — a totally ordinary `observer init` scenario, since
// every registrar calls recordChecksum against the SAME shared
// ~/.observer/hook_checksums.json — must not corrupt the file or lose
// each other's entries.
func TestConcurrentChecksumWritersDoNotCorrupt(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	csPath := filepath.Join(home, ".observer", "hook_checksums.json")
	if err := os.MkdirAll(filepath.Dir(csPath), 0o755); err != nil {
		t.Fatal(err)
	}

	const writers = 16
	var wg sync.WaitGroup
	errs := make([]error, writers)
	paths := make([]string, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := NewRegistry(Options{
				BinaryPath:    "/opt/observer/bin/observer",
				HomeDir:       home,
				ChecksumsPath: csPath,
			})
			if err != nil {
				errs[i] = err
				return
			}
			cfgPath := filepath.Join(home, fmt.Sprintf("config-%d.json", i))
			if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf(`{"n":%d}`, i)), 0o600); err != nil {
				errs[i] = err
				return
			}
			paths[i] = cfgPath
			<-start // maximize collision by releasing all writers together
			errs[i] = r.recordChecksum("", cfgPath)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("writer %d: %v", i, err)
		}
	}

	body, err := os.ReadFile(csPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("hook_checksums.json corrupted by concurrent writers: %v\n%s", err, body)
	}
	missing := 0
	for i, p := range paths {
		if _, ok := got[p]; !ok {
			missing++
			t.Logf("writer %d entry for %s missing after concurrent recordChecksum", i, p)
		}
	}
	if missing > 0 {
		t.Errorf("%d/%d entries lost to unlocked concurrent writes to hook_checksums.json", missing, writers)
	}
}

// TestConcurrentCodexWritersDoNotCorrupt pins the ledger's item 2: the
// Codex hooks.json and config.toml writers (writeCodexHooks,
// ensureCodexHooksFeatureFlag) use a FIXED `<path>.tmp` name and
// registerCodex/unregisterCodex take no advisory lock at all — unlike
// every other registrar in this package. Many observer processes
// running `observer init --codex` concurrently must each succeed and
// leave both files parseable, never a spliced/torn body from two
// writers sharing one temp filename.
func TestConcurrentCodexWritersDoNotCorrupt(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(home, ".codex", "config.toml")
	pre := "personality = \"pragmatic\"\n"
	if err := os.WriteFile(cfgPath, []byte(pre), 0o600); err != nil {
		t.Fatal(err)
	}

	const writers = 16
	var wg sync.WaitGroup
	errs := make([]error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := NewRegistry(Options{
				BinaryPath:    fmt.Sprintf("/opt/observer-%d/bin/observer", i),
				HomeDir:       home,
				ChecksumsPath: filepath.Join(home, fmt.Sprintf(".observer-%d", i), "hook_checksums.json"),
			})
			if err != nil {
				errs[i] = err
				return
			}
			<-start
			errs[i] = r.Register("codex").Error
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("writer %d: %v", i, err)
		}
	}

	hooksPath := filepath.Join(home, ".codex", "hooks.json")
	hooksBody, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	var hooksGot map[string]any
	if err := json.Unmarshal(hooksBody, &hooksGot); err != nil {
		t.Fatalf("hooks.json corrupted by concurrent writers: %v\n%s", err, hooksBody)
	}
	hooks, ok := hooksGot["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks.json missing top-level hooks block after concurrent writers:\n%s", hooksBody)
	}
	for _, event := range codexEvents {
		if _, ok := hooks[event]; !ok {
			t.Errorf("event %s missing from hooks.json after concurrent register:\n%s", event, hooksBody)
		}
	}

	cfgBody, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfgGot map[string]any
	if err := toml.Unmarshal(cfgBody, &cfgGot); err != nil {
		t.Fatalf("config.toml corrupted by concurrent writers: %v\n%s", err, cfgBody)
	}
	if _, ok := cfgGot["personality"]; !ok {
		t.Errorf("personality lost from config.toml by concurrent writers:\n%s", cfgBody)
	}
	features, _ := cfgGot["features"].(map[string]any)
	if hv, _ := features["hooks"].(bool); !hv {
		t.Errorf("features.hooks not true after concurrent writers:\n%s", cfgBody)
	}
}

// TestUnregisterRefusesSymlinkedEmptyConfig pins the ledger's item 3:
// when a registrar's config file has become empty and would normally
// be deleted, a SYMLINKED config (the shape a dotfile manager
// produces — same premise as TestSettingsWriterFollowsSymlink) must
// not be silently os.Remove'd. Removing the link only unlinks the
// dirent; the TARGET file — the one the AI tool and any dotfile repo
// actually track — survives untouched with its stale observer hook
// entry still in place, while the registrar reports success. The fix
// must refuse (report res.Error) and leave both the link and its
// target exactly as they were, mirroring the "refuse and name the
// file" stance readSettingsFile/decodeSettingsObject already take for
// shapes this package can't honestly rewrite.
func TestUnregisterRefusesSymlinkedEmptyConfig(t *testing.T) {
	type tc struct {
		name       string
		register   func(r *Registry) error
		unregister func(r *Registry) UnregistrationResult
		relPath    []string
	}
	cases := []tc{
		{
			name:       "claude-code",
			register:   func(r *Registry) error { return r.Register("claude-code").Error },
			unregister: func(r *Registry) UnregistrationResult { return r.Unregister("claude-code") },
			relPath:    []string{".claude", "settings.json"},
		},
		{
			name:       "cursor",
			register:   func(r *Registry) error { return r.Register("cursor").Error },
			unregister: func(r *Registry) UnregistrationResult { return r.Unregister("cursor") },
			relPath:    []string{".cursor", "hooks.json"},
		},
		{
			name:       "claude-code-statusline",
			register:   func(r *Registry) error { return r.RegisterClaudeCodeStatusline().Error },
			unregister: func(r *Registry) UnregistrationResult { return r.UnregisterClaudeCodeStatusline() },
			relPath:    []string{".claude", "settings.json"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			for _, d := range []string{".claude", ".cursor"} {
				if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			r, err := NewRegistry(Options{
				BinaryPath:    "/opt/observer/bin/observer",
				HomeDir:       home,
				ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.register(r); err != nil {
				t.Fatalf("register: %v", err)
			}

			link := filepath.Join(append([]string{home}, c.relPath...)...)
			body, err := os.ReadFile(link)
			if err != nil {
				t.Fatal(err)
			}
			dotfiles := t.TempDir()
			target := filepath.Join(dotfiles, "config.json")
			if err := os.WriteFile(target, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlinks unavailable on this platform/privilege level: %v", err)
			}

			res := c.unregister(r)
			if res.Error == nil {
				t.Fatalf("expected unregister to refuse a symlinked config that would become empty, got success: %+v", res)
			}

			fi, err := os.Lstat(link)
			if err != nil {
				t.Fatalf("symlink disappeared: %v", err)
			}
			if fi.Mode()&os.ModeSymlink == 0 {
				t.Fatal("symlink was replaced/removed instead of being refused")
			}
			after, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if len(after) == 0 {
				t.Error("symlink target was emptied even though unregister reported an error")
			}
			if string(after) != string(body) {
				t.Errorf("symlink target was modified even though unregister reported an error:\nbefore=%s\nafter=%s", body, after)
			}
		})
	}
}
