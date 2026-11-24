package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/codextrust"
	"github.com/marmutapp/superbased-observer/internal/credfile"
)

// NEW-06 review follow-up: a developer's handler inside Observer's own
// matcher group. The first refresh used to move Observer's handler out of
// the group (leaving the developer's handler as a group of its own) and
// append a fresh Observer group; the refresh after that then counted the
// leftover group as a --force conflict, so `observer start` failed for the
// tool and every Observer entry kept running the stale binary. Codex, which
// trusts a handler by its position, also silently stopped running the
// developer's handler once it moved. These tests pin, for every grouped
// writer, that a refresh replaces Observer's handler where it sits, that the
// leftover of an earlier split never blocks, and that no developer handler
// changes position.

// new06Bin is the observer binary of refresh run (run 0 installs).
func new06Bin(run int) string { return fmt.Sprintf("/home/u/v%d/observer", run) }

// new06WriteEvent replaces event's entries in the file with entries.
func new06WriteEvent(t *testing.T, path, event string, entries []json.RawMessage) {
	t.Helper()
	top := new06ReadTop(t, path)
	var hooks map[string]json.RawMessage
	if err := json.Unmarshal(top["hooks"], &hooks); err != nil {
		t.Fatal(err)
	}
	list, err := marshalHookJSON(entries)
	if err != nil {
		t.Fatal(err)
	}
	hooks[event] = list
	if top["hooks"], err = marshalHookJSON(hooks); err != nil {
		t.Fatal(err)
	}
	body, err := marshalHookJSON(top)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// new06WithHandlers returns group with its handler list set to handlers.
func new06WithHandlers(t *testing.T, group json.RawMessage, handlers ...json.RawMessage) json.RawMessage {
	t.Helper()
	list, err := marshalHookJSON(handlers)
	if err != nil {
		t.Fatal(err)
	}
	g, err := credfile.SetObjectMember(group, "hooks", list, true)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// new06HandlerAt returns the group and handler position of handler in
// groups, (-1, -1) when it is not there exactly.
func new06HandlerAt(groups []json.RawMessage, handler string) (int, int) {
	for gi, g := range groups {
		for hi, h := range groupedHookEntries.handlers(g) {
			if credfile.SameJSON(h, []byte(handler)) {
				return gi, hi
			}
		}
	}
	return -1, -1
}

// new06InstallGroup installs Observer (run 0) on a fresh file and returns
// its one group on the target's event.
func new06InstallGroup(t *testing.T, e new06Env) json.RawMessage {
	t.Helper()
	if res := e.registry(t, new06Bin(0), false).Register(e.tg.tool); res.Error != nil {
		t.Fatalf("install: %v", res.Error)
	}
	groups := new06Entries(t, e.path, e.tg.event)
	if len(groups) != 1 {
		t.Fatalf("a fresh install wrote %d groups on %s, want 1: %s", len(groups), e.tg.event, groups)
	}
	return groups[0]
}

// new06AssertRefreshed checks run's refresh: no error, the event reported
// as added, no older binary left in the file, and Observer's handler at
// (gi, hi) running this run's binary.
func new06AssertRefreshed(t *testing.T, e new06Env, run int, res RegistrationResult, gi, hi int) []json.RawMessage {
	t.Helper()
	if res.Error != nil {
		t.Fatalf("refresh %d: %v", run, res.Error)
	}
	if !slices.Contains(res.HooksAdded, e.tg.event) {
		t.Errorf("refresh %d: HooksAdded = %v, want %s refreshed", run, res.HooksAdded, e.tg.event)
	}
	body, _ := os.ReadFile(e.path)
	for old := 0; old < run; old++ {
		if strings.Contains(string(body), new06Bin(old)) {
			t.Errorf("refresh %d: the stale binary %s survived:\n%s", run, new06Bin(old), body)
		}
	}
	groups := new06Entries(t, e.path, e.tg.event)
	if gi >= len(groups) {
		t.Fatalf("refresh %d: %d groups on %s, want Observer's at %d: %s", run, len(groups), e.tg.event, gi, groups)
	}
	hs := groupedHookEntries.handlers(groups[gi])
	if hi >= len(hs) {
		t.Fatalf("refresh %d: group %d holds %d handlers, want Observer's at %d: %s", run, gi, len(hs), hi, groups[gi])
	}
	if cmd, _ := groupedHookEntries.command(hs[hi]); !strings.Contains(cmd, new06Bin(run)) {
		t.Errorf("refresh %d: handler %d of group %d runs %q, want Observer on %s", run, hi, gi, cmd, new06Bin(run))
	}
	return groups
}

// TestNEW06SharedGroupRefreshesInPlace: a developer's handler sits in
// Observer's group after Observer's handler. Three refreshes in a row, as
// `observer start` runs them (no --force), each replace only Observer's
// handler, in its place: the group is never split, and the developer's
// handler stays at group 0, handler 1 with every field.
func TestNEW06SharedGroupRefreshesInPlace(t *testing.T) {
	t.Parallel()
	for _, tg := range new06Targets() {
		if !tg.layout.grouped {
			continue
		}
		t.Run(tg.tool, func(t *testing.T) {
			t.Parallel()
			e := newNew06Env(t, tg)
			obs := new06InstallGroup(t, e)
			dev := new06UserHandler(tg.layout)
			shared := new06WithHandlers(t, obs, append(groupedHookEntries.handlers(obs), json.RawMessage(dev))...)
			new06WriteEvent(t, e.path, tg.event, []json.RawMessage{shared})

			for run := 1; run <= 3; run++ {
				res := e.registry(t, new06Bin(run), false).Register(tg.tool)
				groups := new06AssertRefreshed(t, e, run, res, 0, 0)
				if len(groups) != 1 {
					t.Errorf("refresh %d split Observer's group: %s", run, groups)
				}
				if gi, hi := new06HandlerAt(groups, dev); gi != 0 || hi != 1 {
					t.Errorf("refresh %d: the developer's handler is at group %d handler %d, want 0/1: %s", run, gi, hi, groups)
				}
			}
			first, _ := os.ReadFile(e.path)
			if res := e.registry(t, new06Bin(3), false).Register(tg.tool); res.Error != nil || len(res.HooksAdded) != 0 {
				t.Fatalf("re-register: err %v, added %v; want already set", res.Error, res.HooksAdded)
			}
			if again, _ := os.ReadFile(e.path); string(again) != string(first) {
				t.Errorf("an already-current file was rewritten:\n%s", again)
			}
		})
	}
}

// TestNEW06DeveloperGroupOnObserverMatcherNeverBlocksRefresh: a developer's
// own group on Observer's matcher, beside Observer's group, never blocks a
// refresh, whichever side it is on, and nothing on the event moves. "before"
// is what the refresh before this fix left behind (the developer's handler
// alone where Observer's group was, Observer's group appended): such a file
// recovers on the next start. "drifted" is Observer's handler weakened
// (T-847) while it shares the group: the rewrite takes Observer's handler
// out, the developer's group stays where it was, and the later refreshes
// then go through.
func TestNEW06DeveloperGroupOnObserverMatcherNeverBlocksRefresh(t *testing.T) {
	t.Parallel()
	type scenario struct {
		name string
		// build returns the event's groups from Observer's installed group
		// and a group holding only the developer's handler on Observer's
		// matcher.
		build func(t *testing.T, obs, devOnly json.RawMessage) []json.RawMessage
		// devAt and obsAt are where the developer's handler and Observer's
		// handler must be after every refresh.
		devAt, obsAt [2]int
	}
	scenarios := []scenario{
		{
			name: "before",
			build: func(_ *testing.T, obs, devOnly json.RawMessage) []json.RawMessage {
				return []json.RawMessage{devOnly, obs}
			},
			devAt: [2]int{0, 0}, obsAt: [2]int{1, 0},
		},
		{
			name: "after",
			build: func(_ *testing.T, obs, devOnly json.RawMessage) []json.RawMessage {
				return []json.RawMessage{obs, devOnly}
			},
			devAt: [2]int{1, 0}, obsAt: [2]int{0, 0},
		},
		{
			name: "drifted",
			build: func(t *testing.T, obs, devOnly json.RawMessage) []json.RawMessage {
				h := groupedHookEntries.handlers(obs)[0]
				weak, err := credfile.SetObjectMember(h, "timeout", json.RawMessage("1"), true)
				if err != nil {
					t.Fatal(err)
				}
				return []json.RawMessage{new06WithHandlers(t, obs, weak, groupedHookEntries.handlers(devOnly)[0])}
			},
			devAt: [2]int{0, 0}, obsAt: [2]int{1, 0},
		},
	}
	for _, tg := range new06Targets() {
		if !tg.layout.grouped {
			continue
		}
		for _, sc := range scenarios {
			t.Run(tg.tool+"/"+sc.name, func(t *testing.T) {
				t.Parallel()
				e := newNew06Env(t, tg)
				obs := new06InstallGroup(t, e)
				dev := new06UserHandler(tg.layout)
				devOnly := new06WithHandlers(t, obs, json.RawMessage(dev))
				new06WriteEvent(t, e.path, tg.event, sc.build(t, obs, devOnly))

				for run := 1; run <= 3; run++ {
					res := e.registry(t, new06Bin(run), false).Register(tg.tool)
					groups := new06AssertRefreshed(t, e, run, res, sc.obsAt[0], sc.obsAt[1])
					if len(groups) != 2 {
						t.Errorf("refresh %d: %d groups, want 2: %s", run, len(groups), groups)
					}
					if gi, hi := new06HandlerAt(groups, dev); gi != sc.devAt[0] || hi != sc.devAt[1] {
						t.Errorf("refresh %d: the developer's handler is at group %d handler %d, want %d/%d: %s",
							run, gi, hi, sc.devAt[0], sc.devAt[1], groups)
					}
					if !credfile.SameJSON(groups[sc.devAt[0]], devOnly) {
						t.Errorf("refresh %d: the developer's group changed: %s", run, groups[sc.devAt[0]])
					}
				}
			})
		}
	}
}

// TestNEW06DeveloperGroupElsewhereStillBlocksRefresh: the --force rule is
// unchanged for a developer's group on another matcher. It still blocks a
// refresh without --force on the writers that check every group, and the
// file is left untouched; native Claude Code only ever counted the
// match-all groups.
func TestNEW06DeveloperGroupElsewhereStillBlocksRefresh(t *testing.T) {
	t.Parallel()
	for _, tg := range new06Targets() {
		if !tg.layout.grouped || tg.tool == "claude-code" {
			continue
		}
		t.Run(tg.tool, func(t *testing.T) {
			t.Parallel()
			e := newNew06Env(t, tg)
			obs := new06InstallGroup(t, e)
			new06WriteEvent(t, e.path, tg.event, []json.RawMessage{obs, json.RawMessage(new06UserEntry(tg.layout))})
			before, _ := os.ReadFile(e.path)
			res := e.registry(t, new06Bin(1), false).Register(tg.tool)
			if res.Error == nil {
				t.Fatal("a developer's group on another matcher no longer blocks the refresh without --force")
			}
			if !strings.Contains(res.Error.Error(), "--force") {
				t.Errorf("refused for another reason: %v", res.Error)
			}
			if after, _ := os.ReadFile(e.path); string(after) != string(before) {
				t.Errorf("the refused refresh wrote the file:\n%s", after)
			}
		})
	}
}

// codexTrustedAt reports whether Codex runs the handler hooks.json holds at
// event, group gi, handler hi: config.toml's [hooks.state] record keyed by
// that position carries the handler's current hash (codextrust.Hash).
func codexTrustedAt(t *testing.T, dir, event string, gi, hi int) bool {
	t.Helper()
	hooksPath := filepath.Join(dir, "hooks.json")
	hooksRaw, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	var hf struct {
		Hooks map[string][]struct {
			Matcher *string `json:"matcher"`
			Hooks   []struct {
				Command string `json:"command"`
				Timeout *int64 `json:"timeout"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(hooksRaw, &hf); err != nil {
		t.Fatal(err)
	}
	if gi >= len(hf.Hooks[event]) || hi >= len(hf.Hooks[event][gi].Hooks) {
		return false
	}
	g := hf.Hooks[event][gi]
	h := g.Hooks[hi]
	timeout := int64(600)
	if h.Timeout != nil {
		timeout = *h.Timeout
	}
	snake := codextrust.CamelToSnake(event)
	want := codextrust.Hash(snake, g.Matcher, h.Command, timeout, false, nil)
	var cfg struct {
		Hooks struct {
			State map[string]struct {
				TrustedHash string `toml:"trusted_hash"`
			} `toml:"state"`
		} `toml:"hooks"`
	}
	cfgRaw, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := toml.Unmarshal(cfgRaw, &cfg); err != nil {
		t.Fatal(err)
	}
	key := hooksPath + ":" + snake + ":" + strconv.Itoa(gi) + ":" + strconv.Itoa(hi)
	return cfg.Hooks.State[key].TrustedHash == want
}

// TestNEW06CodexRefreshKeepsDeveloperTrust: Codex runs a hooks.json handler
// only when config.toml trusts it at its position
// ("<path>:<event>:<group>:<handler>"). A developer trusted two handlers of
// their own, one inside Observer's PreToolUse group and one in their own
// "*" group after Observer's PostToolUse group. Three refreshes (no
// --force) keep both at the positions they were trusted at, so Codex still
// runs them, and Observer's own entries are re-trusted at theirs.
func TestNEW06CodexRefreshKeepsDeveloperTrust(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hooksPath := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("model = \"gpt-x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := new06Env{tg: new06Target{tool: "codex", layout: groupedHookEntries, event: "PreToolUse"}, home: home, path: hooksPath}
	if res := e.registry(t, new06Bin(0), false).Register("codex"); res.Error != nil || len(res.TrustRecorded) == 0 {
		t.Fatalf("install: %v, trust recorded %v", res.Error, res.TrustRecorded)
	}

	const (
		inGroup = `{"type":"command","command":"/opt/acme/audit.sh","timeout":30}`
		ownCmd  = `{"type":"command","command":"/opt/acme/after.sh"}`
	)
	pre := new06Entries(t, hooksPath, "PreToolUse")
	new06WriteEvent(t, hooksPath, "PreToolUse", []json.RawMessage{
		new06WithHandlers(t, pre[0], append(groupedHookEntries.handlers(pre[0]), json.RawMessage(inGroup))...),
	})
	post := new06Entries(t, hooksPath, "PostToolUse")
	new06WriteEvent(t, hooksPath, "PostToolUse", []json.RawMessage{post[0], json.RawMessage(`{"matcher":"*","hooks":[` + ownCmd + `]}`)})

	// The developer approves their two handlers in codex /hooks.
	star := "*"
	cfg, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg = append(cfg, fmt.Sprintf("\n[hooks.state.%s]\ntrusted_hash = %q\n\n[hooks.state.%s]\ntrusted_hash = %q\n",
		strconv.Quote(hooksPath+":pre_tool_use:0:1"), codextrust.Hash("pre_tool_use", &star, "/opt/acme/audit.sh", 30, false, nil),
		strconv.Quote(hooksPath+":post_tool_use:1:0"), codextrust.Hash("post_tool_use", &star, "/opt/acme/after.sh", 600, false, nil))...)
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	if !codexTrustedAt(t, dir, "PreToolUse", 0, 1) || !codexTrustedAt(t, dir, "PostToolUse", 1, 0) {
		t.Fatal("the developer's trust records do not verify before any refresh")
	}

	for run := 1; run <= 3; run++ {
		res := e.registry(t, new06Bin(run), false).Register("codex")
		new06AssertRefreshed(t, e, run, res, 0, 0)
		if gi, hi := new06HandlerAt(new06Entries(t, hooksPath, "PreToolUse"), inGroup); gi != 0 || hi != 1 {
			t.Errorf("refresh %d: the handler in Observer's group moved to %d/%d, want 0/1", run, gi, hi)
		}
		if gi, hi := new06HandlerAt(new06Entries(t, hooksPath, "PostToolUse"), ownCmd); gi != 1 || hi != 0 {
			t.Errorf("refresh %d: the developer's own group moved to %d/%d, want 1/0", run, gi, hi)
		}
		if !codexTrustedAt(t, dir, "PreToolUse", 0, 1) {
			t.Errorf("refresh %d: Codex no longer trusts the developer's handler in Observer's group", run)
		}
		if !codexTrustedAt(t, dir, "PostToolUse", 1, 0) {
			t.Errorf("refresh %d: Codex no longer trusts the developer's own PostToolUse group", run)
		}
		for _, ent := range codexTrustReport(t, dir, hooksPath).Entries {
			if ent.State != codextrust.StateTrusted {
				t.Errorf("refresh %d: Observer's %s entry is %s, want trusted", run, ent.Event, ent.State)
			}
		}
	}
}

// TestNEW06KiroV3UnregisterKeepsTopLevelKeys: unregistering removes
// Observer's definitions but never deletes a file that still holds a
// top-level key of the developer's, even with no developer definition
// left in it.
func TestNEW06KiroV3UnregisterKeepsTopLevelKeys(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	r, err := NewRegistry(Options{
		BinaryPath:    "/home/u/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := r.kiroV3Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":"v1","hooks":[],"x-team-policy":`+new06TopLevel+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := r.registerKiroV3Hooks(); res.Error != nil || len(res.HooksAdded) == 0 {
		t.Fatalf("register: %v %v", res.Error, res.HooksAdded)
	}
	if res := r.unregisterKiroV3Hooks(); res.Error != nil || len(res.HooksRemoved) == 0 {
		t.Fatalf("unregister: %v %v", res.Error, res.HooksRemoved)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("unregister deleted a file holding the developer's top-level key: %v", err)
	}
	top := new06ReadTop(t, path)
	if !credfile.SameJSON(top["x-team-policy"], []byte(new06TopLevel)) {
		t.Errorf("x-team-policy changed: %s", top["x-team-policy"])
	}
	var hooks []json.RawMessage
	if err := json.Unmarshal(top["hooks"], &hooks); err != nil {
		t.Fatalf("hooks: %v", err)
	}
	for _, h := range hooks {
		if kiroV3IsObservers(h) {
			t.Errorf("Observer's definition survived the unregister: %s", h)
		}
	}
}
