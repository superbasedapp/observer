package hook

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

const (
	boxTestHome   = "/home/user"
	boxTestBinary = "/home/user/.observer-box/bin/observer"
)

// coveredRows are the registry rows a box can be seeded for.
func coveredRows(t *testing.T) []integration.Capability {
	t.Helper()
	var out []integration.Capability
	for _, c := range integration.Capabilities() {
		if BoxHooksCover(c) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatal("no registry row is covered; Claude Code at least must be")
	}
	return out
}

// TestRenderBoxHooksGolden pins the seeded file of every covered mechanism
// (one golden per covered row): every command runs the in-box observer, no
// --config, inside the box home only. UPDATE_HOOK_GOLDEN=1 rewrites them.
func TestRenderBoxHooksGolden(t *testing.T) {
	for _, c := range coveredRows(t) {
		t.Run(c.Tool, func(t *testing.T) {
			f, err := RenderBoxHooks(BoxHookInput{Capability: c, Home: boxTestHome, Binary: boxTestBinary})
			if err != nil {
				t.Fatalf("RenderBoxHooks: %v", err)
			}
			if !strings.HasPrefix(f.Path, boxTestHome+"/") {
				t.Fatalf("path %q is outside the box home", f.Path)
			}
			if !f.Changed || len(f.Events) == 0 {
				t.Fatalf("a fresh box must get a file with events: %+v", f)
			}
			if strings.Contains(string(f.Content), "--config") {
				t.Fatal("a box command must carry no --config (the box has no config file)")
			}
			gp := filepath.Join("testdata", "hookrender", c.Tool+"-box.json")
			if os.Getenv("UPDATE_HOOK_GOLDEN") == "1" {
				if err := os.WriteFile(gp, f.Content, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(gp)
			if err != nil {
				t.Fatalf("read golden: %v (UPDATE_HOOK_GOLDEN=1 records it)", err)
			}
			if string(f.Content) != string(want) {
				t.Fatalf("box file for %s changed:\n got: %s\nwant: %s", c.Tool, f.Content, want)
			}
		})
	}
}

// TestBoxHookRenderersMatchTheLocalWriters: each box command names the same
// `hook <tool> <event-arg>` the local writer registers (the local golden
// file's commands with the binary and --config dropped), so an in-box
// invocation reaches the same receiver and registry binding as a local one.
func TestBoxHookRenderersMatchTheLocalWriters(t *testing.T) {
	for _, c := range coveredRows(t) {
		t.Run(c.Tool, func(t *testing.T) {
			local, err := os.ReadFile(filepath.Join("testdata", "hookrender", c.Tool+"-fresh.json"))
			if err != nil {
				t.Fatalf("no local golden for covered row %s: %v (add it to TestLocalSettingsWritersGolden)", c.Tool, err)
			}
			f, err := RenderBoxHooks(BoxHookInput{Capability: c, Home: boxTestHome, Binary: boxTestBinary})
			if err != nil {
				t.Fatal(err)
			}
			norm := func(b []byte, bin string) []string {
				var out []string
				for _, cmd := range settingsCommands(t, b) {
					cmd = strings.TrimPrefix(cmd, bin+" ")
					if i := strings.Index(cmd, " --config "); i >= 0 {
						cmd = cmd[:i]
					}
					out = append(out, cmd)
				}
				slices.Sort(out)
				return out
			}
			got, want := norm(f.Content, boxTestBinary), norm(local, "/usr/local/bin/observer")
			if !slices.Equal(got, want) {
				t.Fatalf("box commands differ from the local writer's:\n box: %v\nlocal: %v", got, want)
			}
		})
	}
}

// settingsCommands lists every hook command in a settings document.
func settingsCommands(t *testing.T, b []byte) []string {
	t.Helper()
	var doc struct {
		Hooks map[string][]struct {
			Hooks []claudeHookCommand `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var out []string
	for _, groups := range doc.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				out = append(out, h.Command)
			}
		}
	}
	return out
}

// TestRenderBoxHooksMerge: an existing box file keeps every other key, event
// and foreign entry; Observer's earlier entries (another observer binary)
// are replaced, never doubled; rendering the result again changes nothing.
func TestRenderBoxHooksMerge(t *testing.T) {
	c, _ := integration.For("claude-code")
	existing := []byte(`{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/acme/audit","timeout":30}]},{"matcher":"*","hooks":[{"type":"command","command":"/usr/bin/observer hook claude-code pre-tool"}]}],"Custom":[{"hooks":[{"type":"command","command":"x"}]}]}}`)
	f, err := RenderBoxHooks(BoxHookInput{Capability: c, Home: boxTestHome, Binary: boxTestBinary, Existing: existing})
	if err != nil {
		t.Fatal(err)
	}
	body := string(f.Content)
	for _, want := range []string{`"model":"opus"`, "/opt/acme/audit", `"timeout": 30`, `"Custom"`, boxTestBinary + " hook claude-code pre-tool"} {
		if !strings.Contains(strings.ReplaceAll(body, `"model": "opus"`, `"model":"opus"`), want) {
			t.Fatalf("merged file lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "/usr/bin/observer") {
		t.Fatal("the earlier Observer entry was kept beside the new one")
	}
	if n := strings.Count(body, " hook claude-code pre-tool"); n != 1 {
		t.Fatalf("pre-tool registered %d times, want 1", n)
	}
	again, err := RenderBoxHooks(BoxHookInput{Capability: c, Home: boxTestHome, Binary: boxTestBinary, Existing: f.Content})
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed {
		t.Fatal("re-rendering the seeded file must change nothing (a resumed box)")
	}
}

// TestRenderBoxHooksSharedGroup: the box seed goes through the shared raw
// round-trip (hookentries.go). A stale Observer handler sharing a group with
// a developer's handler is refreshed in its place, never left running
// beside a newly appended group (before, only an Observer-only group was
// replaced, so such a box ran Observer's hook twice, once on the stale
// binary); a stray Observer group later on the event goes; the developer's
// handler and group keep every field and their positions; the developer's
// event order is kept; nothing is HTML-escaped; and rendering the result
// again changes nothing.
func TestRenderBoxHooksSharedGroup(t *testing.T) {
	claude, _ := integration.For("claude-code")
	const (
		stale   = `{"type":"command","command":"/usr/bin/observer hook claude-code pre-tool"}`
		dev     = `{"type":"command","command":"/opt/acme/audit.sh && echo <done>","timeout":30,"statusMessage":"auditing"}`
		devPost = `{"matcher":"Bash","description":"team gate","hooks":[{"type":"command","command":"/opt/acme/post.sh"}]}`
	)
	existing := []byte(`{"model":"opus","hooks":{` +
		`"Stop":[{"hooks":[{"type":"command","command":"/opt/acme/notify"}]}],` +
		`"PreToolUse":[{"matcher":"*","hooks":[` + stale + `,` + dev + `]},` +
		`{"matcher":"*","hooks":[{"type":"command","command":"/usr/lib/observer hook claude-code pre-tool"}]}],` +
		`"PostToolUse":[` + devPost + `]}}`)
	f, err := RenderBoxHooks(BoxHookInput{Capability: claude, Home: boxTestHome, Binary: boxTestBinary, Existing: existing})
	if err != nil {
		t.Fatal(err)
	}
	body := string(f.Content)
	for _, gone := range []string{"/usr/bin/observer", "/usr/lib/observer"} {
		if strings.Contains(body, gone) {
			t.Errorf("a stale Observer handler (%s) survived beside the new one:\n%s", gone, body)
		}
	}
	if n := strings.Count(body, " hook claude-code pre-tool"); n != 1 {
		t.Errorf("pre-tool registered %d times, want 1:\n%s", n, body)
	}
	if !strings.Contains(body, "&& echo <done>") || strings.Contains(body, "u0026") {
		t.Errorf("a command was HTML-escaped:\n%s", body)
	}
	var doc struct {
		Hooks map[string][]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(f.Content, &doc); err != nil {
		t.Fatal(err)
	}
	pre := doc.Hooks["PreToolUse"]
	if len(pre) != 1 {
		t.Fatalf("PreToolUse holds %d groups, want Observer's shared group only (the stray goes): %s", len(pre), pre)
	}
	hs := groupedHookEntries.handlers(pre[0])
	if len(hs) != 2 || !credfile.SameJSON(hs[1], []byte(dev)) {
		t.Fatalf("the developer's handler is not at group 0 handler 1 with every field: %s", pre[0])
	}
	if cmd, _ := groupedHookEntries.command(hs[0]); cmd != boxTestBinary+" hook claude-code pre-tool" {
		t.Errorf("Observer's handler at group 0 handler 0 runs %q", cmd)
	}
	if post := doc.Hooks["PostToolUse"]; len(post) != 2 || !credfile.SameJSON(post[0], []byte(devPost)) {
		t.Errorf("PostToolUse: the developer's group is not kept first with every field: %s", post)
	}
	stop, pre0, post0 := strings.Index(body, `"Stop"`), strings.Index(body, `"PreToolUse"`), strings.Index(body, `"PostToolUse"`)
	if stop < 0 || pre0 < 0 || post0 < 0 || stop > pre0 || pre0 > post0 {
		t.Errorf("the developer's event order (Stop, PreToolUse, PostToolUse) was not kept:\n%s", body)
	}
	again, err := RenderBoxHooks(BoxHookInput{Capability: claude, Home: boxTestHome, Binary: boxTestBinary, Existing: f.Content})
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed || string(again.Content) != string(f.Content) {
		t.Errorf("re-rendering the seeded file changed it:\n%s", again.Content)
	}
}

// TestRenderBoxHooksNarrowedEntryIsRewritten: Observer's own entry, current
// binary but narrowed to one tool (T-847), is never kept as seeded: it is
// rebuilt on the match-all matcher, in its place.
func TestRenderBoxHooksNarrowedEntryIsRewritten(t *testing.T) {
	claude, _ := integration.For("claude-code")
	cur := boxTestBinary + " hook claude-code pre-tool"
	existing := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + cur + `"}]},` +
		`{"matcher":"Edit","hooks":[{"type":"command","command":"/opt/acme/a.sh"}]}]}}`)
	f, err := RenderBoxHooks(BoxHookInput{Capability: claude, Home: boxTestHome, Binary: boxTestBinary, Existing: existing})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Hooks map[string][]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(f.Content, &doc); err != nil {
		t.Fatal(err)
	}
	pre := doc.Hooks["PreToolUse"]
	if len(pre) != 2 || groupedHookEntries.matcher(pre[0]) != "*" || groupedHookEntries.observerCommand(pre[0], func(c string) bool { return c == cur }) == "" {
		t.Fatalf("the narrowed Observer entry was not rebuilt on \"*\" in its place: %s", pre)
	}
	if groupedHookEntries.matcher(pre[1]) != "Edit" {
		t.Errorf("the developer's group moved or changed: %s", pre)
	}
}

// TestRenderBoxHooksRefusals: rows without a box renderer, rows whose gate
// is not wired, a file that turns the tool's hooks off, an environment that
// moves the file and a broken file.
func TestRenderBoxHooksRefusals(t *testing.T) {
	claude, _ := integration.For("claude-code")
	t.Run("not covered", func(t *testing.T) {
		for _, c := range integration.Capabilities() {
			if _, ok := boxHookRenderers[c.Hook.Mechanism]; ok {
				continue
			}
			if BoxHooksCover(c) {
				t.Fatalf("%s is covered with no box renderer", c.Tool)
			}
			if _, err := RenderBoxHooks(BoxHookInput{Capability: c, Home: boxTestHome, Binary: boxTestBinary}); !errors.Is(err, ErrBoxHooksNotCovered) {
				t.Fatalf("%s: err = %v, want ErrBoxHooksNotCovered", c.Tool, err)
			}
		}
	})
	t.Run("no wired gate", func(t *testing.T) {
		c := claude
		c.Hook.Bindings = nil
		if BoxHooksCover(c) {
			t.Fatal("a row with no wired gate binding is never covered")
		}
	})
	t.Run("not auto-wired", func(t *testing.T) {
		c := claude
		c.Hook.AutoWired = false
		if BoxHooksCover(c) {
			t.Fatal("a row init does not register is never covered")
		}
	})
	t.Run("switched off in the file", func(t *testing.T) {
		_, err := RenderBoxHooks(BoxHookInput{Capability: claude, Home: boxTestHome, Binary: boxTestBinary, Existing: []byte(`{"disableAllHooks":true}`)})
		if !errors.Is(err, ErrBoxHooksSwitchedOff) {
			t.Fatalf("err = %v, want ErrBoxHooksSwitchedOff", err)
		}
	})
	t.Run("relocated by the agent env", func(t *testing.T) {
		env := map[string]string{"CLAUDE_CONFIG_DIR": "/home/user/alt"}
		f, err := RenderBoxHooks(BoxHookInput{Capability: claude, Home: boxTestHome, Binary: boxTestBinary, Getenv: func(k string) string { return env[k] }})
		if err != nil {
			t.Fatal(err)
		}
		if f.Path != "/home/user/alt/settings.json" {
			t.Fatalf("path = %q, want the relocated file", f.Path)
		}
	})
	t.Run("broken file", func(t *testing.T) {
		if _, err := RenderBoxHooks(BoxHookInput{Capability: claude, Home: boxTestHome, Binary: boxTestBinary, Existing: []byte(`{"hooks":[]}`)}); err == nil {
			t.Fatal("a hooks member that is not an object must refuse")
		}
	})
	t.Run("relative paths", func(t *testing.T) {
		if _, err := RenderBoxHooks(BoxHookInput{Capability: claude, Home: "home", Binary: boxTestBinary}); err == nil {
			t.Fatal("a relative box home must refuse")
		}
	})
	t.Run("skip event", func(t *testing.T) {
		f, err := RenderBoxHooks(BoxHookInput{Capability: claude, Home: boxTestHome, Binary: boxTestBinary, SkipEvent: func(_, e string) bool { return e == "Setup" }})
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(f.Events, "Setup") || strings.Contains(string(f.Content), " setup\"") {
			t.Fatal("a skipped event was written")
		}
	})
}
