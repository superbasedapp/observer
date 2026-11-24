package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/credfile"
)

// NEW-06 (ship-readiness audit 2026-11-23): hook registration at `observer
// start` rewrote ~/.cursor/hooks.json through a struct holding only
// "command", so a developer's own entries lost their timeout, matcher and
// type without a warning. The same typed round trip sat in the Cursor
// wsl.exe bridge, the Claude Code Windows bridge, the generic settings
// writer (Gemini CLI, Qwen Code, Qoder), Codex's hooks.json (which also
// lost every top-level key beside "hooks"), and, at the group level, the
// native Claude Code writer. Every one now goes through hookentries.go.
// These tests pin, per writer, on fixture files in temp dirs:
//
//   - a developer's entries carrying fields Observer never writes survive
//     a register, a refresh and an unregister exactly (field set, values,
//     number literals, an unescaped && or <...>);
//   - unknown top-level keys survive;
//   - a second registration with Observer's entry already present changes
//     nothing, byte for byte;
//   - a file Observer cannot edit without guessing is refused with a clear
//     message and left byte-identical.

// new06Target is one registration target and the shape of its hooks file.
type new06Target struct {
	tool string
	// file is the hooks file under the sandbox home.
	file func(home, winHome string) string
	// layout is where a handler sits in an entry.
	layout hookEntryLayout
	// event is one event Observer registers on this target.
	event string
	// windows sets the cross-OS bridge options.
	windows bool
}

func new06Targets() []new06Target {
	native := func(rel ...string) func(home, winHome string) string {
		return func(home, _ string) string { return filepath.Join(append([]string{home}, rel...)...) }
	}
	win := func(rel ...string) func(home, winHome string) string {
		return func(_, winHome string) string { return filepath.Join(append([]string{winHome}, rel...)...) }
	}
	return []new06Target{
		{tool: "cursor", file: native(".cursor", "hooks.json"), layout: flatHookEntries, event: "beforeShellExecution"},
		{tool: "cursor-windows", file: win(".cursor", "hooks.json"), layout: flatHookEntries, event: "beforeShellExecution", windows: true},
		{tool: "claude-code", file: native(".claude", "settings.json"), layout: groupedHookEntries, event: "PreToolUse"},
		{tool: "claude-code-windows", file: win(".claude", "settings.json"), layout: groupedHookEntries, event: "PreToolUse", windows: true},
		{tool: "gemini-cli", file: native(".gemini", "settings.json"), layout: groupedHookEntries, event: "BeforeAgent"},
		{tool: "qwen-code", file: native(".qwen", "settings.json"), layout: groupedHookEntries, event: "UserPromptSubmit"},
		{tool: "codex", file: native(".codex", "hooks.json"), layout: groupedHookEntries, event: "PreToolUse"},
		{tool: "codex-windows", file: win(".codex", "hooks.json"), layout: groupedHookEntries, event: "PreToolUse", windows: true},
	}
}

// new06Env is one target's sandbox: the home, the Windows home under it and
// the hooks file path.
type new06Env struct {
	tg            new06Target
	home, winHome string
	path          string
}

func newNew06Env(t *testing.T, tg new06Target) new06Env {
	t.Helper()
	home := t.TempDir()
	winHome := nestedWinHome(t, home)
	e := new06Env{tg: tg, home: home, winHome: winHome, path: tg.file(home, winHome)}
	if err := os.MkdirAll(filepath.Dir(e.path), 0o755); err != nil {
		t.Fatal(err)
	}
	return e
}

// registry builds a Registry over the sandbox (bin is the observer binary
// the entries run).
func (e new06Env) registry(t *testing.T, bin string, force bool) *Registry {
	t.Helper()
	o := Options{
		BinaryPath:    bin,
		HomeDir:       e.home,
		Force:         force,
		ChecksumsPath: filepath.Join(e.home, ".observer", "hook_checksums.json"),
	}
	if e.tg.windows {
		o.WindowsCursorHome = e.winHome
		o.WindowsClaudeHome = e.winHome
		o.WindowsCodexHome = e.winHome
		o.WSLDistro = "Ubuntu-24.04"
	}
	r, err := NewRegistry(o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// new06UserHandler is the developer's own handler: fields Observer never
// writes, a number literal a float64 round trip would change, and a command
// with characters an HTML-escaping encoder rewrites.
func new06UserHandler(l hookEntryLayout) string {
	if l.grouped {
		return `{"type":"command","command":"/opt/acme/audit.sh && echo <done>","timeout":30,"statusMessage":"auditing","env":{"ACME":"1"},"retries":1.0}`
	}
	return `{"command":"/opt/acme/audit.sh && echo <done>","timeout":30,"matcher":"rm|curl","type":"command","env":{"ACME":"1"},"retries":1.0}`
}

// new06UserEntry is the developer's entry as the event list holds it: the
// handler itself (flat) or a group of their own around it.
func new06UserEntry(l hookEntryLayout) string {
	if l.grouped {
		return `{"matcher":"Bash","description":"team gate","hooks":[` + new06UserHandler(l) + `]}`
	}
	return new06UserHandler(l)
}

// new06TopLevel is an unknown top-level member with a 64-bit integer that a
// float64 round trip would corrupt.
const new06TopLevel = `{"owner":"secops","ticket":9007199254740993,"tags":["a<b","c&d"]}`

// new06Seed is a hooks file holding only the developer's content: their
// entry on an event Observer registers and on one it never touches, an
// unknown event, and unknown top-level keys.
func new06Seed(tg new06Target) string {
	entry := new06UserEntry(tg.layout)
	return `{
  "x-team-policy": ` + new06TopLevel + `,
  "hooks": {
    "` + tg.event + `": [` + entry + `],
    "UserDefinedEvent": [` + entry + `]
  },
  "zeta": [1.50, true, null]
}`
}

// new06ReadTop decodes the file's top-level members.
func new06ReadTop(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	top := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("%s is not a JSON object: %v\n%s", path, err, b)
	}
	return top
}

// new06Entries returns event's entries in the file.
func new06Entries(t *testing.T, path, event string) []json.RawMessage {
	t.Helper()
	var hooks map[string][]json.RawMessage
	if err := json.Unmarshal(new06ReadTop(t, path)["hooks"], &hooks); err != nil {
		t.Fatalf("hooks member: %v", err)
	}
	return hooks[event]
}

// new06AssertUserContent checks every piece of the developer's seed is in
// the file exactly (credfile.SameJSON compares number literals as text):
// the top-level keys, and their entry on both events.
func new06AssertUserContent(t *testing.T, e new06Env) {
	t.Helper()
	top := new06ReadTop(t, e.path)
	if !credfile.SameJSON(top["x-team-policy"], []byte(new06TopLevel)) {
		t.Errorf("x-team-policy changed: %s", top["x-team-policy"])
	}
	if !credfile.SameJSON(top["zeta"], []byte(`[1.50, true, null]`)) {
		t.Errorf("zeta changed: %s", top["zeta"])
	}
	body, _ := os.ReadFile(e.path)
	if !bytes.Contains(body, []byte("9007199254740993")) || !bytes.Contains(body, []byte(`&& echo <done>`)) {
		t.Errorf("a number literal or an unescaped command was rewritten:\n%s", body)
	}
	for _, ev := range []string{e.tg.event, "UserDefinedEvent"} {
		found := false
		for _, entry := range new06Entries(t, e.path, ev) {
			if credfile.SameJSON(entry, []byte(new06UserEntry(e.tg.layout))) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: the developer's entry lost or changed a field; entries = %s", ev, new06Entries(t, e.path, ev))
		}
	}
}

// new06ObserverCount counts Observer's command handlers on event.
func new06ObserverCount(t *testing.T, e new06Env, event string) int {
	t.Helper()
	n := 0
	for _, entry := range new06Entries(t, e.path, event) {
		for _, c := range e.tg.layout.commands(entry) {
			if strings.Contains(c, " hook ") && strings.Contains(c, "observer") {
				n++
			}
		}
	}
	return n
}

func TestNEW06RegisterKeepsUserFieldsAndTopLevelKeys(t *testing.T) {
	t.Parallel()
	for _, tg := range new06Targets() {
		t.Run(tg.tool, func(t *testing.T) {
			t.Parallel()
			e := newNew06Env(t, tg)
			if err := os.WriteFile(e.path, []byte(new06Seed(tg)), 0o600); err != nil {
				t.Fatal(err)
			}
			// --force: the developer's entry shares an event Observer
			// registers (without it the conflict rule refuses, as before).
			res := e.registry(t, "/home/u/bin/observer", true).Register(tg.tool)
			if res.Error != nil {
				t.Fatalf("Register: %v", res.Error)
			}
			if new06ObserverCount(t, e, tg.event) != 1 {
				t.Fatalf("Observer's entry missing on %s: %s", tg.event, new06Entries(t, e.path, tg.event))
			}
			new06AssertUserContent(t, e)
		})
	}
}

func TestNEW06SecondRegistrationIsByteIdentical(t *testing.T) {
	t.Parallel()
	for _, tg := range new06Targets() {
		t.Run(tg.tool, func(t *testing.T) {
			t.Parallel()
			e := newNew06Env(t, tg)
			if err := os.WriteFile(e.path, []byte(new06Seed(tg)), 0o600); err != nil {
				t.Fatal(err)
			}
			if res := e.registry(t, "/home/u/bin/observer", true).Register(tg.tool); res.Error != nil {
				t.Fatalf("first Register: %v", res.Error)
			}
			first, err := os.ReadFile(e.path)
			if err != nil {
				t.Fatal(err)
			}
			// What `observer start` does: no --force, Observer's entries
			// already present beside the developer's.
			for run := 2; run <= 3; run++ {
				res := e.registry(t, "/home/u/bin/observer", false).Register(tg.tool)
				if res.Error != nil {
					t.Fatalf("run %d: %v", run, res.Error)
				}
				if len(res.HooksAdded) != 0 || len(res.Rewrites) != 0 {
					t.Errorf("run %d: added %v, rewrites %v; want none", run, res.HooksAdded, res.Rewrites)
				}
				got, err := os.ReadFile(e.path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, first) {
					t.Fatalf("run %d rewrote the file:\n--- before\n%s\n--- after\n%s", run, first, got)
				}
			}
			new06AssertUserContent(t, e)
		})
	}
}

// TestNEW06HandEditedFileIsLeftAlone is the reported case: Observer's entries
// are installed, the developer then adds their own entries (with fields
// Observer never writes) and a top-level key by hand, and the next
// `observer start` must leave the file exactly as they left it.
func TestNEW06HandEditedFileIsLeftAlone(t *testing.T) {
	t.Parallel()
	for _, tg := range new06Targets() {
		t.Run(tg.tool, func(t *testing.T) {
			t.Parallel()
			e := newNew06Env(t, tg)
			if res := e.registry(t, "/home/u/bin/observer", false).Register(tg.tool); res.Error != nil {
				t.Fatalf("install: %v", res.Error)
			}
			top := new06ReadTop(t, e.path)
			var hooks map[string][]json.RawMessage
			if err := json.Unmarshal(top["hooks"], &hooks); err != nil {
				t.Fatal(err)
			}
			hooks[tg.event] = append(hooks[tg.event], json.RawMessage(new06UserEntry(tg.layout)))
			hooks["UserDefinedEvent"] = []json.RawMessage{json.RawMessage(new06UserEntry(tg.layout))}
			hb, err := marshalHookJSON(hooks)
			if err != nil {
				t.Fatal(err)
			}
			top["hooks"] = hb
			top["x-team-policy"] = json.RawMessage(new06TopLevel)
			top["zeta"] = json.RawMessage(`[1.50, true, null]`)
			edited, err := marshalHookJSON(top)
			if err != nil {
				t.Fatal(err)
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, edited, "", "\t"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(e.path, pretty.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}

			res := e.registry(t, "/home/u/bin/observer", false).Register(tg.tool)
			if res.Error != nil {
				t.Fatalf("Register over the hand-edited file: %v", res.Error)
			}
			if len(res.HooksAdded) != 0 {
				t.Errorf("HooksAdded = %v, want none (Observer's entries were present)", res.HooksAdded)
			}
			got, err := os.ReadFile(e.path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, pretty.Bytes()) {
				t.Fatalf("the hand-edited file was rewritten:\n--- before\n%s\n--- after\n%s", pretty.Bytes(), got)
			}
		})
	}
}

// TestNEW06RefreshKeepsUserFields: a stale Observer entry (another binary
// path) is replaced; the developer's entries keep every field.
func TestNEW06RefreshKeepsUserFields(t *testing.T) {
	t.Parallel()
	for _, tg := range new06Targets() {
		t.Run(tg.tool, func(t *testing.T) {
			t.Parallel()
			e := newNew06Env(t, tg)
			if err := os.WriteFile(e.path, []byte(new06Seed(tg)), 0o600); err != nil {
				t.Fatal(err)
			}
			if res := e.registry(t, "/home/u/old/observer", true).Register(tg.tool); res.Error != nil {
				t.Fatalf("install: %v", res.Error)
			}
			res := e.registry(t, "/home/u/new/observer", true).Register(tg.tool)
			if res.Error != nil {
				t.Fatalf("refresh: %v", res.Error)
			}
			body, _ := os.ReadFile(e.path)
			if bytes.Contains(body, []byte("/home/u/old/observer")) {
				t.Errorf("the stale Observer entry survived:\n%s", body)
			}
			if new06ObserverCount(t, e, tg.event) != 1 {
				t.Errorf("want exactly one Observer entry on %s: %s", tg.event, new06Entries(t, e.path, tg.event))
			}
			new06AssertUserContent(t, e)
		})
	}
}

// TestNEW06SharedGroupHandlerSurvives: in the matcher-group family, a
// developer's handler placed inside Observer's own group stays there with
// every field: a present entry is still "already set" (no rewrite), and a
// refresh replaces only Observer's handler.
func TestNEW06SharedGroupHandlerSurvives(t *testing.T) {
	t.Parallel()
	for _, tg := range new06Targets() {
		if !tg.layout.grouped {
			continue
		}
		t.Run(tg.tool, func(t *testing.T) {
			t.Parallel()
			e := newNew06Env(t, tg)
			if res := e.registry(t, "/home/u/old/observer", false).Register(tg.tool); res.Error != nil {
				t.Fatalf("install: %v", res.Error)
			}
			top := new06ReadTop(t, e.path)
			var hooks map[string][]map[string]json.RawMessage
			if err := json.Unmarshal(top["hooks"], &hooks); err != nil {
				t.Fatal(err)
			}
			g := hooks[tg.event][0]
			var hs []json.RawMessage
			if err := json.Unmarshal(g["hooks"], &hs); err != nil {
				t.Fatal(err)
			}
			hs = append(hs, json.RawMessage(new06UserHandler(tg.layout)))
			g["hooks"], _ = marshalHookJSON(hs)
			hb, _ := marshalHookJSON(hooks)
			top["hooks"] = hb
			edited, _ := marshalHookJSON(top)
			if err := os.WriteFile(e.path, edited, 0o600); err != nil {
				t.Fatal(err)
			}

			res := e.registry(t, "/home/u/old/observer", false).Register(tg.tool)
			if res.Error != nil || len(res.HooksAdded) != 0 {
				t.Fatalf("re-register: err %v, added %v; want already set", res.Error, res.HooksAdded)
			}
			if got, _ := os.ReadFile(e.path); !bytes.Equal(got, edited) {
				t.Fatalf("the file changed:\n%s", got)
			}

			res = e.registry(t, "/home/u/new/observer", false).Register(tg.tool)
			if res.Error != nil {
				t.Fatalf("refresh: %v", res.Error)
			}
			found := false
			for _, entry := range new06Entries(t, e.path, tg.event) {
				for _, h := range tg.layout.handlers(entry) {
					if credfile.SameJSON(h, []byte(new06UserHandler(tg.layout))) {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("the developer's handler in Observer's group was lost or changed: %s", new06Entries(t, e.path, tg.event))
			}
			if body, _ := os.ReadFile(e.path); bytes.Contains(body, []byte("/home/u/old/observer")) {
				t.Errorf("the stale Observer handler survived:\n%s", body)
			}
		})
	}
}

func TestNEW06UnregisterKeepsUserFields(t *testing.T) {
	t.Parallel()
	for _, tg := range new06Targets() {
		t.Run(tg.tool, func(t *testing.T) {
			t.Parallel()
			e := newNew06Env(t, tg)
			if err := os.WriteFile(e.path, []byte(new06Seed(tg)), 0o600); err != nil {
				t.Fatal(err)
			}
			if res := e.registry(t, "/home/u/bin/observer", true).Register(tg.tool); res.Error != nil {
				t.Fatalf("install: %v", res.Error)
			}
			res := e.registry(t, "/home/u/bin/observer", false).Unregister(tg.tool)
			if res.Error != nil {
				t.Fatalf("Unregister: %v", res.Error)
			}
			if len(res.HooksRemoved) == 0 {
				t.Fatalf("nothing removed: %+v", res)
			}
			if n := new06ObserverCount(t, e, tg.event); n != 0 {
				t.Errorf("%d Observer entries left on %s", n, tg.event)
			}
			new06AssertUserContent(t, e)
		})
	}
}

// TestNEW06MalformedFileIsRefusedUntouched: a file Observer cannot edit
// without guessing is refused with a message naming the file, and its bytes
// stay exactly as they were (Cursor used to swallow the decode error and
// write its own entries over the whole hooks member).
func TestNEW06MalformedFileIsRefusedUntouched(t *testing.T) {
	t.Parallel()
	type malformed struct {
		name, body string
		grouped    bool // only for the matcher-group family
		why        string
	}
	cases := func(event string) []malformed {
		return []malformed{
			{name: "not JSON", body: `{"hooks": {"` + event + `": [`, why: "parse"},
			{name: "hooks is a list", body: `{"hooks": [{"command": "/opt/acme/a.sh"}]}`, why: "not an object of event lists"},
			{name: "hooks is a string", body: `{"hooks": "/opt/acme/a.sh"}`, why: "not an object of event lists"},
			{name: "event is an object", body: `{"hooks": {"` + event + `": {"command": "/opt/acme/a.sh"}}}`, why: "is not a list of hook entries"},
			{name: "entry is a string", body: `{"hooks": {"` + event + `": ["/opt/acme/a.sh"]}}`, why: "is not an object"},
			{name: "event listed twice", body: `{"hooks": {"` + event + `": [], "` + event + `": []}}`, why: "twice"},
			{name: "group hooks is a string", grouped: true, body: `{"hooks": {"` + event + `": [{"matcher": "*", "hooks": "/opt/acme/a.sh"}]}}`, why: "not a list"},
			{name: "group handler is a string", grouped: true, body: `{"hooks": {"` + event + `": [{"matcher": "*", "hooks": ["/opt/acme/a.sh"]}]}}`, why: "not an object"},
		}
	}
	for _, tg := range new06Targets() {
		for _, c := range cases(tg.event) {
			if c.grouped && !tg.layout.grouped {
				continue
			}
			t.Run(tg.tool+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				e := newNew06Env(t, tg)
				if err := os.WriteFile(e.path, []byte(c.body), 0o600); err != nil {
					t.Fatal(err)
				}
				for _, force := range []bool{false, true} {
					res := e.registry(t, "/home/u/bin/observer", force).Register(tg.tool)
					if res.Error == nil {
						t.Fatalf("force=%v: Register accepted a malformed file", force)
					}
					msg := res.Error.Error()
					if !strings.Contains(msg, e.path) || !strings.Contains(msg, c.why) {
						t.Errorf("force=%v: message %q does not name the file and the problem (%q)", force, msg, c.why)
					}
					if c.why != "parse" && !strings.Contains(msg, "nothing was written") {
						t.Errorf("force=%v: message %q does not say nothing was written", force, msg)
					}
					if got, _ := os.ReadFile(e.path); string(got) != c.body {
						t.Fatalf("force=%v: the malformed file was modified:\n%s", force, got)
					}
				}
				if ures := e.registry(t, "/home/u/bin/observer", true).Unregister(tg.tool); ures.Error == nil {
					t.Errorf("Unregister accepted a malformed file")
				}
				if got, _ := os.ReadFile(e.path); string(got) != c.body {
					t.Fatalf("Unregister modified the malformed file:\n%s", got)
				}
			})
		}
	}
}

// TestNEW06KiroV3KeepsUnknownTopLevelKeys: Observer's own V3 hooks file
// keeps a top-level key and a definition it does not own across a register,
// a no-op re-register (byte-identical) and an unregister.
func TestNEW06KiroV3KeepsUnknownTopLevelKeys(t *testing.T) {
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
	userHook := `{"name":"acme","trigger":"PreToolUse","action":{"type":"command","command":"/opt/acme/a.sh && x"},"timeout":30,"note":"keep"}`
	seed := `{"version":"v1","hooks":[` + userHook + `],"x-team-policy":` + new06TopLevel + `}`
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(stage string) {
		t.Helper()
		top := new06ReadTop(t, path)
		if !credfile.SameJSON(top["x-team-policy"], []byte(new06TopLevel)) {
			t.Errorf("%s: x-team-policy changed: %s", stage, top["x-team-policy"])
		}
		var hooks []json.RawMessage
		_ = json.Unmarshal(top["hooks"], &hooks)
		found := false
		for _, h := range hooks {
			if credfile.SameJSON(h, []byte(userHook)) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: the developer's definition changed: %s", stage, top["hooks"])
		}
	}
	if res := r.registerKiroV3Hooks(); res.Error != nil || len(res.HooksAdded) == 0 {
		t.Fatalf("register: %v %v", res.Error, res.HooksAdded)
	}
	check("register")
	first, _ := os.ReadFile(path)
	if res := r.registerKiroV3Hooks(); res.Error != nil || len(res.HooksAdded) != 0 {
		t.Fatalf("re-register: %v %v", res.Error, res.HooksAdded)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(again, first) {
		t.Fatalf("re-register rewrote the file:\n%s", again)
	}
	if res := r.unregisterKiroV3Hooks(); res.Error != nil || len(res.HooksRemoved) == 0 {
		t.Fatalf("unregister: %v %v", res.Error, res.HooksRemoved)
	}
	check("unregister")
}
