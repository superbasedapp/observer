package hook

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// The fake credential every JSON fixture carries in its env block: a
// statusline writer must keep its bytes and never put it in an error.
const slFakeSecret = "sk-test-0000000000000000"

// newStatusLineRegistry is a Linux-shaped registry over a temp home (the
// test write guard refuses anything outside it).
func newStatusLineRegistry(t *testing.T, home string, mut func(*Options)) *Registry {
	t.Helper()
	opts := Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		GOOS:          "linux",
	}
	if mut != nil {
		mut(&opts)
	}
	r, err := NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func slWrite(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func slSum(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return string(s[:])
}

// slToolFile is each --statusline-tools tool's config file under home
// (Linux layout).
var slToolFile = map[string]string{
	"codebuddy": ".codebuddy/settings.json",
	"kimchi":    ".config/kimchi/harness/settings.json",
	"vtcode":    ".config/vtcode/vtcode.toml",
}

// TestStatusLineToolsRoundTrip is the byte-identical contract: for every
// tool and every starting file, register writes Observer's status line,
// a second register is a no-op, and unregister restores the exact bytes
// (or the absence) the file had before.
func TestStatusLineToolsRoundTrip(t *testing.T) {
	jsonStarts := map[string]string{
		"absent":         "",
		"with env+hooks": "{\n  \"env\": {\n    \"CODEBUDDY_API_KEY\": \"" + slFakeSecret + "\"\n  },\n  \"hooks\": {\"PreToolUse\": []},\n  \"model\":\"x\"\n}\n",
		"crlf compact":   "{\r\n\t\"theme\": \"dark\",\r\n\t\"env\": {\"K\": \"" + slFakeSecret + "\"}\r\n}\r\n",
		"empty object":   "{}\n",
	}
	tomlStarts := map[string]string{
		"absent":           "",
		"lf":               "[agent]\nprovider = \"openai\"\n\n[[hooks.lifecycle.pre_tool_use]]\nhooks = [{ type = \"command\", command = \"x\" }]\n",
		"crlf":             "[agent]\r\nprovider = \"openai\"\r\n",
		"no final newline": "[agent]\nprovider = \"openai\"",
		"ui table":         "[ui]\ntheme = \"ciapre\"\n\n[ui.status_line]\n",
		"trailing blanks":  "[ui]\ntheme = \"x\"\n\n\n",
	}
	// "ui table" above declares an empty [ui.status_line]: that is a status
	// line setting, so it is refused below, not round-tripped.
	delete(tomlStarts, "ui table")
	tomlStarts["ui keys"] = "[ui]\ntheme = \"ciapre\"\n"

	for tool, rel := range slToolFile {
		starts := jsonStarts
		if strings.HasSuffix(rel, ".toml") {
			starts = tomlStarts
		}
		for name, body := range starts {
			t.Run(tool+"/"+name, func(t *testing.T) {
				home := t.TempDir()
				path := filepath.Join(home, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if body != "" {
					slWrite(t, path, body)
				}
				before := slSum(t, path)
				r := newStatusLineRegistry(t, home, nil)

				res := r.RegisterStatusLine(tool)
				if res.Error != nil || res.Skipped {
					t.Fatalf("register: err=%v skipped=%v (%s)", res.Error, res.Skipped, res.SkipReason)
				}
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if body != "" && strings.Contains(body, slFakeSecret) && !strings.Contains(string(got), slFakeSecret) {
					t.Fatal("the env block's bytes did not survive")
				}
				wantCmd := r.statusLineCommand(tool, r.mustSpec(t, tool))
				if !strings.Contains(string(got), jsonOrTOMLString(wantCmd)) {
					t.Fatalf("config does not carry the command %q:\n%s", wantCmd, got)
				}
				if strings.HasSuffix(rel, ".toml") && !strings.Contains(string(got), "\ncommand_timeout_ms = 1000") {
					t.Fatalf("vtcode table does not carry command_timeout_ms = 1000:\n%s", got)
				}

				again := r.RegisterStatusLine(tool)
				if again.Error != nil || len(again.AlreadySet) == 0 || len(again.HooksAdded) != 0 {
					t.Fatalf("second register = %+v, want already set", again)
				}
				if string(got) != slRead(t, path) {
					t.Fatal("second register rewrote the file")
				}

				un := r.UnregisterStatusLine(tool)
				if un.Error != nil || len(un.HooksRemoved) == 0 {
					t.Fatalf("unregister = %+v", un)
				}
				if name == "empty object" {
					// A settings object left with no members is removed,
					// the Claude Code writer's rule (an absent file is the
					// vendor's default too); this is the one start that is
					// not restored byte for byte.
					before = "absent"
				}
				if after := slSum(t, path); after != before {
					t.Fatalf("unregister did not restore the file byte for byte:\nbefore %q\nafter  %q", body, slRead(t, path))
				}
				if _, err := os.Stat(r.statusLineScriptDir()); !os.IsNotExist(err) {
					t.Errorf("wrapper directory left behind: %v", err)
				}
			})
		}
	}
}

func slRead(t *testing.T, path string) string {
	t.Helper()
	b, _ := os.ReadFile(path)
	return string(b)
}

// jsonOrTOMLString is how both formats spell a command string.
func jsonOrTOMLString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (r *Registry) mustSpec(t *testing.T, tool string) integration.StatusLineSpec {
	t.Helper()
	spec, _, _, _, err := r.statusLineTarget(tool)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// TestStatusLineToolsCommandShape pins the dispatch on the exec shape: a
// shell host gets `<observer> statusline --host <tool>`, a script-path host
// gets a marker-owned wrapper script that execs the same command.
func TestStatusLineToolsCommandShape(t *testing.T) {
	home := t.TempDir()
	for _, rel := range slToolFile {
		_ = os.MkdirAll(filepath.Join(home, filepath.Dir(filepath.FromSlash(rel))), 0o755)
	}
	r := newStatusLineRegistry(t, home, nil)
	for _, c := range []struct {
		tool   string
		script bool
	}{{"codebuddy", false}, {"kimchi", true}, {"vtcode", true}} {
		if res := r.RegisterStatusLine(c.tool); res.Error != nil {
			t.Fatalf("%s: %v", c.tool, res.Error)
		}
		cmd := r.statusLineCommand(c.tool, r.mustSpec(t, c.tool))
		if !c.script {
			if cmd != "/opt/observer/bin/observer statusline --host "+c.tool {
				t.Errorf("%s: command %q", c.tool, cmd)
			}
			continue
		}
		if cmd != filepath.Join(home, ".observer", "statusline", c.tool+".sh") {
			t.Errorf("%s: command %q is not the wrapper path", c.tool, cmd)
		}
		data, err := os.ReadFile(cmd)
		if err != nil {
			t.Fatalf("%s: wrapper: %v", c.tool, err)
		}
		want := "#!/bin/sh\n" + statusLineScriptMarker(c.tool) + "\nexec /opt/observer/bin/observer statusline --host " + c.tool + "\n"
		if string(data) != want {
			t.Errorf("%s: wrapper =\n%s\nwant\n%s", c.tool, data, want)
		}
		if runtime.GOOS != "windows" {
			if fi, _ := os.Lstat(cmd); !fi.Mode().IsRegular() || fi.Mode().Perm()&0o100 == 0 {
				t.Errorf("%s: wrapper is not a regular executable file (%v)", c.tool, fi.Mode())
			}
		}
		if !r.isOwnStatusLineScript(cmd) {
			t.Errorf("%s: own wrapper not recognised", c.tool)
		}
	}
}

// TestStatusLineToolsConflict pins the single-slot rule: a status line the
// user set themselves is refused without --force (the error never quotes
// the file), left alone by unregister, and replaced only with --force.
func TestStatusLineToolsConflict(t *testing.T) {
	cases := []struct {
		tool, foreign string
	}{
		{"codebuddy", "{\n  \"env\": {\"CODEBUDDY_API_KEY\": \"" + slFakeSecret + "\"},\n  \"statusLine\": {\"type\": \"command\", \"command\": \"~/bin/my-line " + slFakeSecret + "\"}\n}\n"},
		{"kimchi", "{\"statusLine\": {\"command\": \"~/.config/kimchi/line.sh\"}}\n"},
		{"vtcode", "[ui.status_line]\nmode = \"auto\"\n"},
		{"vtcode", "[ui.status_line]\nmode = \"command\"\ncommand = \"/home/u/line.sh\"\n"},
	}
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, filepath.FromSlash(slToolFile[c.tool]))
			slWrite(t, path, c.foreign)
			r := newStatusLineRegistry(t, home, nil)
			res := r.RegisterStatusLine(c.tool)
			if res.Error == nil || !strings.Contains(res.Error.Error(), "--force") {
				t.Fatalf("register over a foreign status line: %v", res.Error)
			}
			if strings.Contains(res.Error.Error(), slFakeSecret) || strings.Contains(res.Error.Error(), "line.sh") {
				t.Fatalf("error quotes the file: %v", res.Error)
			}
			if slRead(t, path) != c.foreign {
				t.Fatal("a refused register changed the file")
			}
			if _, err := os.Stat(r.statusLineScriptDir()); !os.IsNotExist(err) {
				t.Error("a refused register wrote a wrapper script")
			}
			un := r.UnregisterStatusLine(c.tool)
			if un.Error != nil || len(un.HooksKept) == 0 || slRead(t, path) != c.foreign {
				t.Fatalf("unregister of a foreign status line = %+v", un)
			}

			forced := newStatusLineRegistry(t, home, func(o *Options) { o.Force = true })
			if res := forced.RegisterStatusLine(c.tool); res.Error != nil || len(res.HooksAdded) == 0 {
				t.Fatalf("forced register = %+v", res)
			}
			if c.tool == "codebuddy" && !strings.Contains(slRead(t, path), slFakeSecret) {
				t.Fatal("forced register lost the env block")
			}
			if un := forced.UnregisterStatusLine(c.tool); un.Error != nil || len(un.HooksRemoved) == 0 {
				t.Fatalf("unregister after force = %+v", un)
			}
		})
	}
}

// TestStatusLineToolsRefreshesStale pins the observer-owned-but-stale case:
// an entry naming an older observer binary is refreshed without --force.
func TestStatusLineToolsRefreshesStale(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".codebuddy", "settings.json")
	slWrite(t, path, "{\"statusLine\": {\"type\": \"command\", \"command\": \"/old/observer-v1.2 statusline --host codebuddy\", \"padding\": 0}}\n")
	r := newStatusLineRegistry(t, home, nil)
	if res := r.RegisterStatusLine("codebuddy"); res.Error != nil || len(res.HooksAdded) == 0 {
		t.Fatalf("refresh = %+v", res)
	}
	if !strings.Contains(slRead(t, path), "/opt/observer/bin/observer statusline --host codebuddy") {
		t.Fatalf("not refreshed:\n%s", slRead(t, path))
	}
}

// TestStatusLineToolsVTCodeShapes pins the TOML editor's limits: content a
// user adds after Observer's table survives unregister, and a status line
// set in a shape the line editor cannot follow is refused even with --force.
func TestStatusLineToolsVTCodeShapes(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".config", "vtcode", "vtcode.toml")
	slWrite(t, path, "[agent]\nprovider = \"openai\"\n")
	r := newStatusLineRegistry(t, home, nil)
	if res := r.RegisterStatusLine("vtcode"); res.Error != nil {
		t.Fatal(res.Error)
	}
	slWrite(t, path, slRead(t, path)+"\n[tools]\ndefault_policy = \"prompt\"\n")
	if un := r.UnregisterStatusLine("vtcode"); un.Error != nil {
		t.Fatal(un.Error)
	}
	if got, want := slRead(t, path), "[agent]\nprovider = \"openai\"\n\n[tools]\ndefault_policy = \"prompt\"\n"; got != want {
		t.Fatalf("after unregister:\n%q\nwant\n%q", got, want)
	}

	inline := "[ui]\nstatus_line = { mode = \"auto\" }\n"
	slWrite(t, path, inline)
	forced := newStatusLineRegistry(t, home, func(o *Options) { o.Force = true })
	if res := forced.RegisterStatusLine("vtcode"); res.Error == nil {
		t.Fatal("an inline ui.status_line was edited")
	}
	if slRead(t, path) != inline {
		t.Fatal("a refused edit changed the file")
	}
}

// TestStatusLineToolsVTCodeCommandTimeout pins VT Code's command_timeout_ms
// (AP-133 follow-up): Observer's [ui.status_line] table carries 1000 unless
// the table it replaces already set a value, which is kept as is (never
// lowered, never raised); an own table holding the user's value is already
// set; and uninstall restores the pre-register bytes.
func TestStatusLineToolsVTCodeCommandTimeout(t *testing.T) {
	const base = "[agent]\nprovider = \"openai\"\n"
	const ours = "command_timeout_ms = 1000\n"
	// ownWith registers on base, then rewrites Observer's timeout line.
	ownWith := func(line string) func(t *testing.T, r *Registry, path string) {
		return func(t *testing.T, r *Registry, path string) {
			slWrite(t, path, base)
			if res := r.RegisterStatusLine("vtcode"); res.Error != nil {
				t.Fatal(res.Error)
			}
			body := slRead(t, path)
			if !strings.Contains(body, ours) {
				t.Fatalf("fixture: no %q in\n%s", ours, body)
			}
			slWrite(t, path, strings.Replace(body, ours, line, 1))
		}
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, r *Registry, path string)
		force bool
		// wantLine is the timeout line the table carries after register.
		wantLine string
		// alreadySet: the register is a no-op that leaves the file as set up.
		alreadySet bool
		// restore is the file after unregister ("" = not checked).
		restore string
	}{
		{
			name:     "fresh file",
			setup:    func(t *testing.T, _ *Registry, path string) { slWrite(t, path, base) },
			wantLine: ours,
			restore:  base,
		},
		{
			name:       "own table, user raised it",
			setup:      ownWith("command_timeout_ms = 5000\n"),
			wantLine:   "command_timeout_ms = 5000\n",
			alreadySet: true,
			restore:    base,
		},
		{
			name:       "own table, user lowered it",
			setup:      ownWith("command_timeout_ms = 150\n"),
			wantLine:   "command_timeout_ms = 150\n",
			alreadySet: true,
			restore:    base,
		},
		{
			name:     "own table written before the key existed",
			setup:    ownWith(""),
			wantLine: ours,
			restore:  base,
		},
		{
			name: "stale own command keeps the user's value",
			setup: func(t *testing.T, _ *Registry, path string) {
				slWrite(t, path, base+"\n"+vtStatusLineMarker(false)+"\n[ui.status_line]\nmode = \"command\"\ncommand = \"/old/observer-v1 statusline\"\ncommand_timeout_ms = 4000\n")
			},
			wantLine: "command_timeout_ms = 4000\n",
			restore:  base,
		},
		{
			name: "forced over the user's table keeps their value",
			setup: func(t *testing.T, _ *Registry, path string) {
				slWrite(t, path, "[ui.status_line]\nmode = \"command\"\ncommand = \"/home/u/line.sh\"\ncommand_timeout_ms = 2500\n")
			},
			force:    true,
			wantLine: "command_timeout_ms = 2500\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".config", "vtcode", "vtcode.toml")
			r := newStatusLineRegistry(t, home, func(o *Options) { o.Force = c.force })
			c.setup(t, r, path)
			before := slRead(t, path)

			res := r.RegisterStatusLine("vtcode")
			if res.Error != nil {
				t.Fatalf("register: %v", res.Error)
			}
			got := slRead(t, path)
			if c.alreadySet {
				if len(res.AlreadySet) == 0 || got != before {
					t.Fatalf("register = %+v, want already set and the file untouched:\n%s", res, got)
				}
			} else if len(res.HooksAdded) == 0 {
				t.Fatalf("register = %+v, want the table written", res)
			}
			if strings.Count(got, "command_timeout_ms") != 1 || !strings.Contains(got, "\n"+c.wantLine) {
				t.Fatalf("table does not carry exactly %q:\n%s", c.wantLine, got)
			}
			if again := r.RegisterStatusLine("vtcode"); again.Error != nil || len(again.AlreadySet) == 0 || slRead(t, path) != got {
				t.Fatalf("second register = %+v", again)
			}

			un := r.UnregisterStatusLine("vtcode")
			if un.Error != nil || len(un.HooksRemoved) == 0 {
				t.Fatalf("unregister = %+v", un)
			}
			after := slRead(t, path)
			if strings.Contains(after, "status_line") || strings.Contains(after, "command_timeout_ms") {
				t.Fatalf("unregister left the table behind:\n%s", after)
			}
			if c.restore != "" && after != c.restore {
				t.Fatalf("unregister did not restore the file byte for byte:\n%q\nwant\n%q", after, c.restore)
			}
		})
	}
}

// TestVTTOMLValue pins the renderer that carries a user's own
// command_timeout_ms over verbatim, whatever TOML type they wrote.
func TestVTTOMLValue(t *testing.T) {
	for _, c := range []struct {
		in   any
		want string
	}{
		{int64(1000), "1000"},
		{int64(-5), "-5"},
		{"500", `"500"`},
		{1.5, "1.5"},
	} {
		got, err := vtTOMLValue(c.in)
		if err != nil || got != c.want {
			t.Errorf("vtTOMLValue(%#v) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

// TestStatusLineToolsSkipsAndRefusals pins the honest skips: no vendor
// directory, a script-path host on Windows, a tool with no such writer,
// and a dry run that writes nothing.
func TestStatusLineToolsSkipsAndRefusals(t *testing.T) {
	home := t.TempDir()
	r := newStatusLineRegistry(t, home, nil)
	if res := r.RegisterStatusLine("kimchi"); !res.Skipped || res.Error != nil {
		t.Errorf("no ~/.config/kimchi/harness: %+v", res)
	}
	win := newStatusLineRegistry(t, home, func(o *Options) { o.GOOS = "windows" })
	_ = os.MkdirAll(filepath.Join(home, ".config", "kimchi", "harness"), 0o755)
	if res := win.RegisterStatusLine("kimchi"); !res.Skipped || res.Error != nil {
		t.Errorf("kimchi on windows: %+v", res)
	}
	for _, tool := range []string{"claude-code", "stakpak", "no-such-tool"} {
		if res := r.RegisterStatusLine(tool); res.Error == nil {
			t.Errorf("%s: registered through --statusline-tools", tool)
		}
	}
	dry := newStatusLineRegistry(t, home, func(o *Options) { o.DryRun = true })
	res := dry.RegisterStatusLine("kimchi")
	if res.Error != nil || len(res.HooksAdded) == 0 {
		t.Fatalf("dry run = %+v", res)
	}
	if entries, _ := os.ReadDir(filepath.Join(home, ".config", "kimchi", "harness")); len(entries) != 0 {
		t.Errorf("dry run wrote %d entries", len(entries))
	}
	if _, err := os.Stat(dry.statusLineScriptDir()); !os.IsNotExist(err) {
		t.Error("dry run wrote the wrapper script")
	}
}
