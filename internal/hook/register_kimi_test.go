package hook

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// kimiTestBin is the observer binary path the Kimi writer tests register.
const kimiTestBin = "/opt/observer/bin/observer"

func kimiRegistry(t *testing.T, home string, env map[string]string) *Registry {
	t.Helper()
	reg, err := NewRegistry(Options{
		BinaryPath:    kimiTestBin,
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		Getenv:        func(k string) string { return env[k] },
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

// kimiTables decodes body's [[hooks]] tables.
func kimiTables(t *testing.T, body string) []map[string]any {
	t.Helper()
	top := map[string]any{}
	if _, err := toml.Decode(body, &top); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	tables, ok := tomlHookTables(top["hooks"])
	if !ok {
		t.Fatalf("hooks is not a table list: %v", top["hooks"])
	}
	return tables
}

// TestKimiCodeRegisterTable walks the [[hooks]] line editor through the file
// shapes a Kimi Code install can carry (T-378).
func TestKimiCodeRegisterTable(t *testing.T) {
	foreign := "[[hooks]]\nevent = \"PreToolUse\"\nmatcher = \"Bash\"\ncommand = \"node /x/audit.mjs\"\ntimeout = 5\n"
	ours := func(bin, event string) string {
		return "[[hooks]]\ncommand = \"" + bin + " hook kimi-code " + event + "\"\nevent = \"" + event + "\"\ntimeout = 30\n"
	}
	for _, tc := range []struct {
		name    string
		in      string // "" with absent=true: no file
		absent  bool
		keep    []string // substrings that must survive byte for byte
		foreign int      // foreign tables expected after the write
	}{
		{name: "no file", absent: true},
		{name: "empty file", in: ""},
		{
			name: "comments and providers",
			in:   "# top comment\ndefault_model = \"m\"\n\n[providers.openai]\napi_key = \"k\" # note\n",
			keep: []string{"# top comment\n", "api_key = \"k\" # note\n"},
		},
		{
			name:    "foreign hook on the same event",
			in:      "default_model = \"m\"\n\n" + foreign,
			keep:    []string{foreign},
			foreign: 1,
		},
		{
			name: "ours from an old binary between other tables",
			in:   "a = 1\n\n" + ours("/old/observer", "PreToolUse") + "\n# providers follow\n[providers.x]\napi_key = \"k\"\n",
			keep: []string{"a = 1\n", "# providers follow\n[providers.x]\napi_key = \"k\"\n"},
		},
		{name: "CRLF file", in: "# c\r\ndefault_model = \"m\"\r\n", keep: []string{"# c\r\ndefault_model = \"m\"\r\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".kimi-code", "config.toml")
			if !tc.absent {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(tc.in), 0o640); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
			}
			reg := kimiRegistry(t, home, nil)
			res := reg.Register("kimi-code")
			if res.Error != nil {
				t.Fatalf("Register: %v", res.Error)
			}
			if strings.Join(res.HooksAdded, ",") != "UserPromptSubmit,PreToolUse" {
				t.Fatalf("HooksAdded = %v", res.HooksAdded)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, k := range tc.keep {
				if !strings.Contains(string(got), k) {
					t.Errorf("lost %q:\n%s", k, got)
				}
			}
			if strings.Contains(string(got), "/old/observer") {
				t.Errorf("the stale table survived:\n%s", got)
			}
			if strings.Contains(tc.in, "\r\n") && strings.Count(string(got), "\n") != strings.Count(string(got), "\r\n") {
				t.Errorf("line endings mixed:\n%q", got)
			}
			tables := kimiTables(t, string(got))
			var mine, theirs int
			for _, tb := range tables {
				if kimiHookTableIsObservers(tb) {
					mine++
					if tb["timeout"] != int64(30) || !strings.HasPrefix(tb["command"].(string), kimiTestBin+" hook kimi-code ") {
						t.Errorf("observer table = %v", tb)
					}
					for k := range tb {
						if k != "event" && k != "command" && k != "timeout" && k != "matcher" {
							t.Errorf("field %q fails the vendor's config load", k)
						}
					}
					continue
				}
				theirs++
			}
			if mine != 2 || theirs != tc.foreign {
				t.Errorf("tables: mine=%d theirs=%d, want 2 and %d:\n%s", mine, theirs, tc.foreign, got)
			}
			wantMode := os.FileMode(0o640)
			if tc.absent {
				wantMode = 0o600
			}
			if fi, err := os.Stat(path); err != nil || posixModes && fi.Mode().Perm() != wantMode {
				t.Errorf("mode = %v (%v), want %v", fi.Mode().Perm(), err, wantMode)
			}

			// Idempotent byte for byte.
			again := reg.Register("kimi-code")
			if again.Error != nil || len(again.HooksAdded) != 0 || len(again.AlreadySet) != 2 {
				t.Fatalf("second Register = %+v", again)
			}
			if b, _ := os.ReadFile(path); string(b) != string(got) {
				t.Errorf("second Register rewrote the file")
			}

			ures := reg.Unregister("kimi-code")
			if ures.Error != nil {
				t.Fatalf("Unregister: %v", ures.Error)
			}
			if strings.Join(ures.HooksRemoved, ",") != "UserPromptSubmit,PreToolUse" {
				t.Errorf("HooksRemoved = %v", ures.HooksRemoved)
			}
			final, err := os.ReadFile(path)
			if tc.absent || strings.TrimSpace(tc.in) == "" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Errorf("a file Observer created should be removed: %v %q", err, final)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, k := range tc.keep {
				if !strings.Contains(string(final), k) {
					t.Errorf("unregister lost %q:\n%s", k, final)
				}
			}
			for _, tb := range kimiTables(t, string(final)) {
				if kimiHookTableIsObservers(tb) {
					t.Errorf("observer table left after unregister: %v", tb)
				}
			}
			if !strings.Contains(tc.in, "/old/observer") && string(final) != tc.in {
				t.Errorf("register then unregister is not a no-op:\n%q\nwant\n%q", final, tc.in)
			}
		})
	}
}

// TestKimiCodeRefusesShapesItCannotOwn: a hooks key that is not a list of
// [[hooks]] tables is refused without a write and without file contents in
// the error.
func TestKimiCodeRefusesShapesItCannotOwn(t *testing.T) {
	for name, in := range map[string]string{
		"inline array":   "api_key = \"" + credFixtureSecret + "\"\nhooks = [{event = \"Stop\", command = \"x\"}]\n",
		"hooks table":    "api_key = \"" + credFixtureSecret + "\"\n[hooks.x]\nevent = \"Stop\"\n",
		"not a toml doc": "api_key = \"" + credFixtureSecret + "\"\n[[hooks]\n",
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".kimi-code", "config.toml")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
				t.Fatal(err)
			}
			res := kimiRegistry(t, home, nil).Register("kimi-code")
			if res.Error == nil {
				t.Fatal("accepted")
			}
			assertNoSecret(t, "the error", res.Error.Error())
			if b, _ := os.ReadFile(path); string(b) != in {
				t.Error("the file was modified")
			}
		})
	}
}

// TestKimiCodeHonoursKimiCodeHome: an absolute $KIMI_CODE_HOME moves the
// file (the vendor's storage-root override); a relative one names a file
// Observer cannot see, so nothing is written (FU-31).
func TestKimiCodeHonoursKimiCodeHome(t *testing.T) {
	home := t.TempDir()
	alt := filepath.Join(t.TempDir(), "kimi")
	res := kimiRegistry(t, home, map[string]string{"KIMI_CODE_HOME": alt}).Register("kimi-code")
	if res.Error != nil || res.ConfigPath != filepath.Join(alt, "config.toml") {
		t.Fatalf("Register = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(home, ".kimi-code")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the default home was written too: %v", err)
	}
	rel := kimiRegistry(t, home, map[string]string{"KIMI_CODE_HOME": "rel/kimi"})
	if res := rel.Register("kimi-code"); res.Error == nil {
		t.Errorf("relative KIMI_CODE_HOME: Register = %+v, want an error", res)
	}
	if _, err := rel.kimiCodeConfigPath(); err == nil || !strings.Contains(err.Error(), "KIMI_CODE_HOME") {
		t.Errorf("relative KIMI_CODE_HOME: kimiCodeConfigPath err = %v, want one naming the variable", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".kimi-code")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a relative KIMI_CODE_HOME wrote the default home: %v", err)
	}
}

// TestKimiCodeDryRunWritesNothing.
func TestKimiCodeDryRunWritesNothing(t *testing.T) {
	home := t.TempDir()
	reg := kimiRegistry(t, home, nil)
	reg.opts.DryRun = true
	res := reg.Register("kimi-code")
	if res.Error != nil || len(res.HooksAdded) != 2 {
		t.Fatalf("dry run = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(home, ".kimi-code")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("dry run wrote: %v", err)
	}
}
