package hostfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
)

const zedSettings = `// Zed settings
{
  "theme": "One Dark", // the user's comment
  "context_servers": {
    "other": { "command": "x", "env": { "TOKEN": "secret-value" } },
  },
}
`

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
}

// TestApplyKeepsEverythingElse: one member set in a JSONC file keeps the
// comments, the sibling server and the mode, takes a backup of the prior
// bytes, and a second run changes nothing.
func TestApplyKeepsEverythingElse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "zed", "settings.json")
	write(t, p, zedSettings)
	entry := map[string]any{"command": "/opt/observer", "args": []any{"serve"}}
	res, err := Apply(Edit{Path: p, Format: cfgfmt.FormatJSONC, Member: []string{"context_servers", "superbased-observer"}, Value: entry})
	if err != nil || !res.Changed || res.Created || res.Backup == "" {
		t.Fatalf("Apply = %+v, %v", res, err)
	}
	got, _ := os.ReadFile(p)
	for _, want := range []string{"// Zed settings", "// the user's comment", `"TOKEN": "secret-value"`, `"superbased-observer"`, `"/opt/observer"`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("result lacks %q:\n%s", want, got)
		}
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
			t.Errorf("mode = %v, want 0640 kept", fi.Mode().Perm())
		}
	}
	if b, _ := os.ReadFile(res.Backup); string(b) != zedSettings {
		t.Errorf("backup = %q", b)
	}
	if len(fsatomic.DisplacedCopies(p)) != 1 {
		t.Errorf("backups = %v", fsatomic.DisplacedCopies(p))
	}
	again, err := Apply(Edit{Path: p, Format: cfgfmt.FormatJSONC, Member: []string{"context_servers", "superbased-observer"}, Value: entry})
	if err != nil || again.Changed {
		t.Errorf("re-run = %+v, %v", again, err)
	}
	v, found, err := Value(p, cfgfmt.FormatJSONC, []string{"context_servers", "superbased-observer", "command"})
	if err != nil || !found || v != "/opt/observer" {
		t.Errorf("Value = %v, %v, %v", v, found, err)
	}
	rm, err := Apply(Edit{Path: p, Format: cfgfmt.FormatJSONC, Member: []string{"context_servers", "superbased-observer"}, Remove: true})
	if err != nil || !rm.Changed {
		t.Fatalf("remove = %+v, %v", rm, err)
	}
	if got, _ := os.ReadFile(p); strings.Contains(string(got), "superbased-observer") || !strings.Contains(string(got), "secret-value") {
		t.Errorf("after removal:\n%s", got)
	}
}

// TestApplyCreatesOnlyInAnExistingDir: a missing file in an existing
// directory is created (0600); a missing directory is refused and nothing
// is created; a removal from a missing file is a no-op; a dry run writes
// nothing.
func TestApplyCreatesOnlyInAnExistingDir(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "mcp.json")
	dry, err := Apply(Edit{Path: p, Format: cfgfmt.FormatJSON, Member: []string{"servers", "x"}, Value: "y", DryRun: true})
	if err != nil || !dry.Changed {
		t.Fatalf("dry run = %+v, %v", dry, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("a dry run wrote the file")
	}
	res, err := Apply(Edit{Path: p, Format: cfgfmt.FormatJSON, Member: []string{"servers", "x"}, Value: "y"})
	if err != nil || !res.Created || res.Backup != "" {
		t.Fatalf("Apply = %+v, %v", res, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Errorf("new file mode = %v", fi.Mode().Perm())
		}
	}
	missing := filepath.Join(root, "absent", "mcp.json")
	if _, err := Apply(Edit{Path: missing, Format: cfgfmt.FormatJSON, Member: []string{"servers", "x"}, Value: "y"}); !errors.Is(err, ErrNoHostDir) {
		t.Errorf("missing dir err = %v", err)
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Error("the directory was created")
	}
	if r, err := Apply(Edit{Path: filepath.Join(root, "none.json"), Format: cfgfmt.FormatJSON, Member: []string{"a"}, Remove: true}); err != nil || r.Changed {
		t.Errorf("removal from a missing file = %+v, %v", r, err)
	}
}

// TestApplyRefusesLinks: a linked directory or a linked file is refused and
// the link target is untouched.
func TestApplyRefusesLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "settings.json"), "{}\n")
	if err := os.Symlink(outside, filepath.Join(root, "zed")); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(Edit{Path: filepath.Join(root, "zed", "settings.json"), Format: cfgfmt.FormatJSONC, Member: []string{"a"}, Value: "b"}); !errors.Is(err, ErrLink) {
		t.Errorf("linked dir err = %v", err)
	}
	dir := filepath.Join(root, "real")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "settings.json"), filepath.Join(dir, "settings.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(Edit{Path: filepath.Join(dir, "settings.json"), Format: cfgfmt.FormatJSONC, Member: []string{"a"}, Value: "b"}); !errors.Is(err, ErrLink) {
		t.Errorf("linked file err = %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "settings.json")); string(b) != "{}\n" {
		t.Errorf("link target changed: %q", b)
	}
}

// TestApplyWithholdsFileContent: a file that does not parse is refused and
// the error carries no byte of it.
func TestApplyWithholdsFileContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	write(t, p, `{"key": "sk-live-SECRET" broken`)
	_, err := Apply(Edit{Path: p, Format: cfgfmt.FormatJSON, Member: []string{"a"}, Value: "b"})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("err = %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != `{"key": "sk-live-SECRET" broken` {
		t.Error("an unparseable file was rewritten")
	}
}

// TestApplyNoBackup: a credential-bearing file is edited with no displaced
// copy beside it.
func TestApplyNoBackup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	write(t, p, `{"apiKey": "sk-SECRET"}`)
	res, err := Apply(Edit{Path: p, Format: cfgfmt.FormatJSON, Member: []string{"mcpServers", "x"}, Value: "y", NoBackup: true})
	if err != nil || !res.Changed || res.Backup != "" {
		t.Fatalf("Apply = %+v, %v", res, err)
	}
	if got := fsatomic.DisplacedCopies(p); len(got) != 0 {
		t.Errorf("backups = %v, want none", got)
	}
}
