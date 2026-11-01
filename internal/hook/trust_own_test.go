package hook

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestObserverOwnCommandBinaries: the executable comes back only for the
// command shapes Observer's registrars write, including the WSL bridge; a
// look-alike behind any other prefix gives none.
func TestObserverOwnCommandBinaries(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"/usr/local/bin/observer hook claude-code pre-tool", []string{"/usr/local/bin/observer"}},
		{"'/opt/My Tools/observer' hook codex stop --config '/home/u/My Config/config.toml'", []string{"/opt/My Tools/observer"}},
		{"MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- /home/u/observer hook claude-code stop", []string{"/home/u/observer"}},
		{"wsl.exe -d Ubuntu -- /home/u/observer hook cursor stop", []string{"/home/u/observer"}},
		{`C:\Users\u\observer.exe hook cursor stop`, []string{"C:/Users/u/observer.exe"}},
		{"LD_PRELOAD=evil.so /usr/local/bin/observer hook claude-code stop", nil},
		{"FOO=1 wsl.exe -d Ubuntu -- /home/u/observer hook claude-code stop", nil},
		{"wsl.exe -e /home/u/observer hook claude-code stop", nil},
		{"node evil.js hook claude-code stop", nil},
	}
	for _, c := range cases {
		if got := ObserverHookCommandBinaries(c.cmd); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ObserverHookCommandBinaries(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
	if got := ObserverStatuslineCommandBinaries("'/opt/obs/observer' statusline"); !reflect.DeepEqual(got, []string{"/opt/obs/observer"}) {
		t.Errorf("status line: %q", got)
	}
	if got := ObserverStatuslineCommandBinaries("node /opt/acme statusline"); got != nil {
		t.Errorf("foreign status line: %q", got)
	}
}

// TestRegisteredBinaryRecord: RecordedBinaryPaths reads every binary the
// registrars recorded, after a real registration, and nothing from a
// missing or malformed record.
func TestRegisteredBinaryRecord(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(home, "bin", "observer")
	reg, err := NewRegistry(Options{BinaryPath: bin, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("claude-code"); res.Error != nil {
		t.Fatal(res.Error)
	}
	if res := reg.RegisterClaudeCodeStatusline(); res.Error != nil {
		t.Fatal(res.Error)
	}
	if got := RecordedBinaryPaths(ChecksumsPathFor(home), os.ReadFile); !reflect.DeepEqual(got, []string{bin}) {
		t.Fatalf("recorded %q, want [%s]", got, bin)
	}
	if got := RecordedBinaryPaths(filepath.Join(home, "missing.json"), os.ReadFile); got != nil {
		t.Fatalf("missing record: %q", got)
	}
	bad := filepath.Join(home, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := RecordedBinaryPaths(bad, os.ReadFile); got != nil {
		t.Fatalf("malformed record: %q", got)
	}
}
