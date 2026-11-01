package psparse

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want []string // nil: refused
	}{
		{`C:\o\observer.exe hook codex PreToolUse`, []string{`C:\o\observer.exe`, "hook", "codex", "PreToolUse"}},
		{`& 'C:\Users\First Last\observer.exe' hook codex Stop --config 'C:\Users\First Last\c.toml'`, []string{`C:\Users\First Last\observer.exe`, "hook", "codex", "Stop", "--config", `C:\Users\First Last\c.toml`}},
		{`& 'C:\Users\O''Brien\o.exe' hook`, []string{`C:\Users\O'Brien\o.exe`, "hook"}},
		{`& 'C:\a $b ` + "`" + `c;d&e%f\o.exe' x`, []string{`C:\a $b ` + "`" + `c;d&e%f\o.exe`, "x"}},
		{`wsl.exe -d Ubuntu-20.04 -- /home/u/observer hook codex PreToolUse`, []string{"wsl.exe", "-d", "Ubuntu-20.04", "--", "/home/u/observer", "hook", "codex", "PreToolUse"}},
		{`wsl.exe -d D -- "/home/u/my tools/observer" hook`, []string{"wsl.exe", "-d", "D", "--", "/home/u/my tools/observer", "hook"}},
		{`C:/x/observer.exe hook-bridge --distro D --bin //home/u/o --tool codex --event PreToolUse`, []string{"C:/x/observer.exe", "hook-bridge", "--distro", "D", "--bin", "//home/u/o", "--tool", "codex", "--event", "PreToolUse"}},
		{`C:\a%b\o.exe x`, []string{`C:\a%b\o.exe`, "x"}},
		// Refused.
		{`"C:\Program Files\o.exe" hook codex PreToolUse`, nil},
		{`'C:\Program Files\o.exe' hook`, nil},
		{`C:\a$b\o.exe hook`, nil},
		{`C:\a;b\o.exe hook`, nil},
		{"C:\\a`b\\o.exe hook", nil},
		{`C:\a&b\o.exe hook`, nil},
		{`o.exe --config "C:\a$b\c.toml"`, nil},
		{`o.exe 'unterminated`, nil},
		{`o.exe 'a'b`, nil},
		{"& 'C:\\O\u2019Brien\\o.exe' x", nil},
		{``, nil},
	} {
		got, err := Parse(tc.cmd)
		if tc.want == nil {
			if err == nil {
				t.Errorf("Parse(%q) = %q, want a refusal", tc.cmd, got)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Parse(%q) = %q, %v, want %q", tc.cmd, got, err, tc.want)
		}
	}
}
