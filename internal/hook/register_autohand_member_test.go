package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const autohandSecret = "ah-SECRET-token"

func autohandRegistry(t *testing.T, home string) *Registry {
	t.Helper()
	reg, err := NewRegistry(Options{BinaryPath: "/usr/local/bin/observer", HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func autohandPath(home string) string { return filepath.Join(home, ".autohand", "config.json") }

func writeAutohand(t *testing.T, home, body string) {
	t.Helper()
	p := autohandPath(home)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAutohandHooksMemberOnly pins the D16 member-only read and write
// (FU-45): every member but hooks keeps its exact bytes, including a
// value Go's decoder would reshape (a 30-digit number, a unicode escape)
// and the planted credentials; a register then an unregister gives the file
// back byte for byte; the mode is kept.
func TestAutohandHooksMemberOnly(t *testing.T) {
	home := t.TempDir()
	orig := "{\n  \"provider\": \"openai\",\n  \"auth\": {\"token\": \"" + autohandSecret + "\"},\n" +
		"  \"api\": {\"companySecret\": \"" + autohandSecret + "\", \"big\": 123456789012345678901234567890, \"u\": \"\\u00e9\"}\n}\n"
	writeAutohand(t, home, orig)
	reg := autohandRegistry(t, home)
	res := reg.Register("autohand")
	if res.Error != nil || len(res.HooksAdded) == 0 {
		t.Fatalf("Register = %+v", res)
	}
	got, _ := os.ReadFile(autohandPath(home))
	for _, keep := range []string{`"auth": {"token": "` + autohandSecret + `"}`, `"big": 123456789012345678901234567890`, `"u": "\u00e9"`} {
		if !strings.Contains(string(got), keep) {
			t.Errorf("a non-hooks member changed bytes (want %s):\n%s", keep, got)
		}
	}
	if fi, _ := os.Stat(autohandPath(home)); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600 kept", fi.Mode().Perm())
	}
	if un := reg.Unregister("autohand"); un.Error != nil || len(un.HooksRemoved) == 0 {
		t.Fatalf("Unregister = %+v", un)
	}
	if back, _ := os.ReadFile(autohandPath(home)); string(back) != orig {
		t.Errorf("register then unregister is not byte-identical:\n%s", back)
	}
}

// TestAutohandRefusals: a duplicate top-level key and a non-object are
// refused without writing, and no error quotes the file (the FIFO case is
// register_autohand_fifo_unix_test.go).
func TestAutohandRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"duplicate key", `{"auth": {"token": "` + autohandSecret + `"}, "auth": {}}`, "duplicate top-level"},
		{"not an object", `["` + autohandSecret + `"]`, "not a JSON object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeAutohand(t, home, tc.body)
			res := autohandRegistry(t, home).Register("autohand")
			if res.Error == nil || !strings.Contains(res.Error.Error(), tc.want) || strings.Contains(res.Error.Error(), autohandSecret) {
				t.Fatalf("Register err = %v, want %q and no file contents", res.Error, tc.want)
			}
			if got, _ := os.ReadFile(autohandPath(home)); string(got) != tc.body {
				t.Error("a refusal wrote")
			}
		})
	}
}
