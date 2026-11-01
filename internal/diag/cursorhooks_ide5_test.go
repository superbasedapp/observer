package diag

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestCheckCursorHooksEnterpriseCovered pins IDE-5 in the doctor: events a
// trusted enterprise hooks.json runs are covered (the registrar stands them
// down), and an untrusted one is named and not relied on.
func TestCheckCursorHooksEnterpriseCovered(t *testing.T) {
	doc, path, err := hook.ManagedHooksDocument("cursor", "", "linux")
	if err != nil {
		t.Fatal(err)
	}
	full := hook.ParseManagedHooksDocument(path, doc)

	t.Run("enterprise only", func(t *testing.T) {
		home := t.TempDir()
		got := checkCursorHooksWith(home, home, full)
		if got.Status != StatusOK || !strings.Contains(strings.Join(got.Details, " "), "(enterprise): 18/18") {
			t.Errorf("got %v %q %v, want OK with the enterprise file counted", got.Status, got.Message, got.Details)
		}
	})
	t.Run("enterprise fills the user file's gap", func(t *testing.T) {
		home := t.TempDir()
		mustWriteFile(t, filepath.Join(home, ".cursor", "hooks.json"), cursorHooksFixture("stop", "/usr/bin/observer hook cursor stop"))
		var evs []string
		for _, ev := range hook.CursorEvents() {
			if ev != "stop" {
				evs = append(evs, `"`+ev+`":[{"command":"observer hook cursor `+ev+`"}]`)
			}
		}
		rest := hook.ParseManagedHooksDocument(path, []byte(`{"version":1,"hooks":{`+strings.Join(evs, ",")+`}}`))
		if got := checkCursorHooksWith(home, home, rest); got.Status != StatusOK {
			t.Errorf("got %v %q %v, want OK", got.Status, got.Message, got.Details)
		}
	})
	t.Run("a user entry the enterprise file also carries fires twice", func(t *testing.T) {
		home := t.TempDir()
		mustWriteFile(t, filepath.Join(home, ".cursor", "hooks.json"), cursorHooksFixture("stop", "/usr/bin/observer hook cursor stop"))
		got := checkCursorHooksWith(home, home, full)
		if got.Status != StatusWarn || !strings.Contains(got.Message, "twice") || !strings.Contains(strings.Join(got.Details, " "), ": stop") {
			t.Errorf("got %v %q %v, want a duplicate WARN naming stop", got.Status, got.Message, got.Details)
		}
	})
	t.Run("untrusted enterprise is not relied on", func(t *testing.T) {
		home := t.TempDir()
		mustWriteFile(t, filepath.Join(home, ".cursor", "hooks.json"), cursorHooksFixture("stop", "/usr/bin/observer hook cursor stop"))
		u := full
		u.Untrusted = path + " is writable by group or others"
		got := checkCursorHooksWith(home, home, u)
		if got.Status != StatusWarn || !strings.Contains(strings.Join(got.Details, " "), "not relied on") {
			t.Errorf("got %v %q %v, want WARN naming the untrusted file", got.Status, got.Message, got.Details)
		}
	})
}

// TestCheckCursorHooksUntrustedEnterpriseOnly pins the audit low item: an
// untrusted enterprise file with no user file is reported (with the
// untrusted detail), never "cursor not installed".
func TestCheckCursorHooksUntrustedEnterpriseOnly(t *testing.T) {
	doc, path, err := hook.ManagedHooksDocument("cursor", "", "linux")
	if err != nil {
		t.Fatal(err)
	}
	m := hook.ParseManagedHooksDocument(path, doc)
	m.Untrusted = path + " is writable by group or others"
	home := t.TempDir()
	got := checkCursorHooksWith(home, home, m)
	if got.Message == "cursor not installed" || got.Status != StatusWarn {
		t.Fatalf("got %v %q, want a WARN", got.Status, got.Message)
	}
	if !strings.Contains(strings.Join(got.Details, " "), "not relied on") {
		t.Errorf("details %v do not keep the untrusted reason", got.Details)
	}
}
