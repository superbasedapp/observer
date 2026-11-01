package secgithooks

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		Reason:    "internal/secgithooks edits hook text only",
	})
}

var pre = Hooks[0]

func TestInstallRemoveIsByteExact(t *testing.T) {
	t.Parallel()
	block := Block(pre, "/opt/observer's bin/observer")
	cases := []struct {
		name, existing string
	}{
		{"new file", ""},
		{"existing shell hook", "#!/bin/sh\nnpm test\n"},
		{"env bash, no trailing newline", "#!/usr/bin/env bash\nset -e\nmake lint"},
		{"shebang only, no newline", "#!/bin/zsh"},
		{"CRLF hook", "#!/bin/sh\r\necho hi\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Install(c.existing, block)
			if err != nil {
				t.Fatal(err)
			}
			if !Has(got) || !strings.HasPrefix(got, "#!") {
				t.Fatalf("installed: %q", got)
			}
			if again, _ := Install(got, block); again != got {
				t.Fatal("a second install changed the hook")
			}
			back, empty := Remove(got)
			if c.existing == "" {
				if !empty {
					t.Fatalf("a hook Observer created is not reported empty: %q", back)
				}
				return
			}
			if back != c.existing && !(c.existing == "#!/bin/zsh" && back == "#!/bin/zsh\n") {
				t.Fatalf("removal is not byte-exact:\n got %q\nwant %q", back, c.existing)
			}
			if empty && c.existing != "#!/bin/zsh" {
				t.Fatal("a developer's hook reported empty")
			}
		})
	}
}

func TestInstallRefusesNonShellHooks(t *testing.T) {
	t.Parallel()
	for _, existing := range []string{"#!/usr/bin/env python3\nprint(1)\n", "\x7fELF\x02\x01", "echo no shebang\n", "#!/usr/bin/env node\n"} {
		if _, err := Install(existing, Block(pre, "/o")); err == nil {
			t.Errorf("%q: edited", existing)
		}
	}
}

func TestBlockIsAdvisoryAndQuoted(t *testing.T) {
	t.Parallel()
	b := Block(Hooks[1], "/a b/it's/observer")
	for _, want := range []string{
		`sbo_obs='/a b/it'"'"'s/observer'`, `if [ -x "$sbo_obs" ]`,
		// git's stdin saved, fed to the check and restored (lane sec-gate2).
		`cat >"$sbo_in"`, `"$sbo_obs" security prepush "$@" <"$sbo_in" || sbo_rc=$?`, `exec <"$sbo_in"`,
		// Only the dedicated refusal status stops the hook.
		`if [ "$sbo_rc" -eq 43 ]; then exit 1; fi`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("block lacks %q:\n%s", want, b)
		}
	}
	pc := Block(Hooks[0], "/o")
	if !strings.Contains(pc, `"$sbo_obs" security precommit "$@" || sbo_rc=$?`) || strings.Contains(pc, "sbo_in") {
		t.Errorf("pre-commit block:\n%s", pc)
	}
	if strings.Contains(b+pc, "&& exit") {
		t.Error("a trailing `[ ] && exit` leaves status 1 when the check passes, failing a hook that is only the block")
	}
}

// TestInstallReplacesAnOlderBlock (lane sec-gate2): a block an earlier
// release wrote is replaced in place, the developer's lines kept, and the
// removal stays byte-exact.
func TestInstallReplacesAnOlderBlock(t *testing.T) {
	t.Parallel()
	old := beginMarker + "\nsbo_obs='/o'\nif [ -x \"$sbo_obs\" ]; then\n  \"$sbo_obs\" security precommit \"$@\"\n  [ $? -eq 1 ] && exit 1\nfi\n" + endMarker + "\n"
	existing := "#!/bin/sh\n" + old + "npm test\n"
	block := Block(pre, "/o")
	got, err := Install(existing, block)
	if err != nil {
		t.Fatal(err)
	}
	if want := "#!/bin/sh\n" + block + "npm test\n"; got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if back, _ := Remove(got); back != "#!/bin/sh\nnpm test\n" {
		t.Fatalf("removal: %q", back)
	}
}

func TestRemoveLeavesForeignTextAlone(t *testing.T) {
	t.Parallel()
	if out, empty := Remove("#!/bin/sh\necho hi\n"); out != "#!/bin/sh\necho hi\n" || empty {
		t.Fatalf("%q %v", out, empty)
	}
	half := "#!/bin/sh\n" + beginMarker + "\necho\n"
	if out, _ := Remove(half); out != half {
		t.Fatal("a block without its end marker was cut")
	}
}

func TestHooksDirRefusal(t *testing.T) {
	t.Parallel()
	root := filepath.FromSlash("/w/repo")
	gitDir := filepath.Join(root, ".git")
	cases := []struct {
		dir  string
		want bool
	}{
		{filepath.Join(gitDir, "hooks"), false},
		{filepath.Join(root, ".githooks"), false},
		{filepath.FromSlash("/w/repo2/hooks"), true},
		{filepath.FromSlash("/home/u/.config/git/hooks"), true},
		{"relative/hooks", true},
	}
	for _, c := range cases {
		if got := HooksDirRefusal(c.dir, root, gitDir) != ""; got != c.want {
			t.Errorf("%s: refused %v, want %v", c.dir, got, c.want)
		}
	}
}

// TestCurrentSeesAnOlderBlockAsOutdated (lane sec-gate3 milestone 2d): the
// previous release's block (exit 1 refuses, so observer's generic error
// blocks, and `sh -e` aborts; or a quoted path edited by hand) is not
// current; this release's block is, for any observer path, also after an
// install replaced the older one.
func TestCurrentSeesAnOlderBlockAsOutdated(t *testing.T) {
	t.Parallel()
	old := beginMarker + "\nsbo_obs='/o'\nif [ -x \"$sbo_obs\" ]; then\n  \"$sbo_obs\" security precommit \"$@\"\n  [ $? -eq 1 ] && exit 1\nfi\n" + endMarker + "\n"
	existing := "#!/bin/sh\n" + old + "npm test\n"
	if !Has(existing) || Current(existing, pre) {
		t.Fatal("an older block reads as current")
	}
	for _, path := range []string{"/o", "/home/u/.local/bin/observer", "/opt/it's here/observer"} {
		block := Block(pre, path)
		got, err := Install(existing, block)
		if err != nil {
			t.Fatal(err)
		}
		if !Current(got, pre) {
			t.Fatalf("this release's block for %q is not current:\n%s", path, got)
		}
		if Current(got, Hooks[1]) {
			t.Fatalf("a pre-commit block reads as the current pre-push block")
		}
		edited := strings.Replace(got, "-eq 43", "-eq 1", 1)
		if Current(edited, pre) {
			t.Fatal("a hand-edited block reads as current")
		}
	}
	if Current("#!/bin/sh\nnpm test\n", pre) {
		t.Fatal("a hook without the block reads as current")
	}
}

// TestPrepushHold (lane sec-gate4 milestone 1d), one case per shape: a
// held commit the push sends to a remote that lacks it refuses; one the
// remote has, one the push does not send, or one git cannot place does
// not; a URL target has no held commit on it.
func TestPrepushHold(t *testing.T) {
	a, b := "a"+strings.Repeat("0", 39), "b"+strings.Repeat("0", 39)
	held := []HeldCommit{{Commit: a, Remotes: []string{"origin"}}, {Commit: b}}
	all := func(string) (bool, bool) { return true, true }
	for _, tc := range []struct {
		name   string
		remote string
		held   []HeldCommit
		sends  Sends
		want   string
		refuse bool
	}{
		{"no held commit", "origin", nil, all, "", false},
		{"origin has a, b is sent", "origin", held, all, b, true},
		{"a is on origin only", "origin", held[:1], all, "", false},
		{"backup lacks a", "backup", held[:1], all, a, true},
		{"a URL has nothing", "https://example.invalid/r.git", held[:1], all, a, true},
		{"not sent", "backup", held, func(string) (bool, bool) { return false, true }, "", false},
		{"git cannot answer", "backup", held, func(string) (bool, bool) { return false, false }, "", false},
		{"no ancestry check", "backup", held, nil, "", false},
	} {
		got, refuse := PrepushHold(tc.remote, tc.held, false, tc.sends)
		if got != tc.want || refuse != tc.refuse {
			t.Errorf("%s: %q %v, want %q %v", tc.name, got, refuse, tc.want, tc.refuse)
		}
	}
	// Audit finding 8: a capped list refuses a push no listed commit
	// refuses, because the commits past the cap cannot be proven.
	if got, refuse := PrepushHold("origin", held[:1], true, all); got != "" || !refuse {
		t.Fatalf("capped list: %q %v, want refused for the unlisted commits", got, refuse)
	}
	if got, refuse := PrepushHold("backup", held[:1], true, all); got != a || !refuse {
		t.Fatalf("capped list, a listed commit sent: %q %v, want %s", got, refuse, a)
	}
	if line := HeldRefusalLine("", "origin"); !strings.Contains(line, "more unpushed commits add a secret") || !strings.Contains(line, "remote origin") {
		t.Fatalf("capped line %q", line)
	}
	if line := HeldRefusalLine(a, "backup"); !strings.Contains(line, "commit a00000000000 adds a secret that is not on remote backup yet") {
		t.Fatalf("line %q", line)
	}
}
