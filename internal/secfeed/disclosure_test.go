package secfeed

import (
	"strings"
	"testing"
	"time"
)

// TestDisclosureOlderVersionAsksAgain (spike CPP-0): the text gained a data
// class (the commit ids git submodules are pinned to), so a verified,
// signed accept of the previous version no longer counts and nothing is
// sent until the current text is accepted.
func TestDisclosureOlderVersionAsksAgain(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 7
	at := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	old, err := EncodeDisclosure(Disclosure{Version: DisclosureVersion - 1, ShownAt: at, Surface: "cli"}, key)
	if err != nil {
		t.Fatal(err)
	}
	d := DecodeDisclosure(old, key)
	if !d.Verified {
		t.Fatal("the older record must still verify (it is genuine, only out of date)")
	}
	if d.Shown() {
		t.Fatal("an accept of the previous text counts for the new one")
	}
	cur, err := EncodeDisclosure(Disclosure{Version: DisclosureVersion, ShownAt: at, Surface: "cli"}, key)
	if err != nil || !DecodeDisclosure(cur, key).Shown() {
		t.Fatalf("the current accept does not read shown: %v", err)
	}
}

// TestDisclosureNamesTheSubmoduleCommits: the individual-node text says
// what the submodule check sends and what it never sends; the managed text
// does not offer it (a managed node never sends a commit to a public host).
func TestDisclosureNamesTheSubmoduleCommits(t *testing.T) {
	for _, want := range []string{"commit ids", "git submodules", "never a submodule's URL, path or name", "observer security scan --online", "Also check online"} {
		if !strings.Contains(DisclosureText, want) {
			t.Errorf("the disclosure does not say %q", want)
		}
	}
	if strings.Contains(DisclosureTextManaged, "commit") {
		t.Error("the managed text names a commit check a managed node never runs")
	}
}
