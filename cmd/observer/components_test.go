package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// TestComponentsVerbsExist pins every CLI verb the catalog attributes to a
// node component to a real top-level command, and the catalog's own verb.
func TestComponentsVerbsExist(t *testing.T) {
	root := newRootCmd()
	have := map[string]bool{}
	for _, c := range root.Commands() {
		have[c.Name()] = true
	}
	if !have["components"] {
		t.Fatal("`observer components` is not registered")
	}
	for _, c := range components.ForBinary(components.BinaryNode) {
		for _, v := range c.Verbs {
			if !have[v] {
				t.Errorf("%s: verb %q is not a top-level command", c.ID, v)
			}
		}
	}
}

func runComponents(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newComponentsCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String() + errb.String(), err
}

func TestComponentsListAndShow(t *testing.T) {
	out, err := runComponents(t, "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"codeintel", "adapter.claude-code", "org.client", "installed but inert (L2)"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output lacks %q", want)
		}
	}
	if strings.Contains(out, "org.saml") {
		t.Error("server rows appear without --all")
	}
	if strings.ContainsAny(out, "\u2013\u2014") {
		t.Error("list output contains an em or en dash")
	}

	out, err = runComponents(t, "list", "--json", "--class", "adapter")
	if err != nil {
		t.Fatal(err)
	}
	var rep components.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("list --json: %v\n%s", err, out)
	}
	if len(rep.Components) != 55 {
		t.Errorf("--class adapter = %d rows, want 55", len(rep.Components))
	}

	out, err = runComponents(t, "list", "--distro", "minimal")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "codeintel ") {
		t.Error("--distro minimal lists codeintel, which minimal compiles out")
	}

	out, err = runComponents(t, "show", "capture.proxy")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"127.0.0.1:8820", "github.com/klauspost/compress", "Target:"} {
		if !strings.Contains(out, want) {
			t.Errorf("show capture.proxy lacks %q:\n%s", want, out)
		}
	}
	// analytics gained the hand-run metrics and summarize verbs (T-674),
	// so the empty-surface example is compression.shell.
	out, err = runComponents(t, "show", "compression.shell")
	if err != nil || !strings.Contains(out, "no listener, no outbound host") {
		t.Errorf("show compression.shell must state an empty surface plainly:\n%s", out)
	}
	if out, err = runComponents(t, "show", "artifact.browser-extension"); err != nil || !strings.Contains(out, "browser_extension") {
		t.Errorf("show artifact: %v\n%s", err, out)
	}
}

func TestComponentsShowUnknownExitCode(t *testing.T) {
	out, err := runComponents(t, "show", "nope")
	var ec exitErr
	if !errors.As(err, &ec) || int(ec) != componentsUnknownExit {
		t.Fatalf("unknown id: err = %v, want exit code %d", err, componentsUnknownExit)
	}
	if !strings.Contains(out, "nope is not a known component") {
		t.Errorf("unknown id message missing:\n%s", out)
	}
}

func TestComponentsBadFilters(t *testing.T) {
	if _, err := runComponents(t, "list", "--class", "bogus"); err == nil {
		t.Error("an unknown class must be refused")
	}
	if _, err := runComponents(t, "list", "--distro", "bogus"); err == nil {
		t.Error("an unknown distro must be refused")
	}
}
