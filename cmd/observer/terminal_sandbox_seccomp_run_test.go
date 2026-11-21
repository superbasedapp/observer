//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxseccomp"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestSeccompRunVocabularyNamesTheProfile: the run state that says
// Observer's filter was applied is the profile's own id, so the one value
// names the filter (tracker F-002).
func TestSeccompRunVocabularyNamesTheProfile(t *testing.T) {
	if string(vocab.SeccompRunObserverDefault) != string(sandboxseccomp.ProfileObserverDefault) {
		t.Fatalf("SeccompRunObserverDefault %q, profile %q", vocab.SeccompRunObserverDefault, sandboxseccomp.ProfileObserverDefault)
	}
	// Every profile has its SeccompRun value, equal to its id, and every
	// value but observer_default lifts PTRACE_SEIZE (lane ptrace).
	for _, id := range sandboxseccomp.Profiles() {
		run := vocab.SeccompRun(id)
		if !run.Valid() || !run.Applied() {
			t.Errorf("profile %s has no applied SeccompRun value", id)
		}
		_, lifts := sandboxseccomp.SeizeGroundOf(id)
		if run.LiftsSeize() != lifts {
			t.Errorf("profile %s: LiftsSeize %v, the profile lifts %v", id, run.LiftsSeize(), lifts)
		}
	}
	if len(sandboxseccomp.Profiles()) != 3 {
		t.Fatal("a new seccomp profile needs its own SeccompRun value")
	}
}

// stubYamaScope sets the host's Yama answer for one test.
func stubYamaScope(t *testing.T, scope int, known bool) {
	t.Helper()
	prev := readYamaScope
	readYamaScope = func() (int, bool) { return scope, known }
	t.Cleanup(func() { readYamaScope = prev })
}

// TestWithSeccompRunSeize: the strace opt-in (lane ptrace) records the seize
// profile of the ground that held (bwrap's own pid namespace whatever Yama
// says; process_lite only on Yama 1 or more), keeps observer_default with
// the reason on the note when no ground holds, and does nothing with the
// opt-in or the filter off.
func TestWithSeccompRunSeize(t *testing.T) {
	bwrap := []string{sandboxbackend.BackendBwrap}
	lite := []string{sandboxbackend.BackendProcessLite}
	for _, c := range []struct {
		name          string
		seccomp, opt  bool
		stack         []string
		scope         int
		known         bool
		want          string
		noteSaysBlock bool
	}{
		{"off: bwrap", true, false, bwrap, 0, true, "observer_default", false},
		{"off: process_lite", true, false, lite, 1, true, "observer_default", false},
		{"on, contained: bwrap, Yama 0", true, true, bwrap, 0, true, "observer_seize_pidns", false},
		{"on, contained: process_lite, Yama 1", true, true, lite, 1, true, "observer_seize_yama", false},
		{"on, not contained: process_lite, Yama 0", true, true, lite, 0, true, "observer_default", true},
		{"on, not contained: process_lite, no Yama", true, true, lite, 0, false, "observer_default", true},
		{"on, filter off: bwrap", false, true, bwrap, 1, true, "off", false},
	} {
		stubYamaScope(t, c.scope, c.known)
		r := &sandboxRuntime{cfg: config.TerminalSandboxConfig{Seccomp: c.seccomp, SeccompAllowSeize: c.opt}}
		res, err := r.withSeccompRun(termsvc.CreateResult{Note: "sandbox: x", Isolation: termrun.Isolation{Stack: c.stack}}, nil)
		if err != nil || res.Isolation.Seccomp != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, res.Isolation.Seccomp, err, c.want)
		}
		if blocked := strings.Contains(res.Note, "strace stays blocked"); blocked != c.noteSaysBlock {
			t.Errorf("%s: note %q", c.name, res.Note)
		}
		if got := sandboxCLISeizeRefusal(r.cfg, res.Isolation.Seccomp, c.stack); (got != "") != c.noteSaysBlock {
			t.Errorf("%s: CLI line %q", c.name, got)
		}
	}
}

// TestWithSeccompRun: the one stamping seam records the state from the
// stack's registry rows and the key, leaves a stackless run and a failed
// create alone (audit N2-A9: a key-on run on a row that loads no filter
// is named not_applicable, never silently unfiltered).
func TestWithSeccompRun(t *testing.T) {
	var noFilter string
	for _, id := range sandboxbackend.IDs() {
		if row, _ := sandboxbackend.Get(id); row.Iso.Seccomp == vocab.SeccompNone || row.Iso.Seccomp == "" {
			noFilter = id
			break
		}
	}
	if noFilter == "" {
		t.Fatal("no registry row without a filter to test with")
	}
	for _, c := range []struct {
		name  string
		keyOn bool
		stack []string
		err   error
		want  string
	}{
		{"bwrap, key on", true, []string{sandboxbackend.BackendBwrap}, nil, "observer_default"},
		{"bwrap, key off", false, []string{sandboxbackend.BackendBwrap}, nil, "off"},
		{"a row without a filter, key on", true, []string{noFilter}, nil, "not_applicable"},
		{"a row without a filter, key off", false, []string{noFilter}, nil, "none"},
		{"no stack", true, nil, nil, ""},
		{"an unknown id only", true, []string{"no-such-backend"}, nil, "not_applicable"},
		{"a failed create", true, []string{sandboxbackend.BackendBwrap}, errors.New("x"), ""},
	} {
		r := &sandboxRuntime{cfg: config.TerminalSandboxConfig{Seccomp: c.keyOn}}
		res, err := r.withSeccompRun(termsvc.CreateResult{Isolation: termrun.Isolation{Stack: c.stack}}, c.err)
		if !errors.Is(err, c.err) || res.Isolation.Seccomp != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, res.Isolation.Seccomp, err, c.want)
		}
	}
}

// TestSandboxCLISeccompLabel: the launch line says the key-on states and
// nothing else, so a key-off launch reads as before.
func TestSandboxCLISeccompLabel(t *testing.T) {
	for state, wantEmpty := range map[string]bool{
		"observer_default": false, "not_applicable": false,
		"observer_seize_pidns": false, "observer_seize_yama": false,
		"off": true, "none": true, "engine_default": true, "": true,
	} {
		if got := sandboxCLISeccompLabel(state); (got == "") != wantEmpty {
			t.Errorf("%q: label %q", state, got)
		}
	}
}
