//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_cli_source.go is the CLI launch's workspace-source choice
// (F-L3R-1, decision log OB-103): the same closed set of sources the
// dashboard picker offers (internal/workspace Source, mapped onto a row's
// deliveries by workspace.DeliveryFor), chosen with --observer-sandbox-source
// (and --observer-sandbox-remote for clone-remote). Without the flag a row
// that can share the live tree keeps the live source, as before; a row that
// declares deliveries none of which carries the live tree takes the first
// source its first declared delivery can carry, and the launch says so. The
// choice reads the row's Deliveries capability, never a backend name.

// sandboxCLIValueFlags are the sandboxed launch's value flags beyond the
// profile: each is stripped from the inner launch's arguments.
var sandboxCLIValueFlags = []struct {
	name, hint string
	set        func(*sandboxCLIRequest, string)
}{
	{"--observer-sandbox-source", "a workspace source (live, clone-local, clone-remote or worktree)", func(r *sandboxCLIRequest, v string) { r.Source = v }},
	{"--observer-sandbox-remote", "the repository to clone (for --observer-sandbox-source clone-remote)", func(r *sandboxCLIRequest, v string) { r.Remote = v }},
}

// sandboxCLIValueFlag consumes one of sandboxCLIValueFlags at rest[i]:
// matched reports the argument is one, n how many further arguments it
// took (1 for a spaced value, 0 for name=value).
func sandboxCLIValueFlag(req *sandboxCLIRequest, rest []string, i int) (n int, matched bool, err error) {
	a := rest[i]
	for _, f := range sandboxCLIValueFlags {
		if v, ok := strings.CutPrefix(a, f.name+"="); ok {
			if v == "" {
				return 0, true, fmt.Errorf("%s needs %s", f.name, f.hint)
			}
			f.set(req, v)
			return 0, true, nil
		}
		if a != f.name {
			continue
		}
		if i+1 >= len(rest) || rest[i+1] == "" || rest[i+1][0] == '-' {
			return 0, true, fmt.Errorf("%s needs %s", f.name, f.hint)
		}
		f.set(req, rest[i+1])
		return 1, true, nil
	}
	return 0, false, nil
}

// sandboxCLICheckSource validates the flags: a source from the closed set,
// and a remote exactly when the source is clone-remote (the URL itself is
// checked against the effective host list at prepare, as on the dashboard).
func sandboxCLICheckSource(src, remote string) error {
	if src == "" {
		if remote != "" {
			return errors.New("--observer-sandbox-remote needs --observer-sandbox-source clone-remote")
		}
		return nil
	}
	parsed, err := workspace.ParseSource(src)
	if err != nil {
		return fmt.Errorf("--observer-sandbox-source: %w", err)
	}
	switch {
	case parsed == workspace.SourceCloneRemote && remote == "":
		return errors.New("--observer-sandbox-source clone-remote needs --observer-sandbox-remote <repository>")
	case parsed != workspace.SourceCloneRemote && remote != "":
		return errors.New("--observer-sandbox-remote needs --observer-sandbox-source clone-remote")
	}
	return nil
}

// sandboxCLIDefaultSources are the sources a launch may take without a
// flag, in preference order: each needs nothing beyond the current
// directory (clone-remote needs a repository and worktree an opt-in).
var sandboxCLIDefaultSources = []workspace.Source{workspace.SourceLive, workspace.SourceCloneLocal}

// sandboxCLIRowDeliveries is the backend row's declared deliveries (empty
// for a row that declares none: a local backend, or a hosted row that
// uploads the live tree).
func sandboxCLIRowDeliveries(backend string) []string {
	v, ok := sandboxremote.VendorFor(backend)
	if !ok {
		return nil
	}
	return v.Deliveries
}

// sandboxCLIWorkspaceSource resolves the launch's source. flag is the
// validated --observer-sandbox-source ("" when not given); deliveries the
// row's declared deliveries. note is the line the launch prints when the
// source was chosen for the user ("" when the flag chose it, or live).
func sandboxCLIWorkspaceSource(flag string, deliveries []string) (src workspace.Source, note string, err error) {
	if flag != "" {
		return workspace.Source(flag), "", nil
	}
	if len(deliveries) == 0 {
		return workspace.SourceLive, "", nil
	}
	modes := make([]workspace.Delivery, 0, len(deliveries))
	for _, d := range deliveries {
		modes = append(modes, workspace.Delivery(d))
	}
	if _, err := workspace.DeliveryFor(workspace.SourceLive, modes); err == nil {
		return workspace.SourceLive, "", nil
	}
	for _, d := range modes {
		for _, c := range sandboxCLIDefaultSources {
			if got, err := workspace.DeliveryFor(c, modes); err == nil && got == d {
				return c, fmt.Sprintf("workspace source %s (this backend cannot share the live tree; its first delivery, %s, carries a %s workspace; choose another with --observer-sandbox-source)", c, d, c), nil
			}
		}
	}
	return "", "", fmt.Errorf("this backend offers no workspace source that needs no choice (its deliveries: %s); pass --observer-sandbox-source clone-remote --observer-sandbox-remote <repository>", strings.Join(deliveries, ", "))
}
