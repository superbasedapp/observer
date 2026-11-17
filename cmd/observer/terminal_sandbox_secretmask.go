//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_secretmask.go is the exec-side half of the opt-in
// workspace secret mask (security assessments depth plan, decision D32, gap
// G4c): the real folder listing the pure planner (internal/sandbox
// secretmask.go) is handed, the registry check that refuses a backend that
// cannot mask, and the flattening of the planner's report into the plain
// outcome termsvc returns to the caller. Which files are secret, the bounds,
// and every limit of the mask (a file created after the launch is not masked,
// a secret-named symlink is reported, an over-limit tree is reported, never
// silently partial) live in the pure package and docs/sandboxed-terminals.md.

// osSecretMaskReadDir is the sandbox.MaskDirReader of a real launch. It
// classifies each entry WITHOUT following links (os.DirEntry.Type is the
// directory entry's own type, lstat'd when the file system does not give
// one), reads at most max entries (it asks for max+1 to learn whether the
// folder holds more), and refuses a folder that is itself a symbolic link.
func osSecretMaskReadDir(dir string, max int) ([]sandbox.MaskDirEntry, bool, error) {
	if fi, err := os.Lstat(dir); err != nil {
		return nil, false, err
	} else if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, false, fmt.Errorf("%s is a symbolic link", dir)
	}
	f, err := os.Open(dir) //nolint:gosec // G304: a folder of the workspace being masked, lstat'd above; read-only listing
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	ents, err := f.ReadDir(max + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	more := len(ents) > max
	if more {
		ents = ents[:max]
	}
	out := make([]sandbox.MaskDirEntry, 0, len(ents))
	for _, e := range ents {
		out = append(out, sandbox.MaskDirEntry{Name: e.Name(), Kind: secretMaskKind(e.Type())})
	}
	return out, more, nil
}

// secretMaskKind maps a directory entry's type bits to the planner's kinds;
// anything that is not a link, a folder or a regular file (a socket, a FIFO,
// a device) is MaskEntryOther.
func secretMaskKind(t fs.FileMode) sandbox.MaskEntryKind {
	switch {
	case t&fs.ModeSymlink != 0:
		return sandbox.MaskEntrySymlink
	case t.IsDir():
		return sandbox.MaskEntryDir
	case t.IsRegular():
		return sandbox.MaskEntryFile
	}
	return sandbox.MaskEntryOther
}

// sandboxSecretMaskOption is the plan option of one bwrap launch: nil (the
// plan is exactly what it always was) unless the launch asked for the mask.
func sandboxSecretMaskOption(asked bool) *sandbox.SecretMaskOption {
	if !asked {
		return nil
	}
	return &sandbox.SecretMaskOption{ReadDir: osSecretMaskReadDir}
}

// secretMaskRefusal refuses a launch that asks for the workspace secret mask
// on a backend whose registry row cannot build it: running the launch with
// the secrets visible while the caller believes them hidden would be the
// silent failure the option exists to prevent. A caller that wants a
// fallback checks Capability.CanMaskWorkspaceSecrets first and warns
// instead of asking.
func secretMaskRefusal(backend string) error {
	row, ok := sandboxbackend.Get(backend)
	if ok && row.CanMaskWorkspaceSecrets() {
		return nil
	}
	return fmt.Errorf("terminal_sandbox: the %q sandbox cannot hide workspace secret files; "+
		"launch without the workspace secret mask (and warn that the workspace's .env and key files are visible), or choose bubblewrap", backend)
}

// secretMaskOutcome flattens the planner's report into termsvc's plain
// outcome; nil for a plan that did not ask for the mask.
func secretMaskOutcome(rep sandbox.SecretMaskReport) *termsvc.SecretMaskOutcome {
	if !rep.Enabled {
		return nil
	}
	out := &termsvc.SecretMaskOutcome{Masked: len(rep.Masked), Complete: rep.Complete(), GapsDropped: rep.GapsDropped}
	for _, g := range rep.Gaps {
		out.Gaps = append(out.Gaps, termsvc.SecretMaskGap{Path: g.Path, Reason: string(g.Reason)})
	}
	return out
}

// logSecretMask says on the daemon's log that a launch's mask is incomplete
// (counts and the first reason only: the full list is in the outcome the
// caller gets).
func (r *sandboxRuntime) logSecretMask(runID string, o *termsvc.SecretMaskOutcome) {
	if r.logger == nil || o == nil || o.Complete {
		return
	}
	first := ""
	if len(o.Gaps) > 0 {
		first = o.Gaps[0].Reason
	}
	r.logger.Warn("terminal sandbox: the workspace secret mask is incomplete; some secret files may be readable in the box",
		"run", runID, "masked", o.Masked, "gaps", len(o.Gaps)+o.GapsDropped, "first_reason", first)
}
