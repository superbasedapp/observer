//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_hosted_guardhooks_linux.go seeds guard's hook
// registration into a hosted box (lane HOOKS, decision SBXD-6): when the
// plan says guard_hooks resolved on, the agent tool's user-scope settings
// file in the BOX home gets Observer's entries (hook.RenderBoxHooks, the
// local writer's own pieces), each command running the in-box observer.
// Every in-box `observer hook <tool> <event>` then goes over the run's
// relay to this machine, where guard decides, and a relay that cannot be
// reached blocks a gate event (hook_relay.go relayFailure). Nothing on this
// machine is read or written here: the box's file is read and written
// through the vendor's exec.
//
// A seed that fails leaves the run refused before the agent starts
// (guardHooksErr, read by runBox): the person was told guard checks the
// agent's commands in the box, so the agent never runs unchecked instead.

// hostedBoxHookReadCap bounds the box settings file read for the merge.
const hostedBoxHookReadCap = 1 << 20

// hostedBoxHookArgMax is the largest file written through an exec argument;
// a larger one (a box file that already held a lot) goes through the
// vendor's file write.
const hostedBoxHookArgMax = 96 << 10

// hostedReadBoxFileScript prints a box file: exit 3 when there is none,
// exit 4 when the path is not a regular file (a link is never followed).
// Argument: the file.
const hostedReadBoxFileScript = `[ -e "$1" ] || [ -L "$1" ] || exit 3; { [ -f "$1" ] && [ ! -L "$1" ]; } || exit 4; cat -- "$1"`

// hostedWriteBoxHookScript writes a box file owner-only through a temporary
// file and a rename, making its directory. Arguments: the file, its content.
const hostedWriteBoxHookScript = `umask 077; d=$(dirname -- "$1") && mkdir -p -- "$d" && printf '%s' "$2" > "$1.observer-tmp" && mv -f -- "$1.observer-tmp" "$1"`

// The read script's exit codes.
const (
	hostedBoxFileAbsent  = 3
	hostedBoxFileNotFile = 4
)

// seedBoxHooks seeds the box when the plan says so; a failure is said and
// kept for runBox, which refuses the run.
func (r *hostedRun) seedBoxHooks(ctx context.Context) {
	if !r.plan.GuardHooks {
		return
	}
	events, err := r.writeBoxHooks(ctx)
	if err != nil {
		r.guardHooksErr = hostedPlainFailure(
			"Observer could not set up its hooks for "+integration.DisplayName(r.plan.Tool)+" in the box, so the agent did not start: this machine's guard would not have checked its commands there. To run without them, set \"Guard in the box\" to Never in Terminals > Settings > Hosted sandboxes.",
			fmt.Sprintf("guard_hooks: seed: %v", sandboxremote.Redact(err.Error(), r.cred.Secrets())),
		)
		return
	}
	r.rlog().line("guard's hooks are set up in the box for %d events", events)
}

// writeBoxHooks reads the box's settings file, renders the registration and
// writes it back when it changed; it returns the number of events.
func (r *hostedRun) writeBoxHooks(ctx context.Context) (int, error) {
	capab, ok := integration.For(r.plan.Tool)
	if !ok {
		return 0, hook.ErrBoxHooksNotCovered
	}
	env := r.agentEnv()
	in := hook.BoxHookInput{
		Capability: capab, Home: r.layout.Home, Binary: r.layout.Binary,
		Getenv: func(k string) string { return env[k] }, SkipEvent: autoRegisterSkipEvent,
	}
	// The path first (no file read), then the box's own file at that path.
	probe, err := hook.RenderBoxHooks(in)
	if err != nil {
		return 0, err
	}
	cur, err := r.readBoxFile(ctx, probe.Path)
	if err != nil {
		return 0, err
	}
	in.Existing = cur
	f, err := hook.RenderBoxHooks(in)
	if err != nil {
		return 0, err
	}
	if !f.Changed {
		return len(f.Events), nil
	}
	if len(f.Content) <= hostedBoxHookArgMax {
		return len(f.Events), r.execOK(ctx, "set up guard's hooks in the box", sandboxremote.ExecSpec{Argv: []string{"sh", "-c", hostedWriteBoxHookScript, "sh", f.Path, string(f.Content)}})
	}
	up := sandboxremote.UploadFile{Path: f.Path, Mode: 0o600, Size: int64(len(f.Content)), Open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(f.Content)), nil
	}}
	return len(f.Events), r.writeFiles(ctx, []sandboxremote.UploadFile{up})
}

// readBoxFile reads a box file (nil when there is none), capped.
func (r *hostedRun) readBoxFile(ctx context.Context, p string) ([]byte, error) {
	out, code, err := hostedExecOutput(ctx, r.client, r.rec.VendorID, []string{"sh", "-c", hostedReadBoxFileScript, "sh", p}, r.boxEnv(), hostedBoxHookReadCap)
	switch {
	case err != nil:
		return nil, fmt.Errorf("read %s in the box: %w", p, err)
	case code == hostedBoxFileAbsent:
		return nil, nil
	case code == hostedBoxFileNotFile:
		return nil, errors.New(p + " in the box is not a regular file")
	case code != 0:
		return nil, fmt.Errorf("read %s in the box: exit %d", p, code)
	}
	return out, nil
}
