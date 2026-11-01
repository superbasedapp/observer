package hook

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// The Cline PostToolUse file hook of the security feedback (lane sec-h;
// security pillar plan section 5.11 (c), spike JSP-6): the SDK hook runtime
// runs ~/.cline/hooks/PostToolUse after a tool and sends its JSON reply's
// contextModification to the model as a <hook_context> user message.
// Observer writes it only while the binding's RegisterWhen component is
// selected (Options.Selected) and removes its own copy when it is not. The
// script execs `observer hook cline-cli PostToolUse`, whose reply is the
// feedback (or nothing).

// clineFeedbackEvent is the file hook's event (and file name).
const clineFeedbackEvent = "PostToolUse"

// clineFeedbackMarker is the second line of Observer's PostToolUse script.
const clineFeedbackMarker = "# superbased-observer: Cline PostToolUse security feedback (written only while security.feedback is selected; observer uninstall removes it)"

// clineFeedbackScript is the script for the observer command cmd.
func clineFeedbackScript(cmd string) []byte {
	return []byte("#!/usr/bin/env bash\n" + clineFeedbackMarker + "\nexec " + cmd + "\n")
}

// clineFeedbackIsObservers reports whether data is Observer's script.
func clineFeedbackIsObservers(data []byte) bool {
	lines := strings.Split(string(data), "\n")
	return len(lines) >= 3 && lines[1] == clineFeedbackMarker
}

// clineFeedbackComponent is the component that registers the Cline
// PostToolUse event ("" when the row has no such binding).
func clineFeedbackComponent() string {
	c, ok := integration.For(clineHookTool)
	if !ok {
		return ""
	}
	for _, b := range c.Hook.Bindings {
		if b.NativeEvent == clineFeedbackEvent && b.RegisterWhen != "" {
			return b.RegisterWhen
		}
	}
	return ""
}

// syncClineFeedback writes Observer's PostToolUse script while the
// component is selected and removes Observer's copy while it is not. A
// PostToolUse of the developer's own (any extension the SDK reads) is
// never touched: Observer then writes nothing. Reports the event as added
// when it wrote the script.
func (r *Registry) syncClineFeedback() RegistrationResult {
	res := RegistrationResult{Tool: clineHookTool, DryRun: r.opts.DryRun}
	comp := clineFeedbackComponent()
	if comp == "" || r.opts.Selected == nil {
		// No such binding, or no selection given (Options.Selected nil):
		// the opt-in file hook is left exactly as it is.
		return res
	}
	want := r.opts.Selected != nil && r.opts.Selected(comp) && !r.skipEvent(clineHookTool, clineFeedbackEvent)
	dir := r.clineHooksDir()
	path := filepath.Join(dir, clineFeedbackEvent)
	have, err := os.ReadFile(path)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		res.Error = fmt.Errorf("hook.registerCline: read %s: %w", path, err)
		return res
	}
	ours := !missing && clineFeedbackIsObservers(have)
	if !want {
		// Not selected: only a file Observer wrote is removed (nothing is
		// created, so an install that never selected the component sees
		// no change at all).
		if ours && !r.opts.DryRun {
			unlock, err := r.lockSettings(path)
			if err != nil {
				res.Error = fmt.Errorf("hook.registerCline: %w", err)
				return res
			}
			defer unlock()
			if err := r.removeClineScript(path, have); err != nil {
				res.Error = fmt.Errorf("hook.registerCline: %w", err)
			}
		}
		return res
	}
	for _, ext := range clineHookExtensions {
		if ext == "" {
			continue
		}
		if _, err := os.Stat(path + ext); err == nil {
			// The developer's own PostToolUse hook: leave it alone.
			return res
		}
	}
	if !missing && !ours {
		return res
	}
	cmd := shellQuoteIfNeeded(r.opts.BinaryPath) + " hook " + clineHookTool + " " + clineFeedbackEvent + r.configFlagSuffix()
	script := clineFeedbackScript(cmd)
	if ours && bytes.Equal(have, script) && clineHookExecutable(path) {
		res.AlreadySet = append(res.AlreadySet, clineFeedbackEvent)
		return res
	}
	res.HooksAdded = append(res.HooksAdded, clineFeedbackEvent)
	if r.opts.DryRun {
		return res
	}
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerCline: %w", err)
		return res
	}
	defer unlock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		res.Error = fmt.Errorf("hook.registerCline: %w", err)
		return res
	}
	pinned := pinWriteTarget(path)
	if err := atomicWriteFile(pinned, script); err != nil {
		res.Error = fmt.Errorf("hook.registerCline: write: %w", err)
		return res
	}
	if err := os.Chmod(pinned.target, 0o755); err != nil {
		res.Error = fmt.Errorf("hook.registerCline: chmod: %w", err)
		return res
	}
	if err := r.recordChecksum(res.Tool, path); err != nil {
		res.Error = err
	}
	return res
}

// unregisterClineFeedback removes Observer's PostToolUse script, if any.
func (r *Registry) unregisterClineFeedback(res *UnregistrationResult) {
	path := filepath.Join(r.clineHooksDir(), clineFeedbackEvent)
	have, err := os.ReadFile(path)
	if err != nil || !clineFeedbackIsObservers(have) {
		return
	}
	// FU-203: Observer's script running another binary is kept.
	if r.keepsForeignBinary(shapedHooksInText(have, clineHookTool)) {
		res.HooksKept = append(res.HooksKept, clineFeedbackEvent)
		noteKeptForeign(res, clineFeedbackEvent)
		return
	}
	res.HooksRemoved = append(res.HooksRemoved, clineFeedbackEvent)
	if r.opts.DryRun {
		return
	}
	if err := r.removeClineScript(path, have); err != nil && res.Error == nil {
		res.Error = fmt.Errorf("hook.unregisterCline: %w", err)
	}
}
