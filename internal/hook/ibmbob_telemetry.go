package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IBM Bob's own telemetry to IBM, switched off per node (AP-135, DECIDED
// 2026-10-24: opt-in for an individual node, never a default). Bob's user
// setting is "telemetry.enabled" (a nested {"telemetry": {"enabled": ...}}
// in ~/.bob/settings/settings.json; the EnableTelemetry policy writes the
// same config path). This package already owns writes to that file (the
// ibm-bob hook writer), so this one setting is written here too, under the
// same lock and pinned target, splicing only the "telemetry" member.
//
// Grounding (bobshell 2.0.6 bundle, read 2026-10-24): initializeTelemetry
// hands EVERY telemetry client the one gate isEnabled: () =>
// runtime.getConfig().telemetry.enabled ?? true, and the client class's
// capture() / startSpan() / endSpan() return early when it is false. The
// "otel-external" client that exports to an OTEL_EXPORTER_OTLP_ENDPOINT or
// an OtelConfiguration endpoint is built by the same createTelemetryClient,
// so telemetry.enabled = false ALSO stops Bob's OTLP export to Observer.
// The only event exported regardless is the "Setting Changed" event for
// telemetry.enabled itself turning false (trackEventUnconditional). Hence
// the refusal below when this node's policy points that export at a
// receiver.

// IBMBobTelemetryResult is the outcome of one IBMBobVendorTelemetry call.
type IBMBobTelemetryResult struct {
	Target     string // ibm-bob or ibm-bob-windows
	ConfigPath string
	Changed    bool // the file was (or, on a dry run, would be) changed
	DryRun     bool
	// Skipped means nothing was written on purpose; Reason says why.
	Skipped bool
	Reason  string
	// Warnings are non-fatal notes (an OTLP endpoint in the environment,
	// a Windows policy the bridge cannot read).
	Warnings []string
	Error    error
}

// IBMBobVendorTelemetry turns Bob's own telemetry off (disable = true:
// telemetry.enabled = false) or hands the setting back to Bob's default
// (disable = false: removes a false telemetry.enabled Observer or the user
// set; a true or absent value is left alone). target is "ibm-bob" (this
// user's ~/.bob) or "ibm-bob-windows" (the Windows user's .bob seen from
// WSL).
//
// It refuses to disable when this host's Bob policy points Bob's OTLP
// export at a receiver (OtelConfiguration) and does not itself set
// EnableTelemetry: the user setting would silence that export too. When the
// policy sets EnableTelemetry, Bob ignores the user setting and nothing is
// written.
func (r *Registry) IBMBobVendorTelemetry(target string, disable bool) IBMBobTelemetryResult {
	res := IBMBobTelemetryResult{Target: target, DryRun: r.opts.DryRun}
	dir, done := r.ibmBobTelemetryDir(&res, disable)
	if done {
		return res
	}
	path := filepath.Join(dir, "settings", "settings.json")
	res.ConfigPath = path
	if disable && (target == "ibm-bob" && r.ibmBobTelemetryPolicyGate(&res)) {
		return res
	}
	if disable && r.opts.Getenv != nil {
		for _, k := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"} {
			if strings.TrimSpace(r.opts.Getenv(k)) != "" {
				res.Warnings = append(res.Warnings, k+" is set in this environment: if Bob exports its traces there, telemetry.enabled=false stops that export too (Bob gates every telemetry client on it)")
				break
			}
		}
	}

	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.IBMBobVendorTelemetry: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Errorf("hook.IBMBobVendorTelemetry: read: %w", err)
		return res
	}
	body, changed, err := ibmBobTelemetryEdit(path, raw, disable)
	if err != nil || !changed {
		res.Error = err
		return res
	}
	res.Changed = true
	if r.opts.DryRun {
		return res
	}
	if err := atomicWriteFileMode(pinned, body, fileModeOr(pinned.target, 0o644)); err != nil {
		res.Error = fmt.Errorf("hook.IBMBobVendorTelemetry: %w", err)
		return res
	}
	// The hooks integrity record of this file is a whole-file digest: keep
	// it current when the file carries Observer's hooks.
	if events, _ := ibmBobUserHookEventsAt(ibmBobHooksTarget(filepath.Dir(dir), "", ""), path); len(events) > 0 {
		if err := r.recordHookChecksum("ibm-bob", path); err != nil {
			res.Error = err
		}
	}
	return res
}

// ibmBobTelemetryDir resolves res.Target's .bob directory; done=true means
// res is final (skipped or an error).
func (r *Registry) ibmBobTelemetryDir(res *IBMBobTelemetryResult, disable bool) (dir string, done bool) {
	native := filepath.Join(r.opts.HomeDir, ".bob")
	switch res.Target {
	case "ibm-bob":
		return native, false
	case "ibm-bob-windows":
		t, _ := waveCrossOSFor("ibm-bob")
		// The host's own .bob is the native target's (with its policy
		// refusal), never the bridge's.
		if dir = r.detectWindowsWaveDir(t); dir == "" || filepath.Clean(dir) == filepath.Clean(native) {
			res.Skipped, res.Reason = true, "no Windows-side .bob detected"
			return "", true
		}
		if disable {
			res.Warnings = append(res.Warnings, "the Windows Bob policy (HKLM\\SOFTWARE\\Policies\\IBM\\Bob) is not read from WSL: if it carries OtelConfiguration without EnableTelemetry, this setting stops that export to Observer too")
		}
		return dir, false
	}
	res.Error = fmt.Errorf("hook.IBMBobVendorTelemetry: unknown target %q", res.Target)
	return "", true
}

// ibmBobTelemetryPolicyGate applies this host's Bob policy to a disable:
// true means res is final (the policy decides EnableTelemetry itself, or it
// exports through OtelConfiguration, which the user setting would silence).
func (r *Registry) ibmBobTelemetryPolicyGate(res *IBMBobTelemetryResult) bool {
	pol := ibmBobPolicyReader()
	switch {
	case pol.Found && pol.EnableTelemetry != nil:
		res.Skipped = true
		res.Reason = fmt.Sprintf("IBM Bob's administrator policy (%s) sets EnableTelemetry=%t, which overrides the user setting; nothing written", pol.Source, *pol.EnableTelemetry)
		return true
	case pol.Found && pol.OtelExport:
		res.Error = fmt.Errorf("hook.IBMBobVendorTelemetry: refusing: IBM Bob's administrator policy (%s) exports Bob's OTLP traces through OtelConfiguration, and Bob gates every telemetry client, that export included, on telemetry.enabled; turning it off would stop the export to Observer (ask the administrator to decide EnableTelemetry in the policy instead)", pol.Source)
		return true
	}
	return false
}

// ibmBobTelemetryEdit is the pure edit of settings.json's "telemetry"
// member: disable sets enabled=false, otherwise a false enabled is removed
// (an emptied member is dropped). It returns the new file body and whether
// anything changed; every other member keeps its bytes.
func ibmBobTelemetryEdit(path string, raw []byte, disable bool) ([]byte, bool, error) {
	fresh := len(bytes.TrimSpace(raw)) == 0
	if fresh && !disable {
		return nil, false, nil // nothing to hand back
	}
	top := map[string]json.RawMessage{}
	if !fresh {
		var err error
		if top, err = decodeSettingsObject(path, raw); err != nil {
			return nil, false, fmt.Errorf("hook.IBMBobVendorTelemetry: %w", err)
		}
	}
	tele, err := jsonObject(top["telemetry"])
	if err != nil {
		return nil, false, fmt.Errorf("hook.IBMBobVendorTelemetry: %s: \"telemetry\" is not an object", path)
	}
	var cur *bool
	if v, ok := tele["enabled"]; ok {
		var b bool
		if json.Unmarshal(v, &b) == nil {
			cur = &b
		}
	}
	switch {
	case disable && cur != nil && !*cur:
		return nil, false, nil // already off
	case disable:
		tele["enabled"] = json.RawMessage("false")
	case cur == nil || *cur:
		return nil, false, nil // on or Bob's default: leave it
	default:
		delete(tele, "enabled")
	}
	if len(tele) == 0 {
		delete(top, "telemetry")
	} else {
		b, err := json.Marshal(tele)
		if err != nil {
			return nil, false, fmt.Errorf("hook.IBMBobVendorTelemetry: %w", err)
		}
		top["telemetry"] = b
	}
	var body []byte
	if fresh {
		body, err = json.MarshalIndent(top, "", "  ")
		body = append(body, '\n')
	} else {
		body, err = spliceTopLevelJSON(raw, top)
	}
	if err != nil {
		return nil, false, fmt.Errorf("hook.IBMBobVendorTelemetry: %w", err)
	}
	return body, true, nil
}
