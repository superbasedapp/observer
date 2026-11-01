package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// IBM Bob administrator-policy hooks (AP-135 decision Q2, DECIDED
// 2026-10-24 by the operator; docs/plans/native-console-ibm-bob-instance-
// 2026-10-23.md). Bob Shell 2.0.6 reads one flat policy object from
// /etc/bob/policy.json (Linux), HKLM\Software\Policies\IBM\Bob (Windows) or
// the com.ibm.bob managed-preferences domain (macOS). Its EnforcedHooks
// policy is a JSON STRING holding Claude-shaped hook groups keyed by event;
// Bob runs those hooks IN ADDITION to the user's own and keeps running them
// when the user sets disableGlobalHooks (bundle: the WorkspaceHooksManager's
// getHooks merges _policyHooks with every user / workspace file).
//
// Two consequences live here, so the per-node writer and the managed
// generator cannot drift:
//
//   - IBMBobEnforcedHooks builds the EnforcedHooks value from the SAME
//     target and entry builder the per-node ibm-bob writer uses
//     (ibmBobHooksTarget + jsonHooksEntry): same events, commands and
//     timeouts.
//   - When the node's own policy already carries Observer's entries, the
//     per-node registration stands down (SkipCovered): a second copy in
//     ~/.bob/settings/settings.json would fire every event twice.
//
// Detection reads only what the OS policy channel exposes, and only
// Observer's own entries in it (ibmBobPolicyReader, per-OS files). The
// cross-OS ibm-bob-windows bridge does NOT detect a Windows policy: the
// registry cannot be read from WSL without running a Windows process, so a
// bridge registration under a fleet policy fires twice (documented in
// docs/ibmbob-adapter.md).

// IBMBobPolicyEnforcedHooks, IBMBobPolicyOtelConfiguration and
// IBMBobPolicyEnableTelemetry are the Bob policy names Observer reasons
// about (bundle: the policy definition table next to "PolicyTypes").
const (
	IBMBobPolicyEnforcedHooks     = "EnforcedHooks"
	IBMBobPolicyOtelConfiguration = "OtelConfiguration"
	IBMBobPolicyEnableTelemetry   = "EnableTelemetry"
)

// ibmBobPolicyEvents is the closed event set of Bob's hook schema (a
// strict object: one unknown event makes Bob ignore the whole value).
var ibmBobPolicyEvents = map[string]bool{
	"SessionStart": true, "UserPromptSubmit": true, "PreCompact": true, "PostCompact": true,
	"PreToolUse": true, "PostToolUse": true, "Stop": true,
}

// IBMBobHookEvents returns the events Observer registers for IBM Bob, in
// order (the registry row's bindings).
func IBMBobHookEvents() []string {
	return append([]string(nil), ibmBobHooksTarget("", "", "").events...)
}

// IBMBobEnforcedHooks returns Observer's Bob hook groups as the JSON event
// map the EnforcedHooks policy carries (compact, keys sorted). binary is the
// command a managed node runs: "" means a bare "observer", which /bin/sh and
// cmd.exe both resolve on PATH; an install path is quoted the way the
// per-node writer quotes it for that path's shape. The value carries no
// --config: a managed node's hook reads its default config.
func IBMBobEnforcedHooks(binary string) (string, error) {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		binary = "observer"
	}
	r := &Registry{opts: Options{BinaryPath: binary}}
	t := ibmBobHooksTarget("", "", "")
	m := make(map[string][]json.RawMessage, len(t.events))
	for _, ev := range t.events {
		e, err := r.jsonHooksEntry(t, ev)
		if err != nil {
			return "", fmt.Errorf("hook.IBMBobEnforcedHooks: %w", err)
		}
		m[ev] = []json.RawMessage{e}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("hook.IBMBobEnforcedHooks: %w", err)
	}
	return string(b), nil
}

// IBMBobPolicy is what one OS policy source of IBM Bob says, reduced to the
// three policies Observer reasons about. The zero value is "no policy".
type IBMBobPolicy struct {
	// Source names where it was read ("/etc/bob/policy.json",
	// `HKLM\SOFTWARE\Policies\IBM\Bob`, a managed-preferences plist).
	Source string
	// Found reports that the source exists.
	Found bool
	// Untrusted is non-empty when the source exists but Observer does not
	// rely on it: unreadable, not a JSON object, or a file a non-root user
	// could have written. An untrusted source never makes the per-node
	// registration stand down.
	Untrusted string
	// EnforcedHooks is the EnforcedHooks value when it is a string;
	// EnforcedHooksWrongType reports a value of another type (Bob ignores it).
	EnforcedHooks          *string
	EnforcedHooksWrongType bool
	// OtelExport reports an OtelConfiguration string naming an OTLP endpoint
	// (Bob ignores one without an endpoint).
	OtelExport bool
	// EnableTelemetry is the EnableTelemetry boolean when set.
	EnableTelemetry *bool
	// GatewayURL is the GatewayUrl string when set (surface-gap S-19): a
	// locked inference host that overrides BOB_GATEWAY_URL, so it decides
	// where Bob's traffic goes whatever a per-node route says.
	GatewayURL string
}

// ParseIBMBobPolicyDocument reads a Bob policy JSON object (policy.json, or
// a managed-preferences plist converted to JSON).
func ParseIBMBobPolicyDocument(source string, data []byte) IBMBobPolicy {
	p := IBMBobPolicy{Source: source, Found: true}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil || doc == nil {
		p.Untrusted = source + " is not a JSON object - Bob ignores it"
		return p
	}
	if raw, ok := doc[IBMBobPolicyEnforcedHooks]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			p.EnforcedHooks = &s
		} else {
			p.EnforcedHooksWrongType = true
		}
	}
	if raw, ok := doc[IBMBobPolicyOtelConfiguration]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			p.OtelExport = ibmBobOtelNamesEndpoint(s)
		}
	}
	if raw, ok := doc[IBMBobPolicyEnableTelemetry]; ok {
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			p.EnableTelemetry = &b
		}
	}
	if raw, ok := doc[IBMBobPolicyGatewayURL]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			p.GatewayURL = strings.TrimSpace(s)
		}
	}
	return p
}

// ibmBobOtelNamesEndpoint reports whether an OtelConfiguration value names an
// OTLP endpoint (Bob's own precondition for the policy to apply).
func ibmBobOtelNamesEndpoint(value string) bool {
	var m map[string]any
	if json.Unmarshal([]byte(value), &m) != nil {
		return false
	}
	for _, k := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"} {
		if s, _ := m[k].(string); strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

// IBMBobCoverage is how much of Observer's Bob wiring a policy carries.
type IBMBobCoverage struct {
	// Covered are the asked events whose Observer entry the policy carries;
	// Missing the ones it does not.
	Covered, Missing []string
	// Commands are the policy commands that cover Covered, in its order.
	Commands []string
	// Problem is non-empty when the EnforcedHooks value is not usable (Bob
	// ignores it too); Covered is then empty.
	Problem string
}

// Complete reports that every asked event rides the policy.
func (c IBMBobCoverage) Complete() bool {
	return c.Problem == "" && len(c.Covered) > 0 && len(c.Missing) == 0
}

// Coverage decides which of events the policy's EnforcedHooks carries an
// Observer entry for. A source with no EnforcedHooks covers nothing.
func (p IBMBobPolicy) Coverage(events []string) IBMBobCoverage {
	switch {
	case !p.Found:
		return IBMBobCoverage{Missing: append([]string(nil), events...)}
	case p.Untrusted != "":
		return IBMBobCoverage{Missing: append([]string(nil), events...), Problem: p.Untrusted}
	case p.EnforcedHooksWrongType:
		return IBMBobCoverage{Missing: append([]string(nil), events...), Problem: "EnforcedHooks is not a string - Bob ignores a policy of the wrong type"}
	case p.EnforcedHooks == nil:
		return IBMBobCoverage{Missing: append([]string(nil), events...)}
	}
	return IBMBobEnforcedCoverage(*p.EnforcedHooks, events)
}

// IBMBobEnforcedCoverage decides coverage from an EnforcedHooks value: an
// event is covered when an enabled command handler under it runs
// `observer hook ibm-bob <event>` (any observer binary path, the ownership
// rule the per-node writer uses). A value Bob's strict schema would reject
// covers nothing, since Bob then runs none of it.
func IBMBobEnforcedCoverage(value string, events []string) IBMBobCoverage {
	miss := func(problem string) IBMBobCoverage {
		return IBMBobCoverage{Missing: append([]string(nil), events...), Problem: problem}
	}
	if strings.TrimSpace(value) == "" {
		return miss("")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(value), &m); err != nil || m == nil {
		return miss("EnforcedHooks is not a JSON object - Bob ignores it")
	}
	byEvent := map[string][]ibmBobPolicyHandler{}
	for ev, raw := range m {
		if !ibmBobPolicyEvents[ev] {
			return miss(fmt.Sprintf("EnforcedHooks names event %q outside Bob's hook schema - Bob ignores the whole value", ev))
		}
		hs, problem := ibmBobPolicyGroups(ev, raw)
		if problem != "" {
			return miss(problem)
		}
		byEvent[ev] = hs
	}
	var c IBMBobCoverage
	for _, ev := range events {
		cmd := ""
		for _, h := range byEvent[ev] {
			if h.Type == "command" && !h.Disabled && observerHookEventInvocation(h.Command, "ibm-bob", ev) {
				cmd = h.Command
				break
			}
		}
		if cmd != "" {
			c.Covered = append(c.Covered, ev)
			c.Commands = append(c.Commands, cmd)
		} else {
			c.Missing = append(c.Missing, ev)
		}
	}
	return c
}

// ibmBobPolicyBinaryMissing returns the policy commands whose observer
// binary does not resolve for this process (a bare name on PATH, or a path
// that is not a runnable file). Bob runs the hook with its own PATH, so this
// is a warning, not a veto: a policy hook whose binary is missing fails and
// gates nothing.
func (r *Registry) ibmBobPolicyBinaryMissing(cmds []string) []string {
	works := r.opts.binaryWorks
	if works == nil {
		works = hookBinaryWorks
	}
	return ibmBobBinaryMissing(cmds, works)
}

// IBMBobPolicyBinaryMissing is ibmBobPolicyBinaryMissing for a reporter (the
// doctor): the covering commands whose observer binary does not resolve for
// this process.
func IBMBobPolicyBinaryMissing(cmds []string) []string {
	return ibmBobBinaryMissing(cmds, hookBinaryWorks)
}

func ibmBobBinaryMissing(cmds []string, works func(string) bool) []string {
	var out []string
	seen := map[string]bool{}
	add := func(bin string) {
		if !seen[bin] {
			seen[bin] = true
			out = append(out, bin)
		}
	}
	for _, cmd := range cmds {
		c, _ := trimBridgeExitTrailer(cmd)
		toks := stripHookCommandPrefix(splitCommandTokens(strings.ReplaceAll(c, `\`, "/")))
		if len(toks) == 0 || strings.Contains(strings.ToLower(c), "wsl.exe") || strings.HasPrefix(strings.TrimSpace(strings.ToLower(c)), "wsl ") {
			continue // a wsl.exe bridge runs a binary of another OS: not resolvable here
		}
		bin := toks[0]
		if !strings.ContainsAny(bin, `/\`) {
			p, err := exec.LookPath(bin)
			if err != nil {
				add(bin)
				continue
			}
			bin = p
		}
		if !works(bin) {
			add(bin)
		}
	}
	return out
}

// ibmBobPolicyHandler is one handler of a policy hook group.
type ibmBobPolicyHandler struct {
	Type     string
	Command  string
	Disabled bool
}

// ibmBobPolicyGroupKeys / ibmBobPolicyHandlerKeys are Bob's strict schema
// (bundle: the Bie group object and the command / http handler objects).
var (
	ibmBobPolicyGroupKeys   = map[string]bool{"matcher": true, "hooks": true}
	ibmBobPolicyHandlerKeys = map[string]map[string]bool{
		"command": {"type": true, "command": true, "timeout": true, "disabled": true},
		"http":    {"type": true, "url": true, "headers": true, "allowedEnvVars": true, "timeout": true, "disabled": true},
	}
)

// ibmBobPolicyGroups decodes one event's group list, checking the keys
// Bob's strict schema allows.
func ibmBobPolicyGroups(event string, raw json.RawMessage) ([]ibmBobPolicyHandler, string) {
	bad := fmt.Sprintf("EnforcedHooks %s does not match Bob's hook schema - Bob ignores the whole value", event)
	var groups []map[string]json.RawMessage
	if json.Unmarshal(raw, &groups) != nil {
		return nil, bad
	}
	var out []ibmBobPolicyHandler
	for _, g := range groups {
		for k := range g {
			if !ibmBobPolicyGroupKeys[k] {
				return nil, bad
			}
		}
		var handlers []map[string]json.RawMessage
		if json.Unmarshal(g["hooks"], &handlers) != nil || len(handlers) == 0 {
			return nil, bad
		}
		for _, h := range handlers {
			var typ, cmd string
			var disabled bool
			_ = json.Unmarshal(h["type"], &typ)
			allowed, ok := ibmBobPolicyHandlerKeys[typ]
			if !ok {
				return nil, bad
			}
			for k := range h {
				if !allowed[k] {
					return nil, bad
				}
			}
			if typ == "command" && (json.Unmarshal(h["command"], &cmd) != nil || cmd == "") {
				return nil, bad
			}
			if d, ok := h["disabled"]; ok && json.Unmarshal(d, &disabled) != nil {
				return nil, bad
			}
			out = append(out, ibmBobPolicyHandler{Type: typ, Command: cmd, Disabled: disabled})
		}
	}
	return out, ""
}

// observerHookEventInvocation is observerHookInvocation plus the event: the
// command's argv is `<observer binary> hook <tool> <event> ...` once env
// assignments and a wsl.exe bridge prefix are stripped.
func observerHookEventInvocation(cmd, tool, event string) bool {
	try := func(c string) bool {
		c, _ = trimBridgeExitTrailer(c)
		toks := stripHookCommandPrefix(splitCommandTokens(c))
		return len(toks) >= 4 && isObserverBinaryToken(toks[0]) && toks[1] == "hook" && toks[2] == tool && toks[3] == event
	}
	if try(cmd) {
		return true
	}
	return strings.Contains(cmd, `\`) && try(strings.ReplaceAll(cmd, `\`, "/"))
}

// ibmBobPolicyReader reads this host's Bob policy (per-OS: ibmbob_policy_
// unix.go / _windows.go / _other.go). A test binary never reads the host's
// policy: tests replace the reader, and the default returns "no policy" so
// a developer box with a Bob policy cannot change a test's outcome.
var ibmBobPolicyReader = func() IBMBobPolicy {
	if testing.Testing() {
		return IBMBobPolicy{}
	}
	return readIBMBobPolicyOS()
}

// ReadIBMBobPolicy returns this host's IBM Bob administrator policy as the
// per-node registration sees it (the zero value when none is deployed).
func ReadIBMBobPolicy() IBMBobPolicy { return ibmBobPolicyReader() }

// ibmBobPolicyStandDown applies the node's Bob policy to the native ibm-bob
// registration. done=true means res is final (the policy covers every event
// this pass would write: SkipCovered). Otherwise t.events may be narrowed to
// the events the policy does not carry, and warnings say why.
func (r *Registry) ibmBobPolicyStandDown(t *jsonHooksTarget) (res RegistrationResult, done bool, warnings []string) {
	pol := ibmBobPolicyReader()
	if !pol.Found || (pol.EnforcedHooks == nil && !pol.EnforcedHooksWrongType) {
		return res, false, nil
	}
	var want []string
	for _, ev := range t.events {
		if !r.skipEvent(t.tool, ev) {
			want = append(want, ev)
		}
	}
	cov := pol.Coverage(want)
	if cov.Problem != "" {
		return res, false, []string{fmt.Sprintf("IBM Bob's administrator policy (%s) carries EnforcedHooks, but %s; Observer registered its hooks per node, and if Bob does run the policy hooks every event fires twice", pol.Source, cov.Problem)}
	}
	if len(cov.Covered) == 0 {
		return res, false, nil
	}
	if r.opts.Force {
		return res, false, []string{fmt.Sprintf("IBM Bob's administrator policy (%s) EnforcedHooks already runs Observer's hooks for %s; --force registered them per node too, so those events fire twice", pol.Source, strings.Join(cov.Covered, ", "))}
	}
	if cov.Complete() {
		path := filepath.Join(t.dir, t.file)
		res = RegistrationResult{
			Tool: t.resultLabel(), ConfigPath: path, DryRun: r.opts.DryRun,
			Skipped: true, SkipKind: SkipCovered,
			SkipReason: fmt.Sprintf("IBM Bob's administrator policy (%s) EnforcedHooks already runs Observer's hooks for %s, and Bob runs policy hooks in addition to user hooks", pol.Source, strings.Join(cov.Covered, ", ")),
			SkipAdvice: "nothing written; the administrator policy provides it. Re-run with --force to register anyway (both fire, doubling every event).",
		}
		if left, _ := ibmBobUserHookEventsAt(*t, path); len(left) > 0 {
			res.SkipAdvice = fmt.Sprintf("nothing written, but %s still holds Observer's per-node entries for %s from an earlier registration, so those events fire twice; remove Observer's entries under \"hooks\" there (observer uninstall removes them)", path, strings.Join(left, ", "))
		}
		if missing := r.ibmBobPolicyBinaryMissing(cov.Commands); len(missing) > 0 {
			res.SkipAdvice += fmt.Sprintf(" Note: the policy's %s does not resolve to a runnable observer for this process; Bob runs it with its own PATH, and if it is missing there too the policy hooks fail and nothing gates (put observer on PATH, or regenerate with --hook-binary).", strings.Join(missing, ", "))
		}
		return res, true, nil
	}
	t.events = cov.Missing
	return res, false, []string{fmt.Sprintf("IBM Bob's administrator policy (%s) EnforcedHooks already runs Observer's hooks for %s; registered only %s per node", pol.Source, strings.Join(cov.Covered, ", "), strings.Join(cov.Missing, ", "))}
}

// IBMBobUserHookEvents returns the events under which ~/.bob/settings/
// settings.json (home is the user home) holds an Observer ibm-bob entry, in
// sorted order. A missing file is no events.
func IBMBobUserHookEvents(home string) ([]string, error) {
	t := ibmBobHooksTarget(home, "", "")
	return ibmBobUserHookEventsAt(t, filepath.Join(t.dir, t.file))
}

func ibmBobUserHookEventsAt(t jsonHooksTarget, path string) ([]string, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	_, _, eventMap, err := readJSONHooksFile(t, path)
	if err != nil {
		return nil, err
	}
	var out []string
	for ev, entries := range eventMap {
		for _, e := range entries {
			if jsonHooksEntryIsObservers(t, e) {
				out = append(out, ev)
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}
