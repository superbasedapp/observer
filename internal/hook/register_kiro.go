package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// Kiro CLI hook registration (guard-enforcement fix gfiD, 2026-10-15;
// integration.HookKiroAgentJSON). Kiro CLI 2.x reads hooks ONLY from the
// "hooks" object of the agent in use: `--agent <name>`, else
// chat.defaultAgent in ~/.kiro/settings/cli.json, else the built-in
// kiro_default (which has no file). Live on demo node 1 (kiro-cli 2.28.0,
// probe hooks, offline mock model): a custom agent made the default fired
// its hooks; a standalone ~/.kiro/hooks/*.json was NOT read. So the writer:
//
//  1. writes Observer's own agent, ~/.kiro/agents/superbased-observer.json
//     ({name, description, tools: ["*"], includeMcpJson: true, hooks}; never
//     allowedTools, which would pre-approve every tool; includeMcpJson keeps
//     the user's own mcp.json servers visible in the default agent);
//  2. sets chat.defaultAgent to it ONLY when no default is set (a developer
//     who chose a default keeps it);
//  3. merges the same entries, keyed on the command string, into every
//     other global agent JSON, beside the user's own hooks (the agent a
//     developer picks with --agent or chat.defaultAgent is gated too);
//  4. writes the CLI V3 standalone ~/.kiro/hooks/superbased-observer.json
//     (PascalCase triggers, the documented current format) for forward
//     compatibility: 2.28 does not read it.
//
// Every write is marked (the observer `hook kiro-cli` command) and undone by
// Unregister: Observer's entries leave every agent, its own agent file and
// V3 file go, and chat.defaultAgent is cleared only when it still names
// Observer's agent. KIRO_HOME relocates ~/.kiro (the vendor's override)
// only when Kiro itself accepts the value (kiroHome).

// kiroAgentName is Observer's own agent (file stem and "name").
const kiroAgentName = "superbased-observer"

// kiroDefaultAgentKey is the cli.json setting naming the default agent. The
// file is a flat map of dotted keys (the `kiro-cli settings <key> <value>`
// store); a nested {"chat":{"defaultAgent"}} is also read as "set".
const kiroDefaultAgentKey = "chat.defaultAgent"

// kiroHookTimeoutMS is the timeout_ms Observer writes on an agent entry
// (internal/integration hookKiroHostTimeout).
const kiroHookTimeoutMS = 30000

// kiroV3TimeoutSeconds is the V3 standalone hook "timeout" (seconds).
const kiroV3TimeoutSeconds = 30

// kiroToolMatcherEvents are the events whose entries carry a tool matcher.
var kiroToolMatcherEvents = map[string]bool{"preToolUse": true}

// kiroAgentEvents are the 2.x camelCase events Observer registers: the
// registry row's Registered bindings.
func kiroAgentEvents() []string { return eventsOr("kiro-cli", "preToolUse", "userPromptSubmit") }

// kiroHomeArtifact is the catalogued Kiro row whose directory sits directly
// under the Kiro home (~/.kiro/hooks/), so its parent is the home.
const kiroHomeArtifact = "kiro-cli/user-hooks"

// kiroHome is the Kiro state directory: $KIRO_HOME when Kiro itself would
// accept it, else ~/.kiro. The rule is agentconfig's KIRO_HOME relocation
// (RelocAbsoluteNotHomeAncestor, RelativeFallsThrough): Kiro takes only an
// absolute path that is not the filesystem root, the home directory or an
// ancestor of the home directory, and otherwise falls back to ~/.kiro
// (kiro.dev/docs/configuration; surface-gap S-11 / S-17, FU-5). Writing to a
// value Kiro refuses would put Observer's agent and hooks where Kiro never
// reads them, or (for the root or the home itself) spray agents/, hooks/ and
// settings/ across a directory the user owns.
func (r *Registry) kiroHome() string {
	if d, err := r.artifactDir(kiroHomeArtifact); err == nil {
		return filepath.Dir(d)
	}
	return filepath.Join(r.opts.HomeDir, ".kiro")
}

// kiroHomeIgnored returns the set KIRO_HOME value when Kiro refuses it
// ("" when it is unset or accepted), for the registration warning.
func (r *Registry) kiroHomeIgnored() string {
	if r.opts.Getenv == nil {
		return ""
	}
	raw := strings.TrimSpace(r.opts.Getenv("KIRO_HOME"))
	if raw == "" {
		return ""
	}
	got, err := agentconfig.ResolveArtifact(kiroHomeArtifact, r.artifactEnv())
	if err != nil || got.RelocatedBy == "KIRO_HOME" {
		return ""
	}
	return raw
}

// kiroAgentHandler is Observer's entry in an agent JSON "hooks" list.
func kiroAgentHandler(event, cmd string) map[string]any {
	h := map[string]any{"command": cmd, "timeout_ms": kiroHookTimeoutMS}
	if kiroToolMatcherEvents[event] {
		h["matcher"] = "*"
	}
	return h
}

// kiroAgentTarget is one agent JSON as a jsonHooksTarget. own marks
// Observer's own agent file (dedicated: deleted once it holds no hook).
func (r *Registry) kiroAgentTarget(file string, own bool) jsonHooksTarget {
	t := jsonHooksTarget{
		tool: "kiro-cli", dir: filepath.Join(r.kiroHome(), "agents"), file: file,
		eventsPath: []string{"hooks"}, events: kiroAgentEvents(),
		eventHandler: kiroAgentHandler, commandKey: "command",
		coexist: true, errPrefix: "hook.registerKiroCLI",
	}
	if own {
		t.dedicated = true
		t.settings = []jsonSetting{
			{path: []string{"name"}, value: kiroAgentName},
			{path: []string{"description"}, value: "SuperBased Observer guard: the default Kiro agent with Observer's hooks (every tool available; remove with observer uninstall)"},
			{path: []string{"tools"}, value: []string{"*"}},
			// An agent sees the global ~/.kiro/settings/mcp.json and the
			// workspace .kiro/settings/mcp.json servers only with
			// includeMcpJson: true (kiro.dev/docs/custom-agents/
			// configuration-reference). Observer's agent becomes the default
			// when none is set, so without it the user's own MCP servers
			// would vanish from every default session (surface-gap S-11;
			// the omitted default is undocumented, live check 30). Ensured on
			// every register, so an agent written before this lands is
			// upgraded in place.
			{path: []string{"includeMcpJson"}, value: true},
		}
	}
	return t
}

// kiroUserAgentFiles lists the other global agent JSON files (sorted file
// names, Observer's own excluded).
func (r *Registry) kiroUserAgentFiles() []string {
	entries, err := os.ReadDir(filepath.Join(r.kiroHome(), "agents"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || name == kiroAgentName+".json" {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// registerKiroCLI installs Observer's Kiro hooks (see the file comment).
func (r *Registry) registerKiroCLI() RegistrationResult {
	res := r.registerJSONHooks(r.kiroAgentTarget(kiroAgentName+".json", true))
	if res.Error != nil {
		return res
	}
	var skipped, foreign []string
	for _, f := range r.kiroUserAgentFiles() {
		sub := r.registerJSONHooks(r.kiroAgentTarget(f, false))
		if sub.Error != nil {
			// A user agent holding an entry in Observer's shape that runs
			// another binary is kept for that reason (FU-192, FU-208); one
			// this writer cannot read as a 2.x agent JSON (malformed, or a
			// V3 hooks array) is left untouched as before.
			if isForeignBinaryRefusal(sub.Error) {
				foreign = append(foreign, "kiro-cli: left untouched "+f+": "+sub.Error.Error())
			} else {
				skipped = append(skipped, f)
			}
			continue
		}
		mergeKiroEvents(&res, sub)
	}
	var warnings []string
	if res.ProbeWarning != "" {
		warnings = append(warnings, res.ProbeWarning)
	}
	if raw := r.kiroHomeIgnored(); raw != "" {
		warnings = append(warnings, "kiro-cli: KIRO_HOME="+raw+" ignored (Kiro accepts only an absolute path that is not the root, the home directory or an ancestor of it); wrote under "+r.kiroHome())
	}
	if len(skipped) > 0 {
		warnings = append(warnings, "kiro-cli: left untouched (not a 2.x agent JSON with a hooks object): "+strings.Join(skipped, ", "))
	}
	warnings = append(warnings, foreign...)
	res.ProbeWarning = strings.Join(warnings, "; ")
	if err := r.ensureKiroDefaultAgent(); err != nil {
		res.Error = err
		return res
	}
	v3 := r.registerKiroV3Hooks()
	mergeKiroEvents(&res, v3)
	if v3.Error != nil {
		res.Error = v3.Error
	}
	return res
}

// mergeKiroEvents folds sub's events into res: an event added anywhere is
// added, never also reported as already set.
func mergeKiroEvents(res *RegistrationResult, sub RegistrationResult) {
	added := map[string]bool{}
	for _, e := range res.HooksAdded {
		added[e] = true
	}
	for _, e := range sub.HooksAdded {
		if !added[e] {
			res.HooksAdded = append(res.HooksAdded, e)
			added[e] = true
		}
	}
	kept := res.AlreadySet[:0]
	for _, e := range res.AlreadySet {
		if !added[e] {
			kept = append(kept, e)
		}
	}
	res.AlreadySet = kept
}

// unregisterKiroCLI removes everything registerKiroCLI wrote.
func (r *Registry) unregisterKiroCLI() UnregistrationResult {
	res := r.unregisterJSONHooks(r.kiroAgentTarget(kiroAgentName+".json", true))
	ownKept := len(res.HooksKeptForeign) > 0
	if ownKept {
		res.HooksKeptForeignIn = append(res.HooksKeptForeignIn, KeptForeignFile{Path: res.ConfigPath, Events: slices.Clone(res.HooksKeptForeign)})
	}
	for _, f := range r.kiroUserAgentFiles() {
		sub := r.unregisterJSONHooks(r.kiroAgentTarget(f, false))
		if sub.Error != nil {
			continue
		}
		res.HooksRemoved = appendNew(res.HooksRemoved, sub.HooksRemoved...)
		// FU-213: an entry in Observer's shape running another binary in
		// one of the user's own agent files is kept (FU-203) and reported
		// with that file named.
		if len(sub.HooksKeptForeign) > 0 {
			noteKeptForeign(&res, sub.HooksKeptForeign...)
			res.HooksKeptForeignIn = append(res.HooksKeptForeignIn, KeptForeignFile{Path: sub.ConfigPath, Events: slices.Clone(sub.HooksKeptForeign)})
		}
	}
	v3 := r.unregisterKiroV3Hooks()
	res.HooksRemoved = appendNew(res.HooksRemoved, v3.HooksRemoved...)
	if res.Error == nil && v3.Error != nil {
		res.Error = v3.Error
	}
	// Observer's own agent kept because its entries run another binary
	// (FU-203) stays the default agent: clearing the pointer would switch
	// that program's hooks off. A user agent's kept entry does not depend
	// on the pointer.
	if ownKept {
		return res
	}
	if err := r.clearKiroDefaultAgent(); err != nil && res.Error == nil {
		res.Error = err
	}
	return res
}

// appendNew appends each of vs not already in list.
func appendNew(list []string, vs ...string) []string {
	for _, v := range vs {
		found := false
		for _, have := range list {
			if have == v {
				found = true
				break
			}
		}
		if !found {
			list = append(list, v)
		}
	}
	return list
}

// kiroSettingsPath is ~/.kiro/settings/cli.json.
func (r *Registry) kiroSettingsPath() string {
	return filepath.Join(r.kiroHome(), "settings", "cli.json")
}

// kiroDefaultAgent returns the configured default agent ("" when unset),
// reading the flat dotted key or a nested chat.defaultAgent.
func kiroDefaultAgent(top map[string]json.RawMessage) string {
	var s string
	if raw, ok := top[kiroDefaultAgentKey]; ok && json.Unmarshal(raw, &s) == nil && strings.TrimSpace(s) != "" {
		return s
	}
	if raw, ok := lookupJSONPath(top, []string{"chat", "defaultAgent"}); ok && json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	return ""
}

// readKiroSettings reads cli.json under the caller's lock.
func readKiroSettings(path string) (map[string]json.RawMessage, []byte, error) {
	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("hook.registerKiroCLI: read settings: %w", err)
	}
	top := map[string]json.RawMessage{}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if top, err = decodeSettingsObject(path, raw); err != nil {
			return nil, nil, fmt.Errorf("hook.registerKiroCLI: %w", err)
		}
	}
	return top, raw, nil
}

// ensureKiroDefaultAgent makes Observer's agent the default when (and only
// when) no default agent is configured.
func (r *Registry) ensureKiroDefaultAgent() error {
	path := r.kiroSettingsPath()
	unlock, err := r.lockSettings(path)
	if err != nil {
		return fmt.Errorf("hook.registerKiroCLI: %w", err)
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	top, _, err := readKiroSettings(path)
	if err != nil {
		return err
	}
	if kiroDefaultAgent(top) != "" || r.opts.DryRun {
		return nil
	}
	b, _ := json.Marshal(kiroAgentName)
	top[kiroDefaultAgentKey] = b
	return writeJSONIndented(filepath.Dir(path), pinned, top)
}

// clearKiroDefaultAgent removes chat.defaultAgent when it still names
// Observer's agent (the flat key; a nested spelling Observer never wrote is
// left alone).
func (r *Registry) clearKiroDefaultAgent() error {
	path := r.kiroSettingsPath()
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	unlock, err := r.lockSettings(path)
	if err != nil {
		return fmt.Errorf("hook.unregisterKiroCLI: %w", err)
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	top, _, err := readKiroSettings(path)
	if err != nil {
		return err
	}
	var s string
	if raw, ok := top[kiroDefaultAgentKey]; !ok || json.Unmarshal(raw, &s) != nil || s != kiroAgentName {
		return nil
	}
	if r.opts.DryRun {
		return nil
	}
	delete(top, kiroDefaultAgentKey)
	return writeJSONIndented(filepath.Dir(path), pinned, top)
}

// kiroV3File is the CLI V3 standalone hooks file shape.
type kiroV3File struct {
	Version string            `json:"version"`
	Hooks   []json.RawMessage `json:"hooks"`
}

// kiroV3Hook is one V3 hook definition Observer writes.
type kiroV3Hook struct {
	Name    string       `json:"name"`
	Trigger string       `json:"trigger"`
	Matcher string       `json:"matcher,omitempty"`
	Action  kiroV3Action `json:"action"`
	Timeout int          `json:"timeout"`
}

// kiroV3Action is a V3 command action.
type kiroV3Action struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// kiroV3Path is ~/.kiro/hooks/superbased-observer.json.
func (r *Registry) kiroV3Path() string {
	return filepath.Join(r.kiroHome(), "hooks", kiroAgentName+".json")
}

// kiroV3IsObservers reports whether a V3 hook entry runs an observer
// `hook kiro-cli` command.
func kiroV3IsObservers(raw json.RawMessage) bool {
	var h struct {
		Action struct {
			Command string `json:"command"`
		} `json:"action"`
	}
	return json.Unmarshal(raw, &h) == nil && isObserverAnyHookEntry(h.Action.Command, "kiro-cli")
}

// kiroV3Hooks renders Observer's V3 hook definitions, one per registered
// event, with the PascalCase trigger (also the argv event the receiver
// folds back onto the binding).
func (r *Registry) kiroV3Hooks() ([]json.RawMessage, []string, error) {
	t := r.kiroAgentTarget(kiroAgentName+".json", true)
	var out []json.RawMessage
	var events []string
	for _, ev := range t.events {
		if r.skipEvent("kiro-cli", ev) {
			continue
		}
		trigger := strings.ToUpper(ev[:1]) + ev[1:]
		h := kiroV3Hook{
			Name: kiroAgentName + " " + trigger, Trigger: trigger,
			Action:  kiroV3Action{Type: "command", Command: r.jsonHooksCommand(t, trigger)},
			Timeout: kiroV3TimeoutSeconds,
		}
		if kiroToolMatcherEvents[ev] {
			h.Matcher = "*"
		}
		b, err := json.Marshal(h)
		if err != nil {
			return nil, nil, fmt.Errorf("hook.registerKiroCLI: marshal: %w", err)
		}
		out = append(out, b)
		events = append(events, ev)
	}
	return out, events, nil
}

// readKiroV3 reads the V3 file under the caller's lock.
func readKiroV3(path string) (kiroV3File, []byte, error) {
	raw, err := readSettingsFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return kiroV3File{}, nil, fmt.Errorf("hook.registerKiroCLI: read v3 hooks: %w", err)
	}
	f := kiroV3File{Version: "v1"}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &f); err != nil {
			return kiroV3File{}, nil, fmt.Errorf("hook.registerKiroCLI: parse %s: %w", path, err)
		}
	}
	return f, raw, nil
}

// registerKiroV3Hooks writes Observer's V3 standalone hooks file, keeping
// any definition in it that is not Observer's.
func (r *Registry) registerKiroV3Hooks() RegistrationResult {
	path := r.kiroV3Path()
	res := RegistrationResult{Tool: "kiro-cli", ConfigPath: path, DryRun: r.opts.DryRun}
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.registerKiroCLI: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	f, raw, err := readKiroV3(path)
	if err != nil {
		res.Error = err
		return res
	}
	// FU-192: an entry in Observer's shape running another binary is kept
	// (the V3 file is Observer's own by name).
	if r.refusesForeignBinary(&res, "hook.registerKiroCLI", path, identityOwnedName, shapedHooksInText(raw, "kiro-cli")) {
		return res
	}
	want, events, err := r.kiroV3Hooks()
	if err != nil {
		res.Error = err
		return res
	}
	var mine, foreign []json.RawMessage
	for _, h := range f.Hooks {
		if kiroV3IsObservers(h) {
			mine = append(mine, h)
		} else {
			foreign = append(foreign, h)
		}
	}
	if f.Version == "v1" && kiroHooksEqual(mine, want) {
		res.AlreadySet = events
		return res
	}
	res.HooksAdded = events
	if r.opts.DryRun {
		return res
	}
	out, err := json.MarshalIndent(kiroV3File{Version: "v1", Hooks: append(foreign, want...)}, "", "  ")
	if err != nil {
		res.Error = fmt.Errorf("hook.registerKiroCLI: marshal: %w", err)
		return res
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		res.Error = fmt.Errorf("hook.registerKiroCLI: mkdir: %w", err)
		return res
	}
	if err := atomicWriteFile(pinned, append(out, '\n')); err != nil {
		res.Error = fmt.Errorf("hook.registerKiroCLI: write: %w", err)
		return res
	}
	if err := r.recordHookChecksum("kiro-cli", path); err != nil {
		res.Error = err
	}
	return res
}

// kiroHooksEqual compares two hook lists semantically, in order.
func kiroHooksEqual(a, b []json.RawMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !jsonEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

// unregisterKiroV3Hooks removes Observer's definitions from the V3 file,
// deleting the file once it holds none.
func (r *Registry) unregisterKiroV3Hooks() UnregistrationResult {
	path := r.kiroV3Path()
	res := UnregistrationResult{Tool: "kiro-cli", ConfigPath: path, DryRun: r.opts.DryRun}
	if _, err := os.Stat(path); err != nil {
		res.Skipped = true
		return res
	}
	unlock, err := r.lockSettings(path)
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterKiroCLI: %w", err)
		return res
	}
	defer unlock()
	pinned := pinWriteTarget(path)
	f, raw, err := readKiroV3(path)
	if err != nil {
		res.Error = err
		return res
	}
	var kept []json.RawMessage
	for _, h := range f.Hooks {
		if kiroV3IsObservers(h) {
			var t struct {
				Trigger string `json:"trigger"`
			}
			_ = json.Unmarshal(h, &t)
			if t.Trigger != "" {
				res.HooksRemoved = appendNew(res.HooksRemoved, strings.ToLower(t.Trigger[:1])+t.Trigger[1:])
			}
			continue
		}
		kept = append(kept, h)
	}
	if len(res.HooksRemoved) == 0 || r.opts.DryRun {
		return res
	}
	if len(kept) == 0 {
		if err := removeEmptyConfigFile(path, raw); err != nil {
			res.Error = fmt.Errorf("hook.unregisterKiroCLI: %w", err)
			return res
		}
		_ = r.removeChecksum(path)
		return res
	}
	out, err := json.MarshalIndent(kiroV3File{Version: f.Version, Hooks: kept}, "", "  ")
	if err != nil {
		res.Error = fmt.Errorf("hook.unregisterKiroCLI: marshal: %w", err)
		return res
	}
	if err := atomicWriteFile(pinned, append(out, '\n')); err != nil {
		res.Error = fmt.Errorf("hook.unregisterKiroCLI: write: %w", err)
		return res
	}
	if err := r.removeChecksum(path); err != nil {
		res.Error = err
	}
	return res
}
