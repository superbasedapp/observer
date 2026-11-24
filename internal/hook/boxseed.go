package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// boxseed.go renders the hook registration a hosted sandbox box gets (lane
// HOOKS, decision SBXD-6, ledger SBX-HOOK-1): the same user-scope settings
// file entries this machine's registration writes, for the agent tool, in
// the BOX's home, each command pointing at the in-box observer. It is pure:
// the caller reads the box's current file and writes the result back; no
// file on this machine is read or written here.
//
// Inside the box every `observer hook <tool> <event>` invocation goes over
// the run's capture relay to this machine, where guard decides
// (cmd/observer hook_relay.go boxHookRelay); a relay that cannot be reached
// blocks a gate event. Seeding the registration is what makes those
// invocations happen at all.
//
// Which tools are covered is a property of the registry row's hook
// MECHANISM (a row in boxHookRenderers), never of the tool's name: a
// settings file whose writer is pure enough to aim at another home. A tool
// whose mechanism has no row here is not covered, and the hosted
// disclosure says so for it.

// claudeCodeHookCommand is the command Claude Code's settings.json entry for
// event runs: the observer binary (quoted when it needs it), `hook
// claude-code`, the event's CLI spelling and configSuffix (" --config <path>"
// or ""). The local writer (registerClaudeCodeAt) and the box seed share it.
func claudeCodeHookCommand(binPath, event, configSuffix string) string {
	return shellQuoteIfNeeded(binPath) + " hook claude-code " + hookEventArg(event) + configSuffix
}

// genericSettingsHookCommand is the command a Claude-Code-shaped settings
// file's entry runs for tool's native event (registerGenericSettingsHooks:
// Gemini CLI, Qwen Code, Qoder): the binary, `hook <tool> <event>` and
// configSuffix.
func genericSettingsHookCommand(binPath, tool, event, configSuffix string) string {
	return shellQuoteIfNeeded(binPath) + " hook " + tool + " " + event + configSuffix
}

// boxHookRenderer is one covered mechanism: the agentconfig artifact of the
// user-scope file it writes, the events it registers for a row, the command
// of one event, and the matcher of Observer's group (the local writer's:
// "*" for Claude Code, none for the generic settings files).
type boxHookRenderer struct {
	artifact string
	events   func(c integration.Capability) []string
	command  func(binPath, tool, event string) string
	matcher  string
}

// boxHookRenderers is the closed set of mechanisms a box can be seeded for
// (one row each, TestBoxHookRenderersMatchTheLocalWriters). Not listed, on
// purpose: every mechanism whose local writer has side effects beyond one
// settings file (Codex's [features] switch and project trust, the plugin
// shims, the hook-file directories), and every file that is not a
// Claude-Code-shaped JSON settings document. Each stays disclosed as
// "no hook gating" until a row is added here.
var boxHookRenderers = map[integration.HookMechanism]boxHookRenderer{
	integration.HookClaudeSettings: {
		artifact: claudeSettingsArtifact,
		events:   func(integration.Capability) []string { return claudeCodeEvents },
		command:  func(bin, _, event string) string { return claudeCodeHookCommand(bin, event, "") },
		matcher:  "*",
	},
	integration.HookQwenSettings:   genericBoxRenderer("qwen-code/user-settings"),
	integration.HookGeminiSettings: genericBoxRenderer("gemini-cli/user-settings"),
	integration.HookQoderJSON:      genericBoxRenderer("qoder/user-settings"),
}

// genericBoxRenderer is the row of a registerGenericSettingsHooks file: the
// events the registry row registers (its Registered bindings, the same
// list the local writer reads with no component selection).
func genericBoxRenderer(artifact string) boxHookRenderer {
	return boxHookRenderer{
		artifact: artifact,
		events:   func(c integration.Capability) []string { return c.Hook.RegisteredEvents() },
		command: func(bin, tool, event string) string {
			return genericSettingsHookCommand(bin, tool, event, "")
		},
	}
}

// BoxHooksCover reports whether a hosted box can be seeded with c's hook
// registration so guard checks the agent's tool calls there: the row's
// mechanism has a box renderer, its writer is auto-wired and not switched
// off by a live check, and one of the events it registers is a wired gate
// (a tool or prompt gate guard acts on). False is the honest zero: the
// hosted disclosure then says no hook runs for the tool.
func BoxHooksCover(c integration.Capability) bool {
	rr, ok := boxHookRenderers[c.Hook.Mechanism]
	if !ok || !c.Hook.AutoWired || c.Hook.LiveGate.Waiting() {
		return false
	}
	if _, gated := LiveCheckGate(c.Tool); gated {
		return false
	}
	events := rr.events(c)
	for _, b := range c.Hook.Bindings {
		if b.Wired && b.Cap.IsGate() && slices.Contains(events, b.NativeEvent) {
			return true
		}
	}
	return false
}

// BoxHookInput is one box's registration to render.
type BoxHookInput struct {
	// Capability is the agent tool's registry row.
	Capability integration.Capability
	// Home is the box home (an absolute slash path).
	Home string
	// Binary is the in-box observer every command runs (an absolute slash
	// path).
	Binary string
	// Getenv reads the agent's environment in the box (a relocation
	// variable such as CLAUDE_CONFIG_DIR moves the file with it, and a
	// switch that turns hooks off is found); nil reads none.
	Getenv func(string) string
	// Existing is the box's current file; nil when the box has none.
	Existing []byte
	// SkipEvent, when set, names events not to write (the same filter
	// `observer start`'s automatic registration applies).
	SkipEvent func(tool, event string) bool
}

// BoxHookFile is the rendered file.
type BoxHookFile struct {
	// Path is the absolute box path of the file.
	Path string
	// Content is the whole file to write.
	Content []byte
	// Changed is false when Existing already holds exactly this
	// registration (nothing to write).
	Changed bool
	// Events are the native events registered, in write order.
	Events []string
}

// ErrBoxHooksNotCovered is returned for a row BoxHooksCover refuses.
var ErrBoxHooksNotCovered = errors.New("hook: the tool's hook mechanism cannot be seeded into a box")

// ErrBoxHooksSwitchedOff wraps the refusal of a box file whose own
// settings (or the agent's environment) turn the tool's hooks off: the
// registration would be written and never run.
var ErrBoxHooksSwitchedOff = errors.New("hook: the box turns the tool's hooks off")

// RenderBoxHooks renders the box's settings file with Observer's entries
// for every event the row's mechanism registers. It goes through the same
// raw round-trip as the local writers (hookentries.go, NEW-06): Observer's
// earlier entry for the tool (any observer binary) is refreshed where it
// sits (mergeObserverGroup), any further Observer handler on the event is
// dropped so a stale one never runs beside the current one, and every other
// key, event, group and handler keeps its data and its order; a new event
// is appended, and nothing is HTML-escaped. A hooks member that cannot be
// edited without guessing is refused. The file's encoding is the local
// writer's: a row whose settings file shares a credential file keeps the
// existing bytes of every other member (spliceTopLevelJSON), any other row
// the sorted rendering (encodeSettingsJSON).
func RenderBoxHooks(in BoxHookInput) (BoxHookFile, error) {
	c := in.Capability
	if !BoxHooksCover(c) {
		return BoxHookFile{}, ErrBoxHooksNotCovered
	}
	if !path.IsAbs(in.Home) || !path.IsAbs(in.Binary) {
		return BoxHookFile{}, errors.New("hook.RenderBoxHooks: the box home and binary must be absolute paths")
	}
	rr := boxHookRenderers[c.Hook.Mechanism]
	env := agentconfig.PathEnv{GOOS: "linux", Home: in.Home, Getenv: in.Getenv}
	got, err := agentconfig.ResolveArtifact(rr.artifact, env)
	if err != nil {
		return BoxHookFile{}, fmt.Errorf("hook.RenderBoxHooks: %w", err)
	}
	if got.Status != agentconfig.PathResolved {
		return BoxHookFile{}, fmt.Errorf("hook.RenderBoxHooks: %s has no path in the box (%s)", rr.artifact, got.Status)
	}
	out := BoxHookFile{Path: strings.ReplaceAll(got.Path, `\`, "/")}

	settings := map[string]json.RawMessage{}
	if len(in.Existing) > 0 {
		if settings, err = decodeSettingsObject(out.Path, in.Existing); err != nil {
			return BoxHookFile{}, fmt.Errorf("hook.RenderBoxHooks: %w", err)
		}
	}
	hooks, err := decodeHookEvents(settings["hooks"], groupedHookEntries)
	if err != nil {
		return BoxHookFile{}, refuseHookShape("hook.RenderBoxHooks", out.Path, err)
	}
	ours := func(cmd string) bool { return isObserverAnyHookEntry(cmd, c.Tool) }
	// T-847: Observer's entry in another shape than the one written here (a
	// narrowed matcher, an extra field) is never kept as current.
	shapeDrift := shapeDriftEvents(settings["hooks"], claudeShapedGroups(ours))
	for _, event := range rr.events(c) {
		if in.SkipEvent != nil && in.SkipEvent(c.Tool, event) {
			continue
		}
		if err := mergeObserverGroup(hooks, groupEntryRule{
			event: event, cmd: rr.command(in.Binary, c.Tool, event),
			matcher: rr.matcher, ours: ours, drift: shapeDrift[event],
		}); err != nil {
			return BoxHookFile{}, fmt.Errorf("hook.RenderBoxHooks: %s: %w", out.Path, err)
		}
		out.Events = append(out.Events, event)
	}
	if err := setHooksMember(settings, "hooks", hooks, false); err != nil {
		return BoxHookFile{}, fmt.Errorf("hook.RenderBoxHooks: %w", err)
	}
	if _, ok := settings["hooks"]; !ok {
		// Every event skipped on a file with no hooks member: still write
		// the (empty) member, as before.
		settings["hooks"] = json.RawMessage("{}")
	}
	if integration.HooksShareCredentialFile(c.Tool) {
		if out.Content, err = spliceTopLevelJSON(in.Existing, settings); err != nil {
			return BoxHookFile{}, fmt.Errorf("hook.RenderBoxHooks: %w", err)
		}
	} else {
		out.Content = encodeSettingsJSON(settings)
		if len(in.Existing) > 0 {
			out.Content = credfile.WithLineEnding(in.Existing, out.Content)
		}
	}
	out.Changed = len(in.Existing) == 0 || !credfile.SameJSON(in.Existing, out.Content)
	if why := boxHooksSwitchedOff(c.Tool, in, out); why != "" {
		return BoxHookFile{}, fmt.Errorf("%w: %s", ErrBoxHooksSwitchedOff, why)
	}
	return out, nil
}

// boxHooksSwitchedOff is the hook-off switch (hookdisable's table, the one
// owner) that the rendered file or the agent's environment sets for the
// tool, "" when none. Only the rendered file and the environment are read:
// a managed or project file in the box is not (a residual the hosted docs
// name).
func boxHooksSwitchedOff(tool string, in BoxHookInput, f BoxHookFile) string {
	env := agentconfig.PathEnv{GOOS: "linux", Home: in.Home, Getenv: in.Getenv}
	findings := hookdisable.Detect(hookdisable.Options{
		Home:   in.Home,
		Getenv: in.Getenv,
		UserFiles: func(id string) (string, bool) {
			got, err := agentconfig.ResolveArtifact(id, env)
			if err != nil || got.Status != agentconfig.PathResolved {
				return "", false
			}
			return got.Path, true
		},
		ReadFile: func(p string) ([]byte, error) {
			if strings.ReplaceAll(p, `\`, "/") == f.Path {
				return f.Content, nil
			}
			return nil, errors.New("not read in a box")
		},
	})
	for _, fd := range findings {
		if slices.Contains(fd.Tools, tool) {
			return fd.Key + " in " + fd.Path + ": " + fd.Effect
		}
	}
	return ""
}
