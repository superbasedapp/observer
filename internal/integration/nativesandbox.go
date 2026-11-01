package integration

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// nativesandbox.go is the agent-native sandbox side table (sandbox plan v2
// section 4.4, phase P1a; the otlpExports precedent): per tool, what the
// agent's OWN sandbox is (Claude Code's /sandbox, Codex's modes, Copilot
// CLI's), what it needs from the layer around it, and the switch that turns
// it off. internal/sandboxselect's nesting rows N11 to N14 judge it against
// the layer Observer builds; the cmd layer reduces a row to the selector's
// NativeSandbox at the boundary, so no selection code names a tool.
//
// Honesty rule: every row is the plan's analysis (Grounding
// NativeGroundingAnalysis) until the Linux probe matrix runs it live; a tool
// with no row has no native sandbox Observer knows of.

// NativeSandboxNeed is one thing an agent's sandbox needs from the layer
// around it.
type NativeSandboxNeed string

// The closed NativeSandboxNeed vocabulary.
const (
	// NeedFreshProc: it mounts a fresh /proc (nesting row N11).
	NeedFreshProc NativeSandboxNeed = "fresh_proc"
	// NeedDevNetTUN: it needs /dev/net/tun and slirp4netns (N12).
	NeedDevNetTUN NativeSandboxNeed = "dev_net_tun"
	// NeedNestedUserns: it creates user namespaces.
	NeedNestedUserns NativeSandboxNeed = "nested_userns"
	// NeedContainerEngine: it relaunches itself in a container engine.
	NeedContainerEngine NativeSandboxNeed = "container_engine"
	// NeedAppContainer: it is AppContainer-based (N14).
	NeedAppContainer NativeSandboxNeed = "app_container"
	// NeedSeatbelt: on macOS it applies its own Seatbelt profile, which
	// cannot nest inside Observer's Seatbelt (N6, lane SBX-P5).
	NeedSeatbelt NativeSandboxNeed = "seatbelt"
)

// NativeSwitchKind is how a switch is applied.
type NativeSwitchKind string

// The closed NativeSwitchKind vocabulary.
const (
	NativeSwitchNone NativeSwitchKind = ""
	// NativeSwitchFlag: a command-line flag (per run).
	NativeSwitchFlag NativeSwitchKind = "flag"
	// NativeSwitchEnv: an environment variable (per run).
	NativeSwitchEnv NativeSwitchKind = "env"
	// NativeSwitchGlobalSetting: a write to the user's global tool
	// settings; never used by a launch, because it would also change the
	// user's unsandboxed runs (review R2-25).
	NativeSwitchGlobalSetting NativeSwitchKind = "global_setting"
)

// NativeSwitch is one grounded switch.
type NativeSwitch struct {
	Kind NativeSwitchKind
	// Value is the flag, NAME=value or setting, verbatim from the source.
	Value string
	// SourceURL is the vendor's documentation of the switch and
	// VerifiedOn the date (YYYY-MM-DD) it was read there. A switch without
	// both is never applied: it is refused, never guessed (lane SBX-P3D).
	SourceURL  string
	VerifiedOn string
}

var nativeDateRE = regexp.MustCompile(`^20[0-9]{2}-[01][0-9]-[0-3][0-9]$`)

// Grounded reports whether the switch names its documentation and date.
func (s NativeSwitch) Grounded() bool {
	return strings.HasPrefix(s.SourceURL, "https://") && nativeDateRE.MatchString(s.VerifiedOn)
}

// PerRun reports whether the switch affects this run alone and may be
// applied: a grounded flag whose tokens validate, or a grounded NAME=value
// environment switch. A global setting never is (review R2-25).
func (s NativeSwitch) PerRun() bool {
	if !s.Grounded() {
		return false
	}
	switch s.Kind {
	case NativeSwitchFlag:
		_, err := NativeSwitchArgs(s)
		return err == nil
	case NativeSwitchEnv:
		return validNativeEnv(s.Value)
	}
	return false
}

// nativeFlagRE is a flag-shaped first token (--name, -n, --name=value).
var nativeFlagRE = regexp.MustCompile(`^--?[A-Za-z0-9][A-Za-z0-9-]*(=.+)?$`)

// nativeTokenOK accepts a token as plain argv data: no whitespace, no
// control character, no placeholder angle bracket and none of the
// characters a shell or a template would give meaning to. The token is
// passed to exec as data and never reaches a shell; the rule keeps a row
// that reads like a command line from being taken as one.
func nativeTokenOK(tok string) bool {
	if tok == "" || len(tok) > 256 {
		return false
	}
	for _, c := range tok {
		if c <= ' ' || c == 0x7f || strings.ContainsRune("<>;|&$`\\'()*?!~#%^", c) {
			return false
		}
	}
	return true
}

// NativeSwitchArgs is a flag switch's argv tokens, validated: one
// flag-shaped token, optionally followed by one value that does not start
// with a dash, each plain data (nativeTokenOK). Anything else is refused.
func NativeSwitchArgs(s NativeSwitch) ([]string, error) {
	if s.Kind != NativeSwitchFlag {
		return nil, fmt.Errorf("integration: a %q switch has no argv form", s.Kind)
	}
	toks := strings.Fields(s.Value)
	if len(toks) == 0 || len(toks) > 2 {
		return nil, fmt.Errorf("integration: switch %q is not one flag with at most one value", s.Value)
	}
	if !nativeFlagRE.MatchString(toks[0]) {
		return nil, fmt.Errorf("integration: switch %q does not start with a flag", s.Value)
	}
	if len(toks) == 2 && strings.HasPrefix(toks[1], "-") {
		return nil, fmt.Errorf("integration: switch %q carries a second flag", s.Value)
	}
	for _, t := range toks {
		if !nativeTokenOK(t) {
			return nil, fmt.Errorf("integration: switch token %q is not plain argv data", t)
		}
	}
	return toks, nil
}

// validNativeEnv accepts NAME=value with a plain name and no control
// character or placeholder in the value.
func validNativeEnv(s string) bool {
	name, val, ok := strings.Cut(s, "=")
	if !ok || name == "" || val == "" {
		return false
	}
	for _, c := range name {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	for _, c := range val {
		if c < 0x20 || c == 0x7f || c == '<' || c == '>' {
			return false
		}
	}
	return true
}

// NativeSettingProbe names a JSON settings file the agent's vendor
// documents and the keys that must all be true in it: the user's own
// setting that turned the agent's sandbox on, or a vendor managed policy
// that forces it on. The cmd layer reads it (locally, no symlink followed,
// size-capped); this package only describes it.
type NativeSettingProbe struct {
	// Paths maps a GOOS to the file; "~/" is the user's home; "*" is any
	// operating system not listed.
	Paths map[string]string
	// Keys are key paths that must ALL be the boolean true (or, with
	// LacksValue, the one key path whose list is checked).
	Keys [][]string
	// Format is the file's format: "" or "json", or "toml" (lane LEFT-SBX).
	Format string
	// DropIns maps a GOOS to a directory of *.json drop-in files the vendor
	// merges with the file (lane LEFT-SBX): a key counts as true when one of
	// the documents sets it true and none sets it to anything else.
	DropIns map[string]string
	// LacksValue, when set, makes the probe true when Keys[0] is a list of
	// strings that does NOT hold this value (Codex's allowed_sandbox_modes
	// without danger-full-access: the per-run disable switch is refused, so
	// the vendor forces its own sandbox). A missing key is not forced.
	LacksValue string
	SourceURL  string
	VerifiedOn string
}

// Grounded reports whether the probe names its documentation and date.
func (p NativeSettingProbe) Grounded() bool {
	return NativeSwitch{SourceURL: p.SourceURL, VerifiedOn: p.VerifiedOn}.Grounded() && len(p.Keys) > 0 && len(p.Paths) > 0
}

// PathFor is the probe's file for goos ("" when none).
func (p NativeSettingProbe) PathFor(goos string) string {
	if v, ok := p.Paths[goos]; ok {
		return v
	}
	return p.Paths["*"]
}

// ErrNoNativeSwitch is NativeSwitchArgsForState's refusal: the evidence
// says Observer changed the agent's sandbox, but the row has no usable
// per-run switch for it.
var ErrNoNativeSwitch = errors.New("integration: no grounded per-run switch for the recorded native sandbox state")

// NativeSwitchArgsForState is THE rule the launch composition applies
// (lane SBX-P3D): the argv tokens the agent gets for the
// native_sandbox_state its run records. disabled_by_observer applies the
// row's Disable switch, weak its WeakMode switch; any other state adds
// nothing. An environment switch adds no argv (the driver that owns the
// box environment applies it); a switch that is not per run is
// ErrNoNativeSwitch, so the evidence can never claim a change nobody made.
func NativeSwitchArgsForState(tool string, state vocab.NativeSandboxState) ([]string, error) {
	var sw NativeSwitch
	switch state {
	case vocab.NativeDisabledByObserver:
		sw = nativeSandboxes[tool].Disable
	case vocab.NativeWeak:
		sw = nativeSandboxes[tool].WeakMode
	default:
		return nil, nil
	}
	if !sw.PerRun() {
		return nil, fmt.Errorf("%w (%s, %s)", ErrNoNativeSwitch, tool, state)
	}
	if sw.Kind == NativeSwitchEnv {
		return nil, nil
	}
	return NativeSwitchArgs(sw)
}

// AppendNativeArgs appends switch tokens to an agent's argument list after
// the launcher's pass-through separator, so the launcher hands them to the
// agent verbatim and never reads them as its own flags: a list that has no
// "--" gains one first.
func AppendNativeArgs(args, switchArgs []string) []string {
	if len(switchArgs) == 0 {
		return args
	}
	out := append([]string(nil), args...)
	hasSep := false
	for _, a := range out {
		if a == "--" {
			hasSep = true
			break
		}
	}
	if !hasSep {
		out = append(out, "--")
	}
	return append(out, switchArgs...)
}

// NativeGrounding says how a row is known.
type NativeGrounding string

// The NativeGrounding values.
const (
	// NativeGroundingAnalysis: the plan's analysis (section 4.4 and the
	// research companion part G); not yet run on a host.
	NativeGroundingAnalysis NativeGrounding = "analysis"
)

// NativeSandbox is one agent's own sandbox.
type NativeSandbox struct {
	// Mechanism names the agent's sandbox, for people.
	Mechanism string
	// DefaultOn: the agent turns it on without the user asking. A sandbox
	// that is off by default is not judged at launch (Observer cannot know
	// whether the user turned it on); its state is left unrecorded.
	DefaultOn bool
	// Needs are what it needs from the layer around it.
	Needs []NativeSandboxNeed
	// Disable is the switch that turns it off.
	Disable NativeSwitch
	// WeakMode is a grounded per-run switch that runs the agent's sandbox
	// in a weaker nested mode (applied only where a conflict row matches
	// and UserOn reads that the user turned it on; recorded weak).
	WeakMode NativeSwitch
	// UserOn reads whether the user turned an off-by-default sandbox on
	// (only read for a row with a WeakMode switch).
	UserOn *NativeSettingProbe
	// Managed are the vendor managed-policy files that force the sandbox
	// on (vendor_forced_native); a row with none is never detected forced.
	Managed []NativeSettingProbe
	// OrgLockable: a vendor managed policy can force it on.
	OrgLockable bool
	// DetectionEnv are variables the agent reads to detect a sandbox; the
	// launcher never sets them by accident.
	DetectionEnv []string
	Grounding    NativeGrounding
	Note         string
}

// NeedsAny reports whether the row needs want.
func (n NativeSandbox) NeedsAny(want NativeSandboxNeed) bool {
	for _, x := range n.Needs {
		if x == want {
			return true
		}
	}
	return false
}

// nativeSandboxes is the side table, keyed by registry tool id. The facts
// are the plan's section 4.4 conflict table.
var nativeSandboxes = map[string]NativeSandbox{
	"claude-code": {
		Mechanism: "bubblewrap on Linux, Seatbelt on macOS (/sandbox)",
		Needs:     []NativeSandboxNeed{NeedFreshProc, NeedNestedUserns, NeedSeatbelt},
		// The per-run settings layer: --settings is a command-line override
		// above the user, project and local settings and below managed
		// settings (the settings reference); the key is sandbox.enabled.
		Disable: NativeSwitch{
			Kind: NativeSwitchFlag, Value: `--settings {"sandbox":{"enabled":false}}`,
			SourceURL: "https://code.claude.com/docs/en/settings-reference", VerifiedOn: "2026-10-23",
		},
		// sandbox.enableWeakerNestedSandbox (https://code.claude.com/docs/en/sandboxing)
		// runs it in a weaker nested mode. Deliberately NOT a WeakMode
		// switch yet (lane SBX-P3D): applying it would change a launch that
		// runs today (Claude Code with its sandbox on, under bwrap), and the
		// per-run route through --settings is not live-proven; recorded gap.
		// A managed enabled + failIfUnavailable forces the sandbox on and
		// cannot be overridden (vendor_forced_native).
		Managed: []NativeSettingProbe{{
			Paths: map[string]string{
				"linux":   "/etc/claude-code/managed-settings.json",
				"darwin":  "/Library/Application Support/ClaudeCode/managed-settings.json",
				"windows": `C:\Program Files\ClaudeCode\managed-settings.json`,
			},
			// The drop-in directory beside it, merged with it (lane
			// LEFT-SBX; the managed-settings page, read 2026-10-24).
			DropIns: map[string]string{
				"linux":   "/etc/claude-code/managed-settings.d",
				"darwin":  "/Library/Application Support/ClaudeCode/managed-settings.d",
				"windows": `C:\Program Files\ClaudeCode\managed-settings.d`,
			},
			Keys:      [][]string{{"sandbox", "enabled"}, {"sandbox", "failIfUnavailable"}},
			SourceURL: "https://code.claude.com/docs/en/managed-settings", VerifiedOn: "2026-10-24",
		}},
		OrgLockable: true, Grounding: NativeGroundingAnalysis,
		Note: "inside Observer's bwrap the inner bwrap is expected to fail on /proc; its weak nested mode works; a managed enabled + failIfUnavailable cannot be overridden",
	},
	"codex": {
		Mechanism: "Landlock and seccomp on Linux, Seatbelt on macOS",
		DefaultOn: true,
		Needs:     []NativeSandboxNeed{NeedSeatbelt},
		Disable: NativeSwitch{
			Kind: NativeSwitchFlag, Value: "--sandbox danger-full-access",
			SourceURL: "https://developers.openai.com/codex/security", VerifiedOn: "2026-10-23",
		},
		// requirements.toml (lane LEFT-SBX): an admin's allowed_sandbox_modes
		// without danger-full-access refuses the per-run disable switch, so
		// Codex's own sandbox is forced. Grounded in the vendor's source, its
		// loader (the system path per OS) and its requirements type (the key
		// and its values), read 2026-10-24; the legacy
		// /etc/codex/managed_config.toml is reinterpreted the same way.
		Managed: []NativeSettingProbe{
			{
				Paths: map[string]string{
					"linux": "/etc/codex/requirements.toml", "darwin": "/etc/codex/requirements.toml",
					"windows": `C:\ProgramData\OpenAI\Codex\requirements.toml`,
				},
				Format: "toml", Keys: [][]string{{"allowed_sandbox_modes"}}, LacksValue: "danger-full-access",
				SourceURL: "https://github.com/openai/codex/blob/main/codex-rs/config/src/loader/mod.rs", VerifiedOn: "2026-10-24",
			},
			{
				Paths:  map[string]string{"linux": "/etc/codex/managed_config.toml", "darwin": "/etc/codex/managed_config.toml"},
				Format: "toml", Keys: [][]string{{"allowed_sandbox_modes"}}, LacksValue: "danger-full-access",
				SourceURL: "https://github.com/openai/codex/blob/main/codex-rs/config/src/loader/mod.rs", VerifiedOn: "2026-10-24",
			},
		},
		OrgLockable: true, Grounding: NativeGroundingAnalysis,
		Note: "expected to nest inside Observer's bwrap (keeps the inherited /proc); its proxy chains to Observer's",
	},
	"gemini-cli": {
		Mechanism:    "relaunch in a container engine, or under sandbox-exec on macOS; tool sandboxing",
		Needs:        []NativeSandboxNeed{NeedContainerEngine, NeedFreshProc, NeedSeatbelt},
		Disable:      NativeSwitch{Kind: NativeSwitchEnv, Value: "SANDBOX=<label>"},
		DetectionEnv: []string{"SANDBOX"}, Grounding: NativeGroundingAnalysis,
		Note: "setting SANDBOX stops the relaunch hop; security.toolSandboxing: false turns tool sandboxing off",
	},
	"qwen-code": {
		Mechanism:    "relaunch in a container engine",
		Needs:        []NativeSandboxNeed{NeedContainerEngine},
		Disable:      NativeSwitch{Kind: NativeSwitchEnv, Value: "QWEN_SANDBOX=false"},
		DetectionEnv: []string{"SANDBOX"}, Grounding: NativeGroundingAnalysis,
		Note: "the container relaunch fails without an engine socket",
	},
	"copilot-cli": {
		Mechanism: "user namespaces with a TUN device and slirp4netns",
		Needs:     []NativeSandboxNeed{NeedDevNetTUN, NeedNestedUserns},
		Disable: NativeSwitch{
			Kind: NativeSwitchFlag, Value: "--no-sandbox",
			SourceURL: "https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/cloud-and-local-sandboxes/using-local-sandboxing", VerifiedOn: "2026-10-23",
		},
		// No managed-policy detection row (lane LEFT-SBX): the managed
		// settings that require the sandbox have no documented file path and
		// key this lane could read (docs.github.com was not reachable from its
		// sandbox); not guessed.
		OrgLockable: true, Grounding: NativeGroundingAnalysis,
		Note: "refuses inside Observer's bwrap (no /dev/net/tun); it reports the failure rather than weakening; the flag cannot override managed settings that require it",
	},
	"droid": {
		Mechanism: "whole-process sandbox mode",
		Needs:     []NativeSandboxNeed{NeedFreshProc},
		Disable:   NativeSwitch{Kind: NativeSwitchGlobalSetting, Value: "sandbox.enabled: false"},
		// Factory's org mode can force it on. No managed-policy detection row
		// (lane LEFT-SBX): the vendor's documents were not reachable from the
		// lane's sandbox, so no path or key is sourced; not guessed.
		OrgLockable: true, Grounding: NativeGroundingAnalysis,
		Note: "whole-process mode is expected to refuse to start inside Observer's bwrap",
	},
	"kiro-cli": {
		Mechanism: "Kiro's command sandbox",
		Needs:     []NativeSandboxNeed{NeedFreshProc},
		Disable:   NativeSwitch{Kind: NativeSwitchGlobalSetting, Value: "sandbox.json \"enabled\": false"},
		Grounding: NativeGroundingAnalysis,
		Note:      "expected to fall back to running unsandboxed inside Observer's bwrap",
	},
}

// NativeSandboxFor returns tool's native sandbox row; ok is false when the
// tool has none Observer knows of.
func NativeSandboxFor(tool string) (NativeSandbox, bool) {
	n, ok := nativeSandboxes[tool]
	return n, ok
}

// NativeSandboxTools lists the tools with a native sandbox row.
func NativeSandboxTools() []string {
	out := make([]string, 0, len(nativeSandboxes))
	for t := range nativeSandboxes {
		out = append(out, t)
	}
	return out
}
