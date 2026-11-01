package sandboxsbpl

// native.go is nesting row N6 for agents (sandbox plan v2 section 4.4 and
// P5 scope item 1): Seatbelt cannot nest, so an agent that applies its OWN
// Seatbelt profile on macOS (sandbox_init or sandbox-exec) fails inside
// Observer's. What the launch does about it is this table, walked top-down
// over facts the cmd layer reduces from internal/integration's native
// sandbox row at the boundary, so no rule here names a tool. Every outcome
// is a register item (MAC-6) until a Mac proves the switch.

// SwitchKind is how an agent's own sandbox is turned off.
type SwitchKind string

// The closed SwitchKind vocabulary (internal/integration's NativeSwitchKind,
// reduced at the boundary).
const (
	SwitchNone          SwitchKind = ""
	SwitchEnv           SwitchKind = "env"
	SwitchFlag          SwitchKind = "flag"
	SwitchGlobalSetting SwitchKind = "global_setting"
)

// Native is what N6 needs about the agent.
type Native struct {
	// Seatbelt: the agent applies its own Seatbelt profile on macOS.
	Seatbelt bool
	// DefaultOn: the agent turns it on without being asked.
	DefaultOn bool
	// Switch and Value are the grounded off switch (an env switch's Value
	// is NAME=value). The boundary passes a per-run kind only for a switch
	// that names its documentation (integration.NativeSwitch.PerRun).
	Switch SwitchKind
	Value  string
	// Args are a flag switch's validated argv tokens (the boundary's
	// integration.NativeSwitchArgs); empty refuses a flag switch.
	Args []string
	// VendorForced: a vendor managed policy forces the agent's sandbox on;
	// ForcedPolicy is [terminal.sandbox].vendor_forced_native.
	VendorForced bool
	ForcedPolicy string
}

// NativeOutcome is the launch's answer.
type NativeOutcome string

// The closed NativeOutcome vocabulary.
const (
	// NativeKept: the agent has no Seatbelt of its own; nothing to do.
	NativeKept NativeOutcome = "kept"
	// NativeUnjudged: its Seatbelt is off by default, so Observer cannot
	// know whether the user turned it on; nothing is recorded, and the
	// note names the switch should the agent fail to start a command.
	NativeUnjudged NativeOutcome = "unjudged"
	// NativeDisableEnv: the per-run environment switch is applied.
	NativeDisableEnv NativeOutcome = "disable_env"
	// NativeDisableFlag: the per-run command-line switch is applied (the
	// launch composition appends Args to the agent's own arguments; lane
	// SBX-P3D).
	NativeDisableFlag NativeOutcome = "disable_flag"
	// NativeRefuse: the launch is refused (tool_conflict).
	NativeRefuse NativeOutcome = "refuse"
)

// NativeDecision is the table's answer.
type NativeDecision struct {
	Outcome NativeOutcome
	Rule    string
	Reason  string
	// Env is the NAME=value to add to the inner launch (NativeDisableEnv).
	Env []string
	// Args are the tokens the agent's arguments gain (NativeDisableFlag).
	Args []string
}

type nativeRow struct {
	id      string
	match   func(n Native) bool
	outcome NativeOutcome
	reason  string
}

// nativeRows is N6's table, first match wins.
var nativeRows = []nativeRow{
	{"N6-none", func(n Native) bool { return !n.Seatbelt }, NativeKept, "the agent applies no Seatbelt profile of its own"},
	{
		"N6-vendor-forced", func(n Native) bool { return n.VendorForced }, NativeRefuse,
		"Seatbelt does not nest, and a vendor managed policy forces the agent's own Seatbelt on; under [terminal.sandbox].vendor_forced_native (nest_or_refuse or refuse) no stack where both run (an hw_vm row, N13) is built yet (tool_conflict)",
	},
	{
		"N6-off-by-default", func(n Native) bool { return !n.DefaultOn }, NativeUnjudged,
		"the agent's own Seatbelt is off by default; if you turned it on it cannot start inside Observer's Seatbelt (Seatbelt does not nest), so turn it off for sandboxed runs",
	},
	{
		"N6-env", func(n Native) bool { return n.Switch == SwitchEnv && validEnvSwitch(n.Value) }, NativeDisableEnv,
		"Seatbelt does not nest, so the agent's own Seatbelt is turned off for this run by its environment switch; Observer's profile is the boundary",
	},
	{
		"N6-flag", func(n Native) bool { return n.Switch == SwitchFlag && len(n.Args) > 0 }, NativeDisableFlag,
		"Seatbelt does not nest, so the agent's own Seatbelt is turned off for this run by its command-line switch; Observer's profile is the boundary",
	},
	{
		"N6-no-per-run-switch", func(Native) bool { return true }, NativeRefuse,
		"Seatbelt does not nest, and the agent has no per-run off switch; a global setting would change your unsandboxed runs too (tool_conflict)",
	},
}

// DecideNative walks N6's table.
func DecideNative(n Native) NativeDecision {
	for _, r := range nativeRows {
		if !r.match(n) {
			continue
		}
		d := NativeDecision{Outcome: r.outcome, Rule: r.id, Reason: r.reason}
		switch r.outcome {
		case NativeDisableEnv:
			d.Env = []string{n.Value}
		case NativeDisableFlag:
			d.Args = append([]string(nil), n.Args...)
		}
		return d
	}
	return NativeDecision{Outcome: NativeRefuse, Rule: "N6-unreached"}
}

// validEnvSwitch accepts NAME=value with a plain name and no control
// character (a switch carrying a placeholder such as <label> is not a
// literal value and is refused, never guessed).
func validEnvSwitch(s string) bool {
	name, val, ok := cutEq(s)
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

func cutEq(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
