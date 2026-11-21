package cloudsession

import (
	"fmt"
	"strings"
)

// gate.go is the sandbox guard's hook side (lane CA-C2): which vendor events
// carry a gate, how each vendor dialect blocks, what a gate does when it
// cannot evaluate, and the committed command. The gate itself
// (`observer cloud-session gate`) evaluates the committed policy file with no
// network call: it verifies the file (policy.go), runs the ordinary guard
// engine over the event, and answers in the vendor's own reply dialect
// (internal/hook). Everything that differs between vendors is a row here.

// GuardMode is the sandbox guard's mode, baked into the committed gate.
type GuardMode string

// The guard modes.
const (
	// GuardEnforce: deny and ask verdicts reach the vendor, and a gate that
	// cannot evaluate blocks where the vendor honors a block
	// (docs/guard.md "Hook failure semantics").
	GuardEnforce GuardMode = "enforce"
	// GuardObserve: verdicts are recorded and nothing is blocked.
	GuardObserve GuardMode = "observe"
)

// GuardModes lists the modes.
func GuardModes() []GuardMode { return []GuardMode{GuardEnforce, GuardObserve} }

// ValidGuardMode reports whether m is a known mode.
func ValidGuardMode(m GuardMode) bool { return m == GuardEnforce || m == GuardObserve }

// GateKind is what a gate entry judges.
type GateKind string

// The gate kinds.
const (
	// GateTool judges a tool call before it runs (PreToolUse).
	GateTool GateKind = "tool"
	// GatePrompt judges a submitted prompt: the soft budget stop and the
	// policy file check. Prompt-content intervention stays with the
	// capture hook on the same event, which already runs the guard's
	// prompt lane (so a prompt is never judged twice).
	GatePrompt GateKind = "prompt"
)

// gateDialect is one row of the gate dialect table: how a vendor reply
// dialect (an internal/hook dialect id, cross-checked against the
// internal/integration registry by TestGateDialectsMatchRegistry) blocks.
type gateDialect struct {
	// id is the internal/hook dialect id.
	id string
	// blocks: the vendor honors a block on this event (documented or live).
	blocks bool
	// missingBinary is the shell that blocks when observer is not installed
	// in the sandbox (the setup step failed); empty when the vendor cannot
	// be made to block without observer's own reply, so a missing binary
	// fails open there.
	missingBinary string
	// grounding is where the blocking behaviour comes from.
	grounding string
}

// gateDialects is THE gate dialect table.
var gateDialects = []gateDialect{
	{
		id: "claude-code-pretool", blocks: true, missingBinary: "exit 2",
		grounding: "live on the local CLI (docs/guard.md); repository hooks fire in a cloud session (CA-A2), a cloud deny is owed a live check",
	},
	{
		id: "claude-code", blocks: true, missingBinary: "exit 2",
		grounding: "exit code 2 with the reason on stderr blocks the prompt (live on the local CLI, 2026-09-07); owed a live check in a cloud session",
	},
	{
		id: "copilot-cli-pretool", blocks: true, missingBinary: "exit 2",
		grounding: "permissionDecision deny (live on Copilot CLI 1.0.91); a non-zero exit denies; the cloud agent runs repository hooks per the vendor docs, not yet live-checked",
	},
	{
		id: "copilot-cli-prompt", blocks: true,
		grounding: "a handled reply blocks (live on Copilot CLI 1.0.96); an exit code does not, so without observer the prompt passes",
	},
}

func gateDialectFor(id string) (gateDialect, bool) {
	for _, d := range gateDialects {
		if d.id == id {
			return d, true
		}
	}
	return gateDialect{}, false
}

// GateBinding returns the agent's gate entry for a vendor event.
func GateBinding(a Agent, event string) (HookBinding, error) {
	for _, b := range a.Hooks {
		if b.Action == ActionGate && b.Event == event {
			return b, nil
		}
	}
	return HookBinding{}, fmt.Errorf("cloudsession: %s has no gate on event %q", a.DisplayName, event)
}

// GateFailure is what a gate does when it cannot evaluate (the policy file
// is refused, the guard cannot be built, the payload does not parse).
type GateFailure string

// The gate failure answers.
const (
	// FailClosed: answer with the dialect's block and a reason.
	FailClosed GateFailure = "fail_closed"
	// FailOpen: let the call through and say so on stderr.
	FailOpen GateFailure = "fail_open"
)

// gateFailureRule is one row of the failure table.
type gateFailureRule struct {
	answer GateFailure
	when   func(mode GuardMode, d gateDialect) bool
}

// gateFailureRules is THE failure table, walked top-down: a gate fails
// closed only under enforcement on a dialect that honors a block.
var gateFailureRules = []gateFailureRule{
	{FailClosed, func(m GuardMode, d gateDialect) bool { return m == GuardEnforce && d.blocks }},
	{FailOpen, func(GuardMode, gateDialect) bool { return true }},
}

// GateFailureFor returns the failure answer for a binding under mode.
func GateFailureFor(b HookBinding, mode GuardMode) GateFailure {
	d, _ := gateDialectFor(b.Dialect)
	for _, r := range gateFailureRules {
		if r.when(mode, d) {
			return r.answer
		}
	}
	return FailOpen
}

// MissingBinaryReason is what a fail-closed gate prints when observer is not
// installed in the sandbox.
const MissingBinaryReason = "Observer is not installed in this cloud sandbox (check the setup script output); the call is blocked because this repository runs the cloud-session guard in enforce mode."

// gateCommand renders the committed command of one gate entry. Like every
// committed command it does nothing outside the vendor's cloud. Inside it,
// with observer installed, `exec` hands observer the hook's stdin and makes
// its exit status the hook's; without observer, an enforce-mode gate on a
// dialect that can block without observer's reply blocks with a reason
// (fail closed), and every other gate exits 0.
func gateCommand(a Agent, b HookBinding, opts PlanOptions) (string, error) {
	if opts.Guard == nil {
		return "", fmt.Errorf("cloudsession: agent %q gate on %s without --guard", a.ID, b.Event)
	}
	d, ok := gateDialectFor(b.Dialect)
	if !ok {
		return "", fmt.Errorf("cloudsession: agent %q gate on %s has unknown dialect %q", a.ID, b.Event, b.Dialect)
	}
	argv := []string{
		"cloud-session", "gate", "--agent", a.ID, "--event", b.Event,
		"--mode", string(opts.Guard.Mode), "--key-pin", opts.Guard.KeyPin, "--policy", PolicyDigest(opts.Guard.Policy),
	}
	bin := shellQuote(opts.installDir() + "/observer")
	quoted := make([]string, len(argv))
	for i, s := range argv {
		quoted[i] = shellQuote(s)
	}
	run := fmt.Sprintf("[ -x %s ] && exec %s %s", bin, bin, strings.Join(quoted, " "))
	if opts.Guard.Mode == GuardEnforce && d.missingBinary != "" {
		return fmt.Sprintf("%s && { %s; printf '%%s\\n' %s >&2; %s; }; exit 0 %s",
			markerGate(a), run, shellQuote(MissingBinaryReason), d.missingBinary, OwnerTag), nil
	}
	return fmt.Sprintf("%s && %s; exit 0 %s", markerGate(a), run, OwnerTag), nil
}

// GateCoverage is one gate's honest capability line, printed by init and
// documented in docs/cloud-sessions.md.
type GateCoverage struct {
	Event string
	Kind  GateKind
	// Blocks: a deny (tool) or a stop (prompt) reaches the vendor.
	Blocks bool
	// Failure is what the gate does when it cannot evaluate.
	Failure GateFailure
	// MissingBinary is what the gate does when observer is not installed.
	MissingBinary GateFailure
	Grounding     string
}

// Line renders the coverage as one sentence.
func (c GateCoverage) Line() string {
	what := "denies tool calls the policy denies"
	if c.Kind == GatePrompt {
		what = "stops prompts when the org budget snapshot is over a cap"
	}
	if !c.Blocks {
		what = "records verdicts only (observe mode)"
	}
	return fmt.Sprintf("%s %s gate: %s; cannot evaluate -> %s; observer missing -> %s (%s)",
		c.Event, c.Kind, what, c.Failure, c.MissingBinary, c.Grounding)
}

// GateCoverageFor returns the coverage of every gate the agent commits under
// mode.
func GateCoverageFor(a Agent, mode GuardMode) []GateCoverage {
	var out []GateCoverage
	for _, b := range a.Hooks {
		if b.Action != ActionGate {
			continue
		}
		d, _ := gateDialectFor(b.Dialect)
		missing := FailOpen
		if mode == GuardEnforce && d.missingBinary != "" {
			missing = FailClosed
		}
		out = append(out, GateCoverage{
			Event: b.Event, Kind: b.Gate, Blocks: mode == GuardEnforce && d.blocks,
			Failure: GateFailureFor(b, mode), MissingBinary: missing, Grounding: d.grounding,
		})
	}
	return out
}

// GuardSetup is init's guard input (PlanOptions.Guard).
type GuardSetup struct {
	// Mode is baked into every gate.
	Mode GuardMode
	// KeyPin is the sha256 hex of the key that signed Policy.
	KeyPin string
	// Policy is the policy file (EncodePolicy output), already verified
	// against KeyPin by the caller; init verifies it again before planning.
	Policy []byte
}

// validateGuard checks the guard input before anything is rendered.
func validateGuard(g *GuardSetup) error {
	if g == nil {
		return nil
	}
	if !ValidGuardMode(g.Mode) {
		return fmt.Errorf("cloudsession: --guard-mode must be one of %v, got %q", GuardModes(), g.Mode)
	}
	pin := PolicyPin{KeyPin: g.KeyPin, Digest: PolicyDigest(g.Policy)}
	if _, err := VerifyPolicy(g.Policy, true, pin); err != nil {
		return fmt.Errorf("cloudsession: the fetched policy does not verify against its key pin: %w", err)
	}
	return nil
}
