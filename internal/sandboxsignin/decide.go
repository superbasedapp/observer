package sandboxsignin

import (
	"fmt"
	"strings"
)

// Verdict is the closed outcome of Decide.
type Verdict string

// The verdicts.
const (
	// VerdictSeed: copy exactly Decision.Files into the box.
	VerdictSeed Verdict = "seed"
	// VerdictAsk: ask the user (the CLI prompt, the dashboard's inline
	// step); nothing is copied until they answer yes.
	VerdictAsk Verdict = "ask"
	// VerdictNotConsented: no consent, so nothing is copied (the user said
	// no, or no one could be asked and none is remembered).
	VerdictNotConsented Verdict = "not_consented"
	// VerdictBound: the backend binds the tool's own state; nothing is
	// copied because the box already reads the host's state directory.
	VerdictBound Verdict = "bound"
	// VerdictRefused: seeding is not possible here (Decision.Reason names
	// why: hosted, no row, keychain or the organization).
	VerdictRefused Verdict = "refused"
)

// Answer is the user's per-launch answer.
type Answer int

// The answers.
const (
	// AnswerNone: not asked or not answered.
	AnswerNone Answer = iota
	// AnswerYes: copy the sign-in for this launch.
	AnswerYes
	// AnswerNo: start without it.
	AnswerNo
)

// Input is everything Decide reads, resolved at the caller's boundary.
type Input struct {
	// Tool is the registry tool id (named in the reasons only).
	Tool string
	// Files are the tool's sign-in files from its registry row (empty when
	// none is grounded).
	Files []string
	// Keychain: the vendor keeps the sign-in in the system keychain on
	// this OS.
	Keychain bool
	// MayUseKeychain: the vendor CAN keep the sign-in in the system
	// keychain instead of the file (a store setting Observer does not read),
	// so a missing file is reported with the keychain reason.
	MayUseKeychain bool
	// Hosted: the backend is a hosted row (a third party's machine).
	Hosted bool
	// Projected: the box starts from projected tool state (a per-run copy
	// the run owns). False means the backend binds the real state.
	Projected bool
	// OrgForbidden: the organization's sandbox managed policy forbids
	// seeding (lowering only).
	OrgForbidden bool
	// Remembered: [terminal.sandbox].sign_in_seed_tools names the tool.
	Remembered bool
	// Launch is the per-launch answer.
	Launch Answer
	// Interactive: someone can be asked now (a terminal prompt, the
	// dashboard dialog).
	Interactive bool
}

// Decision is Decide's result.
type Decision struct {
	// Verdict is the outcome.
	Verdict Verdict
	// Rule is the table row that decided (R1 to R10).
	Rule string
	// Code is a short stable reason code (hosted, no_row, keychain, bound,
	// org_forbidden, declined, consented, remembered, ask, headless).
	Code string
	// Reason is the sentence a refusal, a posture line or a log line shows.
	Reason string
	// Files are the files to copy (VerdictSeed) or to ask about
	// (VerdictAsk); empty otherwise.
	Files []string
	// KeychainIfMissing: a missing file means the sign-in may be in the
	// system keychain (Input.MayUseKeychain).
	KeychainIfMissing bool
}

// The reason sentences the rulings fix.
const (
	// HostedReason is R1's sentence.
	HostedReason = "a hosted sandbox would copy the sign-in to a third party's machine; sign-in seeding covers local sandboxes only"
	// KeychainReason is R3's sentence.
	KeychainReason = "signed in through the system keychain; sign-in seeding covers file sign-ins only"
	// OrgReason is R5's sentence.
	OrgReason = "your organization forbids copying a sign-in into a sandbox (the sandbox managed policy's sign_in_seed_forbidden)"
	// BoundNote says what seeding, its consent and the org forbid do not
	// cover (operator ruling P-183): a row that binds the tool's own state
	// shares the tool's sign-in with the box on every launch.
	BoundNote = "a bound row (bubblewrap, Landlock, Seatbelt, mxc-process, Apple container, or oci-runc running this machine's own tool) shares the tool's own state with the box, sign-in included: the sandbox limits files and network, not the tool's own login; consent and the organization's forbid apply to clean-copy container runs"
)

type rule struct {
	id, code string
	when     func(Input) bool
	verdict  Verdict
	reason   func(Input) string
	files    bool
}

// rules is the ordered table; the first row whose when holds decides.
var rules = []rule{
	{
		id: "R1", code: "hosted", when: func(in Input) bool { return in.Hosted }, verdict: VerdictRefused,
		reason: func(Input) string { return HostedReason },
	},
	{
		id: "R2", code: "no_row", when: func(in Input) bool { return len(in.Files) == 0 }, verdict: VerdictRefused,
		reason: func(in Input) string {
			return fmt.Sprintf("no sign-in file is grounded for %s; sign in inside the box, or onboard %s once outside the sandbox", in.Tool, in.Tool)
		},
	},
	{
		id: "R3", code: "keychain", when: func(in Input) bool { return in.Keychain }, verdict: VerdictRefused,
		reason: func(Input) string { return KeychainReason },
	},
	{
		id: "R4", code: "bound", when: func(in Input) bool { return !in.Projected }, verdict: VerdictBound,
		reason: func(in Input) string {
			return fmt.Sprintf("this backend binds %s's own state directory, so the box reads the host's sign-in file (%s) in place; nothing is copied", in.Tool, strings.Join(in.Files, ", "))
		},
	},
	{
		id: "R5", code: "org_forbidden", when: func(in Input) bool { return in.OrgForbidden }, verdict: VerdictRefused,
		reason: func(Input) string { return OrgReason },
	},
	{
		id: "R6", code: "declined", when: func(in Input) bool { return in.Launch == AnswerNo }, verdict: VerdictNotConsented,
		reason: func(in Input) string { return fmt.Sprintf("you chose to start %s without its sign-in", in.Tool) },
	},
	{
		id: "R7", code: "consented", when: func(in Input) bool { return in.Launch == AnswerYes }, verdict: VerdictSeed, files: true,
		reason: func(in Input) string {
			return fmt.Sprintf("you consented for this launch to copy %s's sign-in", in.Tool)
		},
	},
	{
		id: "R8", code: "remembered", when: func(in Input) bool { return in.Remembered }, verdict: VerdictSeed, files: true,
		reason: func(in Input) string {
			return fmt.Sprintf("[terminal.sandbox].sign_in_seed_tools remembers your consent for %s", in.Tool)
		},
	},
	{
		id: "R9", code: "ask", when: func(in Input) bool { return in.Interactive }, verdict: VerdictAsk, files: true,
		reason: func(in Input) string {
			return fmt.Sprintf("%s's sign-in can be copied into this box with your consent", in.Tool)
		},
	},
	{
		id: "R10", code: "headless", when: func(Input) bool { return true }, verdict: VerdictNotConsented,
		reason: func(in Input) string {
			return fmt.Sprintf("no consent for %s is remembered and no one can be asked, so its sign-in is not copied; the tool signs in again inside the box", in.Tool)
		},
	},
}

// Decide walks the rule table.
func Decide(in Input) Decision {
	for _, r := range rules {
		if !r.when(in) {
			continue
		}
		d := Decision{Verdict: r.verdict, Rule: r.id, Code: r.code, Reason: r.reason(in)}
		if r.files {
			d.Files = append([]string(nil), in.Files...)
			d.KeychainIfMissing = in.MayUseKeychain
		}
		return d
	}
	return Decision{Verdict: VerdictNotConsented, Rule: "R10", Code: "headless"}
}

// RefusesExplicit reports whether a launch that explicitly asked for the
// sign-in (a yes given before the decision, a CLI flag) must be refused
// rather than started without it, so the user is never misled into a box
// that is not signed in: true for every refusal (hosted, no row, keychain,
// the organization).
func (d Decision) RefusesExplicit() bool { return d.Verdict == VerdictRefused }

// ConsentText is the consent question (ruling P-180 (6) 2): it names the
// tool, each file that will be copied (path only), that the tool inside the
// box can read and use it and that the box's allowed network can carry it,
// and that it is removed when the run ends.
func ConsentText(tool string, files []string) string {
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, "~/"+strings.TrimPrefix(f, "/"))
	}
	return fmt.Sprintf("Copy %s's sign-in into this sandbox for this run? File copied: %s. "+
		"The tool inside the box can read and use it, and the box's allowed network can carry it. "+
		"The copy is removed when the run ends; a sign-in the tool refreshes in the box is not written back to this machine.",
		tool, strings.Join(paths, ", "))
}

// PostureLine is the run's posture and log sentence for a decision: which
// tool's sign-in was copied and which file names (copied), never a value.
func PostureLine(tool string, d Decision, copied []string) string {
	switch d.Verdict {
	case VerdictSeed:
		if len(copied) == 0 && d.KeychainIfMissing {
			return fmt.Sprintf("sign-in: not copied for %s: no sign-in file on this machine (%s); %s", tool, strings.Join(d.Files, ", "), KeychainReason)
		}
		if len(copied) == 0 {
			return fmt.Sprintf("sign-in: %s has no sign-in file on this machine (%s), nothing copied", tool, strings.Join(d.Files, ", "))
		}
		return fmt.Sprintf("sign-in: copied %s's sign-in into this box for this run (%s; %s); it is removed when the run ends", tool, strings.Join(copied, ", "), d.Reason)
	case VerdictBound:
		return "sign-in: " + d.Reason
	case VerdictRefused:
		return fmt.Sprintf("sign-in: not copied for %s: %s", tool, d.Reason)
	default:
		return fmt.Sprintf("sign-in: not copied for %s (%s)", tool, d.Reason)
	}
}

// SharedLine is the posture line of a run on a row that binds the tool's own
// state (operator ruling P-183): the box limits files and network, not the
// tool's own login, so the tool's sign-in is visible inside the box. It
// names the tool and the sign-in file names, never a value.
func SharedLine(tool string, files []string) string {
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, "~/"+strings.TrimPrefix(f, "/"))
	}
	return fmt.Sprintf("sign-in: this box shares %s's own state with this machine, sign-in included (%s): the sandbox limits files and network, not the tool's own login", tool, strings.Join(paths, ", "))
}
