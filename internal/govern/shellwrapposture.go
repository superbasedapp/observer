package govern

// shellwrapposture.go: who decides whether a managed node keeps command
// wrapping (shell-wrap) applied (surface-gap arc finding CLI-1b, operator
// decision D6, 2026-10-25: "shell-wrap is org-governable on managed nodes;
// individual nodes stay per-user opt-in").
//
// The admin's setting is the node.governance settings.pin key
// ShellWrapMaintainKey, authored on the node-governance policy form and
// signed like every other pin. Composition, in this order
// (shellWrapPostureRules, one test case per row):
//
//  1. Not a managed node, or its grant is refused: no posture. The
//     developer's own opt-in (`observer shell-wrap enable`) is the only
//     writer, as before.
//  2. The admin pinned the setting ON: maintain (the daemon applies the wrap
//     when it is not applied, and the developer cannot turn it off).
//  3. The admin pinned the setting OFF: release (the daemon removes the wrap
//     only when the organization applied it; a wrap the developer applied is
//     the developer's).
//  4. Unset: no posture. Unlike routes there is no enforce default: wrapping
//     is never forced on by an authority alone.

// ShellWrapMaintainKey is the node.governance pinnable key the admin uses to
// turn managed command wrapping on or off (internal/policyfam/nodegov
// PinnableKeys row "shell_wrap.org_maintain").
const ShellWrapMaintainKey = "shell_wrap.org_maintain"

// ShellWrapPosture is what a managed node does about command wrapping.
type ShellWrapPosture string

const (
	// ShellWrapPostureNone: the developer decides; nothing is written.
	ShellWrapPostureNone ShellWrapPosture = "none"
	// ShellWrapPostureMaintain: keep the wrap applied for every wrappable
	// tool and refuse the developer's disable.
	ShellWrapPostureMaintain ShellWrapPosture = "maintain"
	// ShellWrapPostureRelease: remove a wrap the organization applied.
	ShellWrapPostureRelease ShellWrapPosture = "release"
)

// ShellWrapPostureSource says which rule decided the posture.
type ShellWrapPostureSource string

const (
	// ShellWrapPostureSourceNotManaged: rule 1, not a managed node.
	ShellWrapPostureSourceNotManaged ShellWrapPostureSource = "not_managed"
	// ShellWrapPostureSourceAdminOn: rule 2, the admin turned it on.
	ShellWrapPostureSourceAdminOn ShellWrapPostureSource = "admin_on"
	// ShellWrapPostureSourceAdminOff: rule 3, the admin turned it off.
	ShellWrapPostureSourceAdminOff ShellWrapPostureSource = "admin_off"
	// ShellWrapPostureSourceUnset: rule 4, the admin left it unset.
	ShellWrapPostureSourceUnset ShellWrapPostureSource = "unset"
)

// ShellWrapPostureVerdict is the resolved posture and the rule behind it.
type ShellWrapPostureVerdict struct {
	Posture ShellWrapPosture
	Source  ShellWrapPostureSource
}

type shellWrapPostureInput struct {
	managed bool
	pinned  bool
	value   bool
}

type shellWrapPostureRule struct {
	match   func(in shellWrapPostureInput) bool
	posture ShellWrapPosture
	source  ShellWrapPostureSource
}

var shellWrapPostureRules = []shellWrapPostureRule{
	{func(in shellWrapPostureInput) bool { return !in.managed }, ShellWrapPostureNone, ShellWrapPostureSourceNotManaged},
	{func(in shellWrapPostureInput) bool { return in.pinned && in.value }, ShellWrapPostureMaintain, ShellWrapPostureSourceAdminOn},
	{func(in shellWrapPostureInput) bool { return in.pinned }, ShellWrapPostureRelease, ShellWrapPostureSourceAdminOff},
	{func(shellWrapPostureInput) bool { return true }, ShellWrapPostureNone, ShellWrapPostureSourceUnset},
}

// ShellWrapPosture resolves this node's command-wrapping posture (the rules
// above). A pinned value that is not a bool reads as unset (the vocabulary
// only ever distributes a bool for this key).
func (e Effective) ShellWrapPosture() ShellWrapPostureVerdict {
	in := shellWrapPostureInput{managed: e.Managed && !e.GrantRefused()}
	if v, ok := e.IsPinned(ShellWrapMaintainKey); ok {
		if b, isBool := v.(bool); isBool {
			in.pinned, in.value = true, b
		}
	}
	for _, r := range shellWrapPostureRules {
		if r.match(in) {
			return ShellWrapPostureVerdict{Posture: r.posture, Source: r.source}
		}
	}
	return ShellWrapPostureVerdict{Posture: ShellWrapPostureNone, Source: ShellWrapPostureSourceUnset}
}
