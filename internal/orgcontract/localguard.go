package orgcontract

import "sort"

// The managed-node prompt-guard floor, shared by the node and the server
// (T-864, guard tamper re-test 2026-10-16 gaps 2 and 3).
//
// One owner for two facts both sides must agree on:
//
//   - LocalGuardPromptFloor: the weakest global [guard.prompt].mode a managed
//     node may run. The node's config floor (internal/guardposture) raises a
//     weaker local mode to it, and LocalGuardWeakenings reports a weaker local
//     mode as an attempt.
//   - the SHIPPED default mode of every prompt detector
//     (LocalGuardDefaultDetectorModes). internal/config seeds its
//     [guard.prompt.detectors] defaults from this table, so a node and the
//     server read the same defaults. A detector the default set ships "off"
//     (email, the phone numbers: too noisy to interrupt on) is not a
//     weakening when it is off; before this table the server judged every
//     detector against "redact", so an untouched node with the default set
//     opened a false local_weakening finding.

// LocalGuardPromptFloor is the weakest global prompt mode a managed node may
// run: "off" and "warn" never block or ask.
const LocalGuardPromptFloor = "redact"

// localGuardDefaultDetectorModes is the shipped [guard.prompt.detectors]
// default set (the prompt-submit intervention's reconsider-once posture:
// certain PII asks once, a GitHub token blocks, email and phone numbers are
// off). Read it through LocalGuardDefaultDetectorModes, which copies.
var localGuardDefaultDetectorModes = map[string]string{
	"credit_card": "ask-once",
	"iban":        "ask-once",
	"us_ssn":      "ask-once",
	"uk_nino":     "ask-once",
	"in_aadhaar":  "ask-once",
	"in_pan":      "ask-once",
	"email":       "off",
	"phone_e164":  "off",
	"phone_nanp":  "off",
	"github_pat":  "block",
}

// LocalGuardDefaultDetectorModes returns a fresh copy of the shipped
// per-detector prompt modes.
func LocalGuardDefaultDetectorModes() map[string]string {
	out := make(map[string]string, len(localGuardDefaultDetectorModes))
	for k, v := range localGuardDefaultDetectorModes {
		out[k] = v
	}
	return out
}

// LocalGuardDetectorFloor is the weakest effective mode detector id may run
// on a managed node: the lower of LocalGuardPromptFloor and the detector's
// shipped default. A detector the default set does not name falls under the
// global prompt mode, so its floor is LocalGuardPromptFloor.
func LocalGuardDetectorFloor(id string) string {
	def, ok := localGuardDefaultDetectorModes[id]
	if !ok || localGuardPromptRank[def] >= localGuardPromptRank[LocalGuardPromptFloor] {
		return LocalGuardPromptFloor
	}
	return def
}

// LocalGuardWeakDetectors returns, sorted, the prompt detector ids whose
// effective mode in p sits below their own floor (LocalGuardDetectorFloor):
// the detectors behind a LocalGuardKeyDetectors weakening (T-888), so the
// organization can name each one rather than the group. The ids are the
// node's closed detector ids (the server checks their shape before storing
// them). A nil p yields nil.
func LocalGuardWeakDetectors(p *LocalGuardPosture) []string {
	if p == nil {
		return nil
	}
	var out []string
	for id, m := range p.DetectorModes {
		if localGuardPromptRank[m] < localGuardPromptRank[LocalGuardDetectorFloor(id)] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// LocalGuardPromptModeBelow reports whether prompt mode m is weaker than
// floor (an unknown m counts as off, the fail-closed reading).
func LocalGuardPromptModeBelow(m, floor string) bool {
	f, ok := localGuardPromptRank[floor]
	if !ok {
		return false
	}
	return localGuardPromptRank[m] < f
}
