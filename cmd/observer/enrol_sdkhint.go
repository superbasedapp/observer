package main

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sdkcredsvc"
)

// enrol_sdkhint.go: U-26 (Plane A UI review 2026-11-21). Enrolling this
// machine with an organization and getting the member's SDK key are two
// separate steps: the enrolment carries Plane B's push credential, and the
// superbased SDKs need their own key (`observer sdk sign-in`, Settings > AI
// Apps > Get my SDK key) before they can send an app's data online. Nothing
// used to say so, so after `observer enroll` Settings > AI Apps still read
// "not signed in" with no pointer. `observer enroll` and `observer org
// status` now print one line when AI Apps is on and no SDK key is held.

// SR-9 (ship-readiness audit, 2026-11-23): a hosted (pooled) organization
// issues no member SDK keys, so `observer sdk sign-in` fails there with
// "this organization does not offer SDK keys yet". The hint now names that
// command only when the organization said, in its enrol response, that it
// mints member keys (orgcontract.EnrollResponse.SDKKeys); when it said it
// does not, the hint sends the member to an admin; when it did not say (an
// older server, or `observer org status`, which has no enrol response), the
// hint says both. It never decides from the server's host name.

// sdkKeyHintFacts is what the hint reads.
type sdkKeyHintFacts struct {
	// enrolled: this machine is enrolled with an organization (the SDK key
	// is minted by that organization).
	enrolled bool
	// appsOn: [observability] enabled (the AI Apps switch).
	appsOn bool
	// holdsKey: this machine describes an SDK key it holds.
	holdsKey bool
	// sdkKeys: the organization's answer to "does it mint member SDK keys"
	// (orgcontract.SDKKeysMember, SDKKeysAdminOnly, SDKKeysNotOnPlan, or "" when unknown).
	sdkKeys string
}

// sdkKeyHintRule is one row of sdkKeyHintRules.
type sdkKeyHintRule struct {
	name  string
	when  func(f sdkKeyHintFacts) bool
	lines []string
}

// sdkKeyHintRules is the ordered table sdkKeyHintLines walks; the first
// matching row decides, and a row with no lines prints nothing.
var sdkKeyHintRules = []sdkKeyHintRule{
	{name: "not_enrolled", when: func(f sdkKeyHintFacts) bool { return !f.enrolled }},
	{name: "apps_off", when: func(f sdkKeyHintFacts) bool { return !f.appsOn }},
	{name: "has_key", when: func(f sdkKeyHintFacts) bool { return f.holdsKey }},
	{name: "member_keys", when: func(f sdkKeyHintFacts) bool { return f.sdkKeys == orgcontract.SDKKeysMember }, lines: []string{
		"AI Apps: your SDK key is separate from this enrolment. To send your apps' data to this organization,",
		"  run `observer sdk sign-in`, or use Settings > AI Apps > Get my SDK key in the dashboard.",
	}},
	{name: "admin_only", when: func(f sdkKeyHintFacts) bool { return f.sdkKeys == orgcontract.SDKKeysAdminOnly }, lines: []string{
		"AI Apps: this organization does not give members their own SDK keys yet. To send your apps' data to it,",
		"  ask an admin for an SDK key (Machine identities, in the organization's dashboard settings).",
	}},
	{name: "not_on_plan", when: func(f sdkKeyHintFacts) bool { return f.sdkKeys == orgcontract.SDKKeysNotOnPlan }, lines: []string{
		"AI Apps: this organization's plan does not include AI Apps, so no SDK keys are available to its members yet.",
		"  The organization's billing owner can change its plan on the organization's own page in the superbased portal (https://cloud.superbased.app/portal/, then the organization); Plan and usage in the dashboard shows the current plan.",
	}},
	{name: "unknown", when: func(sdkKeyHintFacts) bool { return true }, lines: []string{
		"AI Apps: your SDK key is separate from this enrolment. If your organization gives members their own keys,",
		"  `observer sdk sign-in` gets yours; if it says they are not offered, ask an admin for an SDK key.",
	}},
}

// sdkKeyHintLines returns the lines to print (nil for none).
func sdkKeyHintLines(f sdkKeyHintFacts) []string {
	for _, r := range sdkKeyHintRules {
		if r.when(f) {
			return r.lines
		}
	}
	return nil
}

// sdkKeyHintFactsFor reads the facts for cfg. The key check reads only the
// key's description file (never the key, never a keychain, never the
// network). sdkKeys is the enrol response's answer, "" when none is at hand.
func sdkKeyHintFactsFor(cfg config.Config, enrolled bool, sdkKeys string) sdkKeyHintFacts {
	held := sdkcredsvc.Service{Dir: sdkcredsvc.DefaultDir(filepath.Dir(cfg.Observer.DBPath))}.HoldsKey()
	return sdkKeyHintFacts{enrolled: enrolled, appsOn: cfg.Observability.Enabled, holdsKey: held, sdkKeys: sdkKeys}
}
