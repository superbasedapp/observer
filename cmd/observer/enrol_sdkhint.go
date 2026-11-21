package main

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/config"
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

// sdkKeyHintFacts is what the hint reads.
type sdkKeyHintFacts struct {
	// enrolled: this machine is enrolled with an organization (the SDK key
	// is minted by that organization).
	enrolled bool
	// appsOn: [observability] enabled (the AI Apps switch).
	appsOn bool
	// holdsKey: this machine describes an SDK key it holds.
	holdsKey bool
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
	{name: "needs_key", when: func(sdkKeyHintFacts) bool { return true }, lines: []string{
		"AI Apps: your SDK key is separate from this enrolment. To send your apps' data to this organization,",
		"  run `observer sdk sign-in`, or use Settings > AI Apps > Get my SDK key in the dashboard.",
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
// network).
func sdkKeyHintFactsFor(cfg config.Config, enrolled bool) sdkKeyHintFacts {
	held := sdkcredsvc.Service{Dir: sdkcredsvc.DefaultDir(filepath.Dir(cfg.Observer.DBPath))}.HoldsKey()
	return sdkKeyHintFacts{enrolled: enrolled, appsOn: cfg.Observability.Enabled, holdsKey: held}
}
