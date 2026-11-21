package planechoice

import "strings"

// Choice is a product choice: what the person is here to do. It is the
// vocabulary of the stored choice (Settings > General, firstrunstate Focus)
// and of an arrival intent (a for= link, the connect hand-off,
// `observer apps on`, the installer's --apps).
type Choice string

// The closed choice vocabulary. ChoiceNone means "nothing stored / no
// intent seen".
const (
	ChoiceNone   Choice = ""
	ChoiceCoding Choice = "coding"
	ChoiceApps   Choice = "apps"
	ChoiceBoth   Choice = "both"
)

// choices is the closed table ParseChoice accepts.
var choices = map[string]Choice{
	"coding": ChoiceCoding,
	"apps":   ChoiceApps,
	"both":   ChoiceBoth,
}

// ParseChoice maps s onto the closed vocabulary. Anything else (empty,
// unknown, path-shaped, a different case after trimming) is refused.
func ParseChoice(s string) (Choice, bool) {
	c, ok := choices[strings.TrimSpace(s)]
	return c, ok
}

// Coding reports whether the choice includes AI coding agents.
func (c Choice) Coding() bool { return c == ChoiceCoding || c == ChoiceBoth }

// Apps reports whether the choice includes AI apps you build.
func (c Choice) Apps() bool { return c == ChoiceApps || c == ChoiceBoth }

// IntentSource is where an arrival intent came from.
type IntentSource string

// The closed intent-source vocabulary.
const (
	// SourceForLink: a website or portal link carrying for=.
	SourceForLink IntentSource = "for_link"
	// SourceConnect: the cloud portal's connect hand-off (/?connecting=1).
	SourceConnect IntentSource = "connect"
	// SourceAppsOn: `observer apps on`, the dashboard's AI Apps button or
	// the VS Code action (the one enable seam).
	SourceAppsOn IntentSource = "apps_on"
	// SourceInstaller: the installer's --apps / SBO_CONNECT_APPS.
	SourceInstaller IntentSource = "installer"
)

var intentSources = map[string]IntentSource{
	string(SourceForLink):   SourceForLink,
	string(SourceConnect):   SourceConnect,
	string(SourceAppsOn):    SourceAppsOn,
	string(SourceInstaller): SourceInstaller,
}

// ParseIntentSource maps s onto the closed source vocabulary.
func ParseIntentSource(s string) (IntentSource, bool) {
	src, ok := intentSources[strings.TrimSpace(s)]
	return src, ok
}

// ComponentState is the obs component's state on this machine, the same
// names the AI Apps card reads (componentstate / web planeaFirstRun.ts).
type ComponentState string

// The component states.
const (
	ComponentActive    ComponentState = "active"
	ComponentAvailable ComponentState = "available"
	ComponentAbsent    ComponentState = "absent"
	ComponentBlocked   ComponentState = "blocked"
	ComponentUnknown   ComponentState = "unknown"
)

// Availability is the apps_available capability input and its reason.
type Availability struct {
	Available bool `json:"available"`
	// Reason is a stable code: "" when available, else not_in_build |
	// blocked | unknown.
	Reason string `json:"reason,omitempty"`
	// Text is the sentence a surface shows beside the disabled option.
	Text string `json:"text,omitempty"`
}

// availabilityRules decides apps_available from the component state alone,
// walked top-down. It never reads the edition name or the enrolment.
var availabilityRules = []struct {
	name  string
	when  func(ComponentState) bool
	avail Availability
}{
	{
		name:  "the component is active",
		when:  func(s ComponentState) bool { return s == ComponentActive },
		avail: Availability{Available: true},
	},
	{
		name:  "the component is in this build and can be turned on",
		when:  func(s ComponentState) bool { return s == ComponentAvailable },
		avail: Availability{Available: true},
	},
	{
		name:  "not in this build",
		when:  func(s ComponentState) bool { return s == ComponentAbsent },
		avail: Availability{Reason: "not_in_build", Text: "AI Apps is not part of this edition."},
	},
	{
		name:  "blocked on this machine",
		when:  func(s ComponentState) bool { return s == ComponentBlocked },
		avail: Availability{Reason: "blocked", Text: "AI Apps is blocked on this machine by a rule or your organization."},
	},
	{
		name:  "state not known",
		when:  func(ComponentState) bool { return true },
		avail: Availability{Reason: "unknown", Text: "This process could not read whether AI Apps is available."},
	},
}

// AppsAvailable walks availabilityRules.
func AppsAvailable(state ComponentState) Availability {
	for _, r := range availabilityRules {
		if r.when(state) {
			return r.avail
		}
	}
	return Availability{Reason: "unknown"}
}

// Inputs is everything the two facts are computed from.
type Inputs struct {
	// Stored is the choice the person made (Settings, the row-4 switch);
	// ChoiceNone when they never chose.
	Stored Choice
	// Intent is the first arrival intent seen on this machine.
	Intent Choice
	// CodingHistory: AI coding sessions were captured here.
	CodingHistory bool
	// AppsOn: AI Apps is on in the running daemon.
	AppsOn bool
	// TraceSeen: an app trace has arrived.
	TraceSeen bool
	// AppsAvailable is the capability input (AppsAvailable(...).Available).
	AppsAvailable bool
}

// Facts are the two facts and the row that decided each.
type Facts struct {
	Coding   bool   `json:"coding"`
	CodingBy string `json:"coding_by"`
	Apps     bool   `json:"apps"`
	AppsBy   string `json:"apps_by"`
}

// factRule is one row of a fact table: the first row whose when holds
// decides the fact's value.
type factRule struct {
	name  string
	when  func(Inputs) bool
	value func(Inputs) bool
}

func yes(Inputs) bool { return true }
func no(Inputs) bool  { return false }

// codingRules decides the coding fact. A stored choice is what the person
// chose and wins over inference (an explicit "AI apps" in Settings on a
// machine with coding history means the apps track, not Both; finding
// F1-1). Coding capture is always on, so "coding is on" is not a signal.
var codingRules = []factRule{
	{name: "the stored choice decides", when: func(in Inputs) bool { return in.Stored != ChoiceNone }, value: func(in Inputs) bool { return in.Stored.Coding() }},
	{name: "the arrival intent names coding", when: func(in Inputs) bool { return in.Intent.Coding() }, value: yes},
	{name: "AI coding history found", when: func(in Inputs) bool { return in.CodingHistory }, value: yes},
	{name: "no coding signal", when: yes, value: no},
}

// appsRules decides the apps fact. apps_available false makes it false
// whatever else holds (review P-02). AI Apps being on, or a trace having
// arrived, is a fact about the machine and outranks a stored "coding" (so a
// machine with AI Apps on never gets the false "Add AI Apps" line, P-01).
var appsRules = []factRule{
	{name: "AI Apps is not available here", when: func(in Inputs) bool { return !in.AppsAvailable }, value: no},
	{name: "AI Apps is on", when: func(in Inputs) bool { return in.AppsOn }, value: yes},
	{name: "a trace has arrived", when: func(in Inputs) bool { return in.TraceSeen }, value: yes},
	{name: "the stored choice decides", when: func(in Inputs) bool { return in.Stored != ChoiceNone }, value: func(in Inputs) bool { return in.Stored.Apps() }},
	{name: "the arrival intent names apps", when: func(in Inputs) bool { return in.Intent.Apps() }, value: yes},
	{name: "no apps signal", when: yes, value: no},
}

func walkFact(rules []factRule, in Inputs) (bool, string) {
	for _, r := range rules {
		if r.when(in) {
			return r.value(in), r.name
		}
	}
	return false, ""
}

// Derive computes the two facts.
func Derive(in Inputs) Facts {
	var f Facts
	f.Coding, f.CodingBy = walkFact(codingRules, in)
	f.Apps, f.AppsBy = walkFact(appsRules, in)
	return f
}

// Track is the getting-started track a machine shows.
type Track string

// The tracks.
const (
	TrackCoding Track = "coding"
	TrackApps   Track = "apps"
	TrackBoth   Track = "both"
)

// Rule is one row of the four-row table.
type Rule struct {
	// Row is the plan's row number (1 to 4).
	Row  int
	Name string
	// Coding, Apps: the facts this row matches.
	Coding, Apps bool
	Track        Track
	// Ask: render the coding track with the one-line switch (row 4).
	Ask bool
	// OfferApps: show the one quiet line offering AI Apps (row 3, only when
	// apps_available).
	OfferApps bool
}

// Rules is the four-row table (plan 2.2). Each (coding, apps) pair matches
// exactly one row.
var Rules = []Rule{
	{Row: 1, Name: "coding and apps: both", Coding: true, Apps: true, Track: TrackBoth},
	{Row: 2, Name: "apps only", Coding: false, Apps: true, Track: TrackApps},
	{Row: 3, Name: "coding only", Coding: true, Apps: false, Track: TrackCoding, OfferApps: true},
	{Row: 4, Name: "no signal: coding with the switch", Coding: false, Apps: false, Track: TrackCoding, Ask: true},
}

// Decision is the result of Decide.
type Decision struct {
	Row       int    `json:"row"`
	Rule      string `json:"rule"`
	Track     Track  `json:"track"`
	Ask       bool   `json:"ask"`
	OfferApps bool   `json:"offer_apps"`
	Facts     Facts  `json:"facts"`
}

// Decide derives the facts and maps them through Rules.
func Decide(in Inputs) Decision {
	f := Derive(in)
	for _, r := range Rules {
		if r.Coding == f.Coding && r.Apps == f.Apps {
			return Decision{
				Row: r.Row, Rule: r.Name, Track: r.Track, Ask: r.Ask,
				OfferApps: r.OfferApps && in.AppsAvailable,
				Facts:     f,
			}
		}
	}
	// Unreachable: the four rows cover every pair.
	return Decision{Row: 4, Track: TrackCoding, Ask: true, Facts: f}
}
