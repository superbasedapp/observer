package secassess

import "strings"

// The structured result an assessment agent writes into its run directory,
// and the checked copy Observer keeps. The agent writes assessment.json in one
// of two schemas; Validate reads it, drops what it cannot trust, computes what
// it must not take from the file (the band, the reference states), and returns
// the same types filled in.
//
// A field tagged computed:"true" is Observer's: a value for it in the file is
// ignored and counted, never read. The closed enums behind the fields live in
// vocab_*.go.

// Contract names the result-file contract of a kind.
type Contract string

// The contracts. A run recorded before the depth work has no contract and
// reads as ContractSARIF.
const (
	ContractSARIF       Contract = "sarif"
	ContractThreatModel Contract = "threatmodel.v1"
	ContractPentest     Contract = "pentest.v1"
	// ContractRetest is the contract of a retest of an earlier penetration test
	// (depth plan W7.2): labels per finding, nothing closed.
	ContractRetest Contract = "retest.v1"
)

// The schema ids written in an assessment.json.
const (
	SchemaThreatModel = "observer.threatmodel.v1"
	SchemaPentest     = "observer.pentest.v1"
	SchemaRetest      = "observer.retest.v1"
)

// ModelContracts is the table of the contracts that have a model file, each with
// the schema id its assessment.json names, in the order the tasks ask for them.
// A red team run writes the pen test's contract. Everything that has to go from
// a contract to its schema, or from a file's schema to its contract, reads this
// table (Contract.Schema, ContractOfSchema, the self-check command), so a new
// contract is one row.
var ModelContracts = []struct {
	Contract Contract
	Schema   string
}{
	{ContractThreatModel, SchemaThreatModel},
	{ContractPentest, SchemaPentest},
	{ContractRetest, SchemaRetest},
}

// Schema returns the schema id of a model contract, "" for any other.
func (c Contract) Schema() string {
	for _, m := range ModelContracts {
		if m.Contract == c {
			return m.Schema
		}
	}
	return ""
}

// ContractOfSchema returns the model contract whose file names the schema id s.
func ContractOfSchema(s string) (Contract, bool) {
	for _, m := range ModelContracts {
		if m.Schema == s {
			return m.Contract, true
		}
	}
	return "", false
}

// RefState is what Observer found when it looked at a reference. Only
// RefFound earns the label "found near the cited line" (the needle is on a code
// line within the match window of the first cited line); RefExists is "location
// exists, nothing matched near the cited line" and earns no credit.
type RefState string

// The reference states.
const (
	// RefFound: the location exists and the needle is on a code line in the
	// cited range.
	RefFound RefState = "found"
	// RefExists: the location exists; there was no usable needle to match.
	RefExists RefState = "exists"
	// RefClaimedNotFound: the location exists and a usable needle is not in
	// the cited range.
	RefClaimedNotFound RefState = "claimed_not_found"
	// RefMissing: no such file, not a regular file inside the project, or the
	// cited line is past the end of it.
	RefMissing RefState = "missing"
	// RefInvalid: the reference itself is malformed (a path that is not
	// project-relative, a backwards or oversized range).
	RefInvalid RefState = "invalid"
	// RefUnchecked: the look was not made (no checker, or its read budget was
	// used up).
	RefUnchecked RefState = "unchecked"
)

// Located reports whether a state names a location that exists.
func (s RefState) Located() bool { return s == RefFound || s == RefExists }

// Ref points at a place in the project. Path is project-relative with forward
// slashes.
type Ref struct {
	Path    string `json:"path"`
	Line    int    `json:"line,omitempty"`
	EndLine int    `json:"end_line,omitempty"`
	// Needle is a short piece of the code at the cited line. It is how a
	// reference earns RefFound.
	Needle string `json:"needle,omitempty"`
	// State is Observer's finding about the reference.
	State RefState `json:"state,omitempty" computed:"true"`
	// MatchLine is the line the needle was found on, set with RefFound only. It
	// is computed, never read from the file: credit and every "found" label
	// belong to this line, not to the cited range.
	MatchLine int `json:"match_line,omitempty" computed:"true"`
}

// Rating is the agent's likelihood and impact, each 1 to 5. The band is
// computed from them, never read.
type Rating struct {
	Likelihood int `json:"likelihood"`
	Impact     int `json:"impact"`
}

// Generator says which tool wrote the file.
type Generator struct {
	Tool  string `json:"tool,omitempty"`
	Model string `json:"model,omitempty"`
}

// ---- threat model (observer.threatmodel.v1) ----

// ThreatModelDoc is a threat model.
type ThreatModelDoc struct {
	Schema        string     `json:"schema"`
	RunID         string     `json:"run_id"`
	PromptVersion string     `json:"prompt_version,omitempty"`
	Generator     Generator  `json:"generator"`
	Summary       string     `json:"summary,omitempty"`
	Scope         Scope      `json:"scope"`
	System        System     `json:"system"`
	Threats       []Threat   `json:"threats,omitempty"`
	NoThreat      []NoThreat `json:"no_threat,omitempty"`
	AttackTrees   []Tree     `json:"attack_trees,omitempty"`
	OpenQuestions []string   `json:"open_questions,omitempty" lone:"list"`
	Limits        []string   `json:"limits,omitempty" lone:"list"`
}

// Scope says what the model covers.
type Scope struct {
	InScope     []string `json:"in_scope,omitempty" lone:"list"`
	OutOfScope  []string `json:"out_of_scope,omitempty" lone:"list"`
	Assumptions []string `json:"assumptions,omitempty" lone:"list"`
}

// System is the decomposition: what the application is made of.
type System struct {
	Components  []Component  `json:"components,omitempty"`
	Zones       []Zone       `json:"zones,omitempty"`
	Actors      []Actor      `json:"actors,omitempty"`
	Assets      []Asset      `json:"assets,omitempty"`
	EntryPoints []EntryPoint `json:"entry_points,omitempty"`
	Flows       []Flow       `json:"flows,omitempty"`
}

// Component is a part of the application (see ComponentTypes).
type Component struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Paths       []Ref    `json:"paths,omitempty" lone:"list"`
	Tech        []string `json:"tech,omitempty" lone:"list"`
	Zone        string   `json:"zone,omitempty"`
}

// Zone is a trust zone: a set of components that trust each other equally.
type Zone struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Actor is someone or something outside the application that uses it or
// attacks it.
type Actor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Asset is something worth protecting.
type Asset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Sensitivity string   `json:"sensitivity"`
	DataClasses []string `json:"data_classes,omitempty" lone:"list"`
	StoredIn    []string `json:"stored_in,omitempty" lone:"list"`
}

// EntryPoint is a way into a component.
type EntryPoint struct {
	ID        string `json:"id"`
	Component string `json:"component"`
	Kind      string `json:"kind"`
	Ref       *Ref   `json:"ref,omitempty"`
	Authn     string `json:"authn,omitempty"`
	Exposure  string `json:"exposure,omitempty"`
}

// Flow is data moving between two components, or between an actor and a
// component.
type Flow struct {
	ID           string   `json:"id"`
	From         string   `json:"from"`
	To           string   `json:"to"`
	Data         []string `json:"data,omitempty" lone:"list"`
	Protocol     string   `json:"protocol,omitempty"`
	Crosses      []string `json:"crosses,omitempty" lone:"list"`
	Authn        string   `json:"authn,omitempty"`
	Encrypted    string   `json:"encrypted,omitempty"`
	PersonalData bool     `json:"personal_data,omitempty"`
}

// Element names the thing a threat is about.
type Element struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Mitigation is a control the agent says is already in the code.
type Mitigation struct {
	Text string `json:"text"`
	Refs []Ref  `json:"refs,omitempty" lone:"list"`
}

// Missing is a control the agent says the project lacks.
type Missing struct {
	Text    string `json:"text"`
	Control string `json:"control,omitempty"`
	Effort  string `json:"effort,omitempty"`
	Refs    []Ref  `json:"refs,omitempty" lone:"list"`
}

// AbuseCase is an attacker's story for a threat.
type AbuseCase struct {
	Actor string   `json:"actor,omitempty"`
	Goal  string   `json:"goal"`
	Steps []string `json:"steps,omitempty" lone:"list"`
}

// Threat is one threat to one element.
type Threat struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Framework   string       `json:"framework"`
	Category    string       `json:"category"`
	Element     Element      `json:"element"`
	Actor       string       `json:"actor,omitempty"`
	Description string       `json:"description,omitempty"`
	Rating      Rating       `json:"rating"`
	Existing    []Mitigation `json:"existing,omitempty"`
	Missing     []Missing    `json:"missing,omitempty"`
	CWE         []string     `json:"cwe,omitempty" lone:"list"`
	CAPEC       []string     `json:"capec,omitempty" lone:"list"`
	ASVS        []string     `json:"asvs,omitempty" lone:"list"`
	Status      string       `json:"status,omitempty"`
	AbuseCase   *AbuseCase   `json:"abuse_case,omitempty"`
	// Band and Score are computed from the rating.
	Band  Band `json:"band,omitempty" computed:"true"`
	Score int  `json:"score,omitempty" computed:"true"`
}

// NoThreat says an element was considered under a category and no threat was
// found. It counts as "waived", not as "analysed".
type NoThreat struct {
	Element  Element `json:"element"`
	Category string  `json:"category"`
	Reason   string  `json:"reason"`
}

// Tree is an attack tree: a goal and the steps that lead to it.
type Tree struct {
	Root  string     `json:"root"`
	Nodes []TreeNode `json:"nodes,omitempty"`
}

// TreeNode is one step of an attack tree. Parent is the id of another node in
// the tree, or empty for a child of the root.
type TreeNode struct {
	ID     string `json:"id"`
	Parent string `json:"parent,omitempty"`
	Label  string `json:"label"`
	Op     string `json:"op,omitempty"`
	Leaf   bool   `json:"leaf,omitempty"`
}

// ---- penetration test (observer.pentest.v1) ----

// PentestDoc is a penetration test or red team result.
type PentestDoc struct {
	Schema        string            `json:"schema"`
	RunID         string            `json:"run_id"`
	PromptVersion string            `json:"prompt_version,omitempty"`
	Generator     Generator         `json:"generator"`
	Summary       string            `json:"summary,omitempty"`
	Target        PTTarget          `json:"target"`
	Method        PTMethod          `json:"method"`
	Coverage      []PTCoverageClaim `json:"coverage,omitempty"`
	Findings      []PTFinding       `json:"findings,omitempty"`
	// Exercise is a red team run's objective and the chain of steps it took
	// (depth plan W7.3); a penetration test has none.
	Exercise *PTExercise `json:"exercise,omitempty"`
	Limits   []string    `json:"limits,omitempty" lone:"list"`
}

// PTExercise is a red team run's account of the exercise: the objective it
// worked towards and the chain of steps that led to it, in order. Observer
// renders its narrative from this structure; the agent's report is not used.
type PTExercise struct {
	// Objective is the developer's own words when they gave one (cleaned, at
	// most MaxObjective characters), else the agent's own, cleaned the same way.
	Objective string `json:"objective,omitempty"`
	// ObjectiveBy says whose words Objective is: ObjectiveByDeveloper or
	// ObjectiveByAgent. It is Observer's: a value in the file is ignored.
	ObjectiveBy string        `json:"objective_by,omitempty" computed:"true"`
	Chain       []PTChainStep `json:"chain,omitempty"`
}

// The owners of an exercise's objective.
const (
	ObjectiveByDeveloper = "developer"
	ObjectiveByAgent     = "agent"
)

// PTChainStep is one step of an exercise's chain.
type PTChainStep struct {
	// Step says what was done, in the agent's words.
	Step string `json:"step"`
	// Finding is the id of the finding the step used or produced ("" for a step
	// that is not a finding, such as reconnaissance).
	Finding string `json:"finding,omitempty"`
	// Result is how the step went (EnumChainResult).
	Result string `json:"result"`
	// Stop is what would have detected or stopped the step: the agent's opinion,
	// and shown as one.
	Stop string `json:"stop,omitempty"`
}

// PTTarget is what was tested and how it was started.
type PTTarget struct {
	URL      string      `json:"url,omitempty"`
	Start    PTStart     `json:"start"`
	Accounts []PTAccount `json:"accounts,omitempty"`
}

// PTStart says how the agent started the target. Started is the agent's
// claim.
type PTStart struct {
	Argv           []string `json:"argv,omitempty"`
	Source         string   `json:"source,omitempty"`
	Started        bool     `json:"started"`
	StartupSeconds int      `json:"startup_seconds,omitempty"`
	Health         PTHealth `json:"health"`
}

// PTHealth is the health check the agent used.
type PTHealth struct {
	Path   string `json:"path,omitempty"`
	Status int    `json:"status,omitempty"`
}

// PTAccount is a test account, by label only; a value is never accepted.
type PTAccount struct {
	Label string `json:"label"`
	Role  string `json:"role,omitempty"`
}

// PTMethod names the method followed.
type PTMethod struct {
	Standard string `json:"standard,omitempty"`
}

// PTCoverageClaim is the agent's account of one test category.
type PTCoverageClaim struct {
	Category string   `json:"category"`
	Status   string   `json:"status"`
	Reason   string   `json:"reason,omitempty"`
	Probes   []string `json:"probes,omitempty" lone:"list"`
	Notes    string   `json:"notes,omitempty"`
}

// PTWhere is where in the code a finding comes from.
type PTWhere struct {
	Refs []Ref `json:"refs,omitempty" lone:"list"`
}

// PTHeader is one HTTP header of a reproduction request, or one header
// condition of an indicator (Value is then a text the header's value contains).
type PTHeader struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// PTMatch is the response condition of an indicator: what holds for the attack
// request's logged response and does not hold for the control request's. Every
// part that is set must hold; an empty condition holds for nothing (it says
// nothing). The parts are checked against the log's stored response: its status,
// its headers and the first kilobyte of its body (the excerpt), so a condition
// on text further into the body cannot hold.
type PTMatch struct {
	// Status is the response status the logged response must have (0: any).
	Status int `json:"status,omitempty"`
	// BodyContains and BodyNotContains are texts the body excerpt must and must
	// not contain (case-sensitive).
	BodyContains    []string `json:"body_contains,omitempty"`
	BodyNotContains []string `json:"body_not_contains,omitempty"`
	// HeaderPresent and HeaderAbsent are header names that must and must not be
	// among the response headers (case-insensitive names).
	HeaderPresent []string `json:"header_present,omitempty"`
	HeaderAbsent  []string `json:"header_absent,omitempty"`
	// HeaderContains names a header and a text one of its values must contain
	// (case-insensitive).
	HeaderContains []PTHeader `json:"header_contains,omitempty"`

	// Unread names the part of the value that could not be read (lenient.go).
	Unread string `json:"-" computed:"true"`
}

// Empty reports whether the condition sets nothing.
func (m PTMatch) Empty() bool {
	return m.Status == 0 && len(m.BodyContains) == 0 && len(m.BodyNotContains) == 0 &&
		len(m.HeaderPresent) == 0 && len(m.HeaderAbsent) == 0 && len(m.HeaderContains) == 0
}

// PTIndicator names the two requests a finding rests on, the attack and a
// control that should differ, and the response condition that tells them apart.
// Probe ids only: the requests themselves are in the helper's log.
type PTIndicator struct {
	Control string   `json:"control,omitempty"`
	Attack  string   `json:"attack,omitempty"`
	When    *PTMatch `json:"when,omitempty"`

	// Unread names the part of the value that could not be read (lenient.go).
	Unread string `json:"-" computed:"true"`
}

// PTRequest is one reproduction request in structured form, so a developer can
// send it again: a method from a closed list, a path and query in a restricted
// character set, a few headers from an allow-list and a short body. A header
// that carries a credential keeps its name and loses its value.
type PTRequest struct {
	Method  string     `json:"method"`
	Path    string     `json:"path"`
	Headers []PTHeader `json:"headers,omitempty"`
	Body    string     `json:"body,omitempty"`

	// Unread names the part of the value that could not be read (lenient.go);
	// the validator turns it into an issue. It is Observer's own, never read
	// from or written to a file.
	Unread string `json:"-" computed:"true"`
}

// parseRequestLine splits "METHOD /path rest" into its parts; the method is
// not checked here (V5 does).
func parseRequestLine(line string) PTRequest {
	f := strings.Fields(line)
	if len(f) < 2 || !strings.HasPrefix(f[1], "/") {
		return PTRequest{}
	}
	req := PTRequest{Method: strings.ToUpper(f[0]), Path: f[1]}
	rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), f[0]))
	rest = strings.TrimSpace(strings.TrimPrefix(rest, f[1]))
	req.Body = rest
	return req
}

// PTRepro is one reproduction step.
type PTRepro struct {
	Step    string     `json:"step"`
	Request *PTRequest `json:"request,omitempty"`
}

// PTFinding is one weakness the agent reports. Basis is the agent's claim of
// how it knows; Observer separately computes the evidence it can check.
type PTFinding struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Category string   `json:"category"`
	CWE      []string `json:"cwe,omitempty" lone:"list"`
	Rating   Rating   `json:"rating"`
	// CVSS is the agent's optional CVSS 4.0 base vector for the weakness as it
	// behaved in the in-box copy. Observer parses it strictly (cvss4.Parse) and
	// leaves it out when it is not a base vector; the score and band that go
	// with it (CVSSScore, CVSSBand) are Observer's own, never read from the file.
	CVSS         string       `json:"cvss,omitempty"`
	Basis        string       `json:"basis"`
	Where        PTWhere      `json:"where"`
	Route        string       `json:"route,omitempty"`
	Indicator    *PTIndicator `json:"indicator,omitempty"`
	Evidence     []string     `json:"evidence,omitempty" lone:"list"`
	Reproduction []PTRepro    `json:"reproduction,omitempty"`
	Impact       string       `json:"impact,omitempty"`
	Fix          string       `json:"fix,omitempty"`
	Status       string       `json:"status,omitempty"`
	// Band and Score are computed from the rating.
	Band  Band `json:"band,omitempty" computed:"true"`
	Score int  `json:"score,omitempty" computed:"true"`
	// CVSSScore is the CVSS 4.0 base score of CVSS (0.0 to 10.0) and CVSSBand
	// its rating as a band, empty for a score of 0.0, which has none. They are
	// set only for a valid vector and never read from the file. A score of 0.0
	// is a score, so CVSSScore is a pointer that omitempty does not drop.
	CVSSScore *float64 `json:"cvss_score,omitempty" computed:"true"`
	CVSSBand  Band     `json:"cvss_band,omitempty" computed:"true"`
	// EvidenceState and EvidenceReason are Observer's reading of whether the
	// request helper's log backs the finding (row V14). They are computed, never
	// read from the file: the agent's own claim is Basis.
	EvidenceState  EvidenceState `json:"evidence_state,omitempty" computed:"true"`
	EvidenceReason string        `json:"evidence_reason,omitempty" computed:"true"`
}
