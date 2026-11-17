package secassessfixture

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The schema ids of the three answer-key files.
const (
	// TruthSchema is truth/manifest.json.
	TruthSchema = "observer.secassess.fixture-truth.v1"
	// ThreatModelSchema is truth/threatmodel.json.
	ThreatModelSchema = "observer.secassess.fixture-threatmodel-truth.v1"
	// ProbesSchema is truth/probes.json.
	ProbesSchema = "observer.secassess.fixture-probes.v1"
)

// Manifest is truth/manifest.json: the seeded flaws, the decoys and the
// incidental properties of the fixture.
type Manifest struct {
	Schema      string        `json:"schema"`
	Notice      string        `json:"notice"`
	Fixture     FixtureInfo   `json:"fixture"`
	Scoring     Scoring       `json:"scoring"`
	Flaws       []Flaw        `json:"flaws"`
	Decoys      []Decoy       `json:"decoys"`
	Incidental  []Incidental  `json:"incidental"`
	Containment []Containment `json:"containment"`
}

// FixtureInfo describes the application the answer key belongs to.
type FixtureInfo struct {
	Name     string    `json:"name"`
	Language string    `json:"language"`
	AppDir   string    `json:"app_dir"`
	Entry    string    `json:"entry"`
	Files    []string  `json:"files"`
	Target   Target    `json:"target"`
	Accounts []Account `json:"accounts"`
}

// Target is where the application listens and how it is started.
type Target struct {
	Port        int      `json:"port"`
	ConsolePort int      `json:"console_port"`
	StartArgv   []string `json:"start_argv"`
}

// Account is a seed account (labels and placeholder passwords only).
type Account struct {
	Label    string `json:"label"`
	Role     string `json:"role"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Scoring states, in words, how the answer key is matched to a result.
type Scoring struct {
	AnchorWindowLines int    `json:"anchor_window_lines"`
	AnchorRule        string `json:"anchor_rule"`
	MatchRule         string `json:"match_rule"`
	DecoyRule         string `json:"decoy_rule"`
	IncidentalRule    string `json:"incidental_rule"`
	SpacingGuarantee  string `json:"spacing_guarantee"`
}

// Flaw is one seeded weakness.
type Flaw struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Class        string   `json:"class"`
	CWE          []string `json:"cwe"`
	CWEFamily    []string `json:"cwe_family"`
	WSTG         []string `json:"wstg"`
	Route        string   `json:"route"`
	File         string   `json:"file"`
	Anchors      []string `json:"anchors"`
	SeverityHint string   `json:"severity_hint"`
	Description  string   `json:"description"`
	Decoys       []string `json:"decoys"`
	Traps        []string `json:"traps"`
}

// Decoy is a near-miss a careful tester must not report.
type Decoy struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	NearMissOf    string   `json:"near_miss_of"`
	Class         string   `json:"class"`
	Route         string   `json:"route"`
	File          string   `json:"file"`
	Anchors       []string `json:"anchors"`
	WhySafe       string   `json:"why_safe"`
	CWEIfReported []string `json:"cwe_if_reported"`
}

// Incidental is a real property of the fixture that is not seeded.
type Incidental struct {
	ID    string   `json:"id"`
	Title string   `json:"title"`
	CWE   []string `json:"cwe"`
	Note  string   `json:"note"`
}

// Containment is one fence that keeps the fixture harmless.
type Containment struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// ThreatModel is truth/threatmodel.json: what a complete threat model of the
// fixture contains.
type ThreatModel struct {
	Schema              string        `json:"schema"`
	Notice              string        `json:"notice"`
	StrideApplicability Applicability `json:"stride_applicability"`
	Zones               []Zone        `json:"zones"`
	Actors              []Actor       `json:"actors"`
	Components          []Component   `json:"components"`
	Assets              []Asset       `json:"assets"`
	Flows               []Flow        `json:"flows"`
	Threats             []Threat      `json:"threats"`
	Existing            []Mitigation  `json:"existing_mitigations"`
	Traps               []Trap        `json:"traps"`
	MatchRule           string        `json:"match_rule"`
}

// Applicability is the STRIDE-per-element matrix the answer key uses.
type Applicability struct {
	ExternalEntity []string `json:"external_entity"`
	Process        []string `json:"process"`
	DataStore      []string `json:"data_store"`
	DataFlow       []string `json:"data_flow"`
	Note           string   `json:"note"`
}

// Zone is a trust zone.
type Zone struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Actor is an external party.
type Actor struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// Component is a process or data store of the fixture.
type Component struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Zone        string   `json:"zone"`
	File        string   `json:"file"`
	Anchors     []string `json:"anchors"`
	NameHints   []string `json:"name_hints"`
	Description string   `json:"description"`
	HoldsLogs   *bool    `json:"holds_logs,omitempty"`
}

// Asset is something worth protecting.
type Asset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Sensitivity string   `json:"sensitivity"`
	StoredIn    []string `json:"stored_in"`
}

// Flow is a data flow between two elements.
type Flow struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	From         string   `json:"from"`
	To           string   `json:"to"`
	Data         []string `json:"data"`
	Protocol     string   `json:"protocol"`
	Crosses      []string `json:"crosses"`
	PersonalData bool     `json:"personal_data"`
	Encrypted    bool     `json:"encrypted"`
	Anchors      []string `json:"anchors"`
}

// ElementRef names a component, a flow or an actor.
type ElementRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Cell is an element with a STRIDE category id (the closed ids of the module's
// threat model contract: spoofing, tampering, repudiation,
// information_disclosure, denial_of_service, elevation_of_privilege).
type Cell struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Category string `json:"category"`
}

// Threat is one expected threat, keyed by (Element, Category).
type Threat struct {
	ID       string     `json:"id"`
	Flaw     string     `json:"flaw"`
	Title    string     `json:"title"`
	Element  ElementRef `json:"element"`
	Category string     `json:"category"`
	Accept   []Cell     `json:"accept"`
}

// Mitigation is a control that really exists in the fixture (a decoy's).
type Mitigation struct {
	ID       string     `json:"id"`
	Decoy    string     `json:"decoy"`
	Title    string     `json:"title"`
	Element  ElementRef `json:"element"`
	Category string     `json:"category"`
	File     string     `json:"file"`
	Anchors  []string   `json:"anchors"`
	Needle   string     `json:"needle"`
}

// ClaimedFor is the (element, category) a trap's claim would be credited to.
type ClaimedFor struct {
	Element  ElementRef `json:"element"`
	Category string     `json:"category"`
}

// Trap is a claim of a mitigation that does not exist.
type Trap struct {
	ID                             string     `json:"id"`
	Kind                           string     `json:"kind"`
	Flaw                           string     `json:"flaw"`
	File                           string     `json:"file"`
	Anchors                        []string   `json:"anchors"`
	Claim                          string     `json:"claim"`
	ClaimedFor                     ClaimedFor `json:"claimed_for"`
	ExpectedRefState               []string   `json:"expected_ref_state"`
	CountsAsValidatorDefectIfFound bool       `json:"counts_as_validator_defect_if_found"`
	KnownLimit                     bool       `json:"known_limit"`
	Why                            string     `json:"why"`
}

// Probes is truth/probes.json: confirming requests, test-time only.
type Probes struct {
	Schema          string            `json:"schema"`
	Notice          string            `json:"notice"`
	HowToRun        []string          `json:"how_to_run"`
	IndicatorFields map[string]string `json:"indicator_fields"`
	Flaws           []FlawProbe       `json:"flaws"`
	Decoys          []DecoyProbe      `json:"decoys"`
	Containment     []ContainProbe    `json:"containment"`
}

// Request is one HTTP request of a probe. Repeat keeps every response; Times
// sends the request that many times and keeps the last.
type Request struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Jar     string            `json:"jar,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	JSON    json.RawMessage   `json:"json,omitempty"`
	Times   int               `json:"times,omitempty"`
	Repeat  int               `json:"repeat,omitempty"`
}

// CookieIncrement says a numeric part of a cookie rises by Step between
// consecutive responses.
type CookieIncrement struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Step    int    `json:"step"`
}

// Indicator is the test that decides whether a response shows a behaviour.
type Indicator struct {
	Status          int               `json:"status,omitempty"`
	BodyContains    []string          `json:"body_contains,omitempty"`
	BodyNotContains []string          `json:"body_not_contains,omitempty"`
	HeaderPresent   []string          `json:"header_present,omitempty"`
	HeaderAbsent    []string          `json:"header_absent,omitempty"`
	HeaderContains  map[string]string `json:"header_contains,omitempty"`
	SetCookieLacks  []string          `json:"set_cookie_lacks,omitempty"`
	CookieIncrement *CookieIncrement  `json:"cookie_increments,omitempty"`
}

// Confirmation is a control and an attack with the indicator that tells them
// apart: it must hold for the attack and not for the control.
type Confirmation struct {
	Name      string    `json:"name"`
	Setup     []Request `json:"setup,omitempty"`
	Control   Request   `json:"control"`
	Attack    Request   `json:"attack"`
	Indicator Indicator `json:"indicator"`
}

// FlawProbe is the confirmations of one flaw.
type FlawProbe struct {
	ID            string         `json:"id"`
	Confirmations []Confirmation `json:"confirmations"`
}

// Works is the proof a decoy's feature still functions.
type Works struct {
	Request   Request   `json:"request"`
	Indicator Indicator `json:"indicator"`
}

// DecoyProbe is the probe of one decoy: the flaw's indicator must not hold for
// the attack-shaped request, and the feature must still work.
type DecoyProbe struct {
	ID            string    `json:"id"`
	Setup         []Request `json:"setup,omitempty"`
	Attack        Request   `json:"attack"`
	FlawIndicator Indicator `json:"flaw_indicator"`
	Works         Works     `json:"works"`
}

// Check is one request with the expectation that must hold.
type Check struct {
	Request Request   `json:"request"`
	Expect  Indicator `json:"expect"`
}

// ContainProbe is a group of fence checks.
type ContainProbe struct {
	ID     string    `json:"id"`
	Name   string    `json:"name"`
	Setup  []Request `json:"setup"`
	Checks []Check   `json:"checks"`
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the document")
	}
	return nil
}

// ParseManifest decodes truth/manifest.json, refusing an unknown field and a
// wrong schema id.
func ParseManifest(data []byte) (Manifest, error) {
	var m Manifest
	if err := decodeStrict(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("secassessfixture.ParseManifest: %w", err)
	}
	if m.Schema != TruthSchema {
		return Manifest{}, fmt.Errorf("secassessfixture.ParseManifest: schema %q, want %q", m.Schema, TruthSchema)
	}
	return m, nil
}

// ParseThreatModel decodes truth/threatmodel.json, refusing an unknown field
// and a wrong schema id.
func ParseThreatModel(data []byte) (ThreatModel, error) {
	var t ThreatModel
	if err := decodeStrict(data, &t); err != nil {
		return ThreatModel{}, fmt.Errorf("secassessfixture.ParseThreatModel: %w", err)
	}
	if t.Schema != ThreatModelSchema {
		return ThreatModel{}, fmt.Errorf("secassessfixture.ParseThreatModel: schema %q, want %q", t.Schema, ThreatModelSchema)
	}
	return t, nil
}

// ParseProbes decodes truth/probes.json, refusing an unknown field and a
// wrong schema id.
func ParseProbes(data []byte) (Probes, error) {
	var p Probes
	if err := decodeStrict(data, &p); err != nil {
		return Probes{}, fmt.Errorf("secassessfixture.ParseProbes: %w", err)
	}
	if p.Schema != ProbesSchema {
		return Probes{}, fmt.Errorf("secassessfixture.ParseProbes: schema %q, want %q", p.Schema, ProbesSchema)
	}
	return p, nil
}

// LineOf returns the 1-based line of the one place the anchor occurs in src.
// An anchor that is absent or occurs more than once is an error: an anchor is
// a unique code substring.
func LineOf(src []byte, anchor string) (int, error) {
	if anchor == "" {
		return 0, errors.New("secassessfixture.LineOf: empty anchor")
	}
	text := string(src)
	at := strings.Index(text, anchor)
	if at < 0 {
		return 0, fmt.Errorf("secassessfixture.LineOf: anchor %q not found", anchor)
	}
	if n := strings.Count(text, anchor); n > 1 {
		return 0, fmt.Errorf("secassessfixture.LineOf: anchor %q occurs %d times", anchor, n)
	}
	return 1 + strings.Count(text[:at], "\n"), nil
}

// LineText returns the text of the 1-based line, without its line break.
func LineText(src []byte, line int) string {
	lines := strings.Split(string(src), "\n")
	if line < 1 || line > len(lines) {
		return ""
	}
	return strings.TrimRight(lines[line-1], "\r")
}

// IsCommentLine reports whether the whole line is a Python comment.
func IsCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

// Response is what an indicator is evaluated on. Header names are matched
// case-insensitively.
type Response struct {
	Status int
	Header map[string][]string
	Body   string
}

func (r Response) values(name string) []string {
	var out []string
	for k, vs := range r.Header {
		if strings.EqualFold(k, name) {
			out = append(out, vs...)
		}
	}
	return out
}

// Holds reports whether the indicator holds for the responses (the last one is
// judged; a cookie_increments condition looks at all of them) and, when it
// does not, the first condition that failed.
func (in Indicator) Holds(responses []Response) (bool, string) {
	if len(responses) == 0 {
		return false, "no response"
	}
	r := responses[len(responses)-1]
	if in.Status != 0 && r.Status != in.Status {
		return false, fmt.Sprintf("status %d, want %d", r.Status, in.Status)
	}
	for _, s := range in.BodyContains {
		if !strings.Contains(r.Body, s) {
			return false, fmt.Sprintf("body lacks %q", s)
		}
	}
	for _, s := range in.BodyNotContains {
		if strings.Contains(r.Body, s) {
			return false, fmt.Sprintf("body contains %q", s)
		}
	}
	for _, h := range in.HeaderPresent {
		if len(r.values(h)) == 0 {
			return false, fmt.Sprintf("header %s absent", h)
		}
	}
	for _, h := range in.HeaderAbsent {
		if len(r.values(h)) != 0 {
			return false, fmt.Sprintf("header %s present", h)
		}
	}
	for h, want := range in.HeaderContains {
		found := false
		for _, v := range r.values(h) {
			if strings.Contains(v, want) {
				found = true
			}
		}
		if !found {
			return false, fmt.Sprintf("header %s lacks %q", h, want)
		}
	}
	for _, attr := range in.SetCookieLacks {
		for _, v := range r.values("Set-Cookie") {
			if strings.Contains(strings.ToLower(v), strings.ToLower(attr)) {
				return false, fmt.Sprintf("a Set-Cookie value carries %s", attr)
			}
		}
	}
	if in.CookieIncrement != nil {
		if ok, why := in.CookieIncrement.holds(responses); !ok {
			return false, why
		}
	}
	return true, ""
}

func (c CookieIncrement) holds(responses []Response) (bool, string) {
	if len(responses) < 2 {
		return false, "cookie_increments needs at least two responses"
	}
	re, err := regexp.Compile(c.Pattern)
	if err != nil {
		return false, "cookie_increments pattern: " + err.Error()
	}
	prev := 0
	for i, r := range responses {
		n, ok := cookieNumber(r, c.Name, re)
		if !ok {
			return false, fmt.Sprintf("response %d carries no numeric %s cookie", i+1, c.Name)
		}
		if i > 0 && n-prev != c.Step {
			return false, fmt.Sprintf("cookie %s went %d to %d, want a step of %d", c.Name, prev, n, c.Step)
		}
		prev = n
	}
	return true, ""
}

func cookieNumber(r Response, name string, re *regexp.Regexp) (int, bool) {
	for _, v := range r.values("Set-Cookie") {
		first, _, _ := strings.Cut(v, ";")
		k, val, ok := strings.Cut(strings.TrimSpace(first), "=")
		if !ok || k != name {
			continue
		}
		m := re.FindStringSubmatch(val)
		if len(m) < 2 {
			continue
		}
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n, true
		}
	}
	return 0, false
}

// ExpandPlaceholders replaces {port} and {console_port} in s.
func ExpandPlaceholders(s string, port, consolePort int) string {
	s = strings.ReplaceAll(s, "{console_port}", strconv.Itoa(consolePort))
	return strings.ReplaceAll(s, "{port}", strconv.Itoa(port))
}

// Categories returns the STRIDE category ids that apply to an element type
// ("external_entity", "process", "data_store", "data_flow"); a data store
// that holds no logs does not take repudiation.
func (a Applicability) Categories(elementType string, holdsLogs bool) []string {
	var src []string
	switch elementType {
	case "external_entity":
		src = a.ExternalEntity
	case "process":
		src = a.Process
	case "data_store":
		src = a.DataStore
	case "data_flow":
		src = a.DataFlow
	}
	out := make([]string, 0, len(src))
	for _, c := range src {
		if c == "repudiation" && elementType == "data_store" && !holdsLogs {
			continue
		}
		out = append(out, c)
	}
	return out
}
