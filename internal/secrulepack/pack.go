package secrulepack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/seccorpus"
)

// The format's fixed names.
const (
	// Schema is the only pack manifest schema.
	Schema = "sbo.code-rule-pack.v1"
	// PackID is the id of Observer's own Opengrep pack. It is distinct
	// from the native guard rule pack (internal/secrules).
	PackID = "observer-code"
	// ManifestFile is the manifest's path inside a pack.
	ManifestFile = "pack.json"
	// RulesDir holds one YAML file per rule; the driver passes it to
	// Opengrep as its only --config.
	RulesDir = "rules"
	// CanaryDir holds the canary target, scanned beside the project.
	CanaryDir = "canary"
)

// Caps. A pack over any of them is refused.
const (
	MaxFiles      = 300
	MaxRules      = 256
	MaxRuleBytes  = 64 << 10
	MaxPackBytes  = 2 << 20
	MaxIDBytes    = 96
	MaxTextBytes  = 400
	maxRegexBytes = 512
)

// BlockingLowerBound is the precision bar (PR7): a rule may count toward
// the commit gate's S-791 only when the Wilson 95 percent lower bound of
// its precision on the labelled corpus is at least this, and the operator's
// spot-check of the reviewers' labels is recorded with no overturned true
// positive (P-047).
const BlockingLowerBound = 0.8

// NoisyFloor is the precision under which a rule is noisy: it is listed as
// such (docs/code-rules-precision.md), kept flag-only, and dropped from the
// pack at its next revision unless it is rewritten and re-measured.
const NoisyFloor = 0.5

// MinSpotcheckSample is the smallest spot-check a blocking rule needs: this
// many of its labelled results answered, or, when fewer of its results were
// labelled true by both reviewers, that many (Precision.MinSpotcheck).
const MinSpotcheckSample = seccorpus.MinSpotcheckSample

// The spot-checker identities (ruling P-064): the operator, or an
// independent AI reviewer named "agent:<id>" that labelled none of the
// corpus. The record step refuses a labeller's id.
const (
	SpotcheckerOperator    = "operator"
	SpotcheckerAgentPrefix = "agent:"
)

// ValidSpotchecker reports whether s names a spot-checker: "operator", or
// "agent:" and an id of 1 to 128 letters, digits, dot, dash and underscore.
func ValidSpotchecker(s string) bool {
	if s == SpotcheckerOperator {
		return true
	}
	id, ok := strings.CutPrefix(s, SpotcheckerAgentPrefix)
	if !ok || id == "" || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Precision is a rule's measured precision on a labelled corpus (JSP-8's
// method: a fixed corpus by commit, every result a rule produces is its
// denominator, a stratified sample labelled by two reviewers).
type Precision struct {
	// Figure is the labelled precision (true positives over labelled
	// results), 0 to 1.
	Figure float64 `json:"figure"`
	// WilsonLower is the Wilson 95 percent interval's lower bound.
	WilsonLower float64 `json:"wilson_lower"`
	// Denominator is how many results were labelled.
	Denominator int `json:"denominator"`
	// Corpus names the corpus and its commit set.
	Corpus string `json:"corpus"`
	// Method names the labelling method.
	Method string `json:"method"`
	// Results is every result the rule produced on the corpus after the
	// ecosystem exclusions; 0 when not recorded. It is at least
	// Denominator (equal when every result was labelled). A rule may block
	// only when it is recorded and equal (FullyLabelled).
	Results int `json:"results,omitempty"`
	// ReviewerDisagreements counts labelled results the two reviewers
	// labelled differently (each counts against the rule).
	ReviewerDisagreements int `json:"reviewer_disagreements,omitempty"`
	// Kappa is Cohen's kappa of the two reviewers on this rule; nil when
	// it has no value (both gave one verdict throughout) and nil when the
	// measurement is one effective pass (Passes.OneEffectivePass): a kappa
	// of two passes not shown independent is not inter-rater agreement.
	Kappa *float64 `json:"kappa,omitempty"`
	// Passes is how the two labelling passes of the whole measurement
	// agreed; nil in a pack measured before it was recorded.
	Passes *Passes `json:"passes,omitempty"`
}

// MinUnanimousResults is the measurement size from which two labelling
// passes agreeing on every verdict and every reason code are not credible
// as independent (lane SEC-G4 audit finding 1: 97 of 97 on both, where the
// same rubric gave 91 percent reason agreement in SEC-G3).
const MinUnanimousResults = 20

// Passes is the agreement of the two labelling passes over the whole
// measurement a figure comes from (every rule's labelled results, not only
// this rule's), recorded by the measure step.
type Passes struct {
	// Results is how many results both passes labelled.
	Results int `json:"results"`
	// VerdictAgreements counts results given the same verdict.
	VerdictAgreements int `json:"verdict_agreements"`
	// ReasonAgreements counts results given the same reason code (a reason
	// code belongs to one verdict, so it is at most VerdictAgreements).
	ReasonAgreements int `json:"reason_agreements"`
	// SecondPassAttestedIsolated is true only when the batch manifest marks
	// every second-pass (side b) batch attested-isolated, a field the
	// labelling harness sets, never a labeller. Nothing sets it yet.
	SecondPassAttestedIsolated bool `json:"second_pass_attested_isolated,omitempty"`
	// SecondPassPending counts labelled results with no second-pass label
	// yet (the side-b batches are prepared and await their relabel, lane
	// SEC-G5); they are counted on the first pass alone and are not in
	// Results. Any pending result makes the measurement one effective pass.
	SecondPassPending int `json:"second_pass_pending,omitempty"`
}

// Unanimous reports whether the two passes agreed on every verdict and
// every reason code over at least MinUnanimousResults results.
func (p Passes) Unanimous() bool {
	return p.Results >= MinUnanimousResults && p.VerdictAgreements == p.Results && p.ReasonAgreements == p.Results
}

// OneEffectivePass reports whether the measurement counts as one effective
// labelling pass: a second-pass label is still pending, or the passes are
// Unanimous and the second pass is not attested isolated. Such a figure
// never lets a rule block.
func (p Passes) OneEffectivePass() bool {
	return p.SecondPassPending > 0 || (p.Unanimous() && !p.SecondPassAttestedIsolated)
}

// OneEffectivePass reports whether the figure's measurement is one
// effective labelling pass (Passes.OneEffectivePass); false when the
// passes were not recorded.
func (p Precision) OneEffectivePass() bool {
	return p.Passes != nil && p.Passes.OneEffectivePass()
}

// TruePositives is the count behind Figure: the labelled results both
// reviewers called true.
func (p Precision) TruePositives() int {
	return int(math.Round(p.Figure * float64(p.Denominator)))
}

// RecomputedLower is the Wilson lower bound recomputed from the counts
// (TruePositives of Denominator); the bar reads it, never WilsonLower.
func (p Precision) RecomputedLower() float64 {
	return WilsonLower(p.TruePositives(), p.Denominator)
}

// FullyLabelled reports whether every result the rule produced on the
// corpus was labelled: Results is recorded, above zero and equal to
// Denominator. A capped figure (a seeded sample of the results, P-077)
// measures a flag-only rule and can never let it block.
func (p Precision) FullyLabelled() bool {
	return p.Results > 0 && p.Results == p.Denominator
}

// MinSpotcheck is the smallest spot-check sample that may let the rule
// block: MinSpotcheckSample, or every true positive when there are fewer,
// and never under one.
func (p Precision) MinSpotcheck() int {
	return max(1, min(MinSpotcheckSample, p.TruePositives()))
}

// PrecisionDigest is the digest of a rule's figures that a spot-check
// carries: sha256 over a domain line and the figures' JSON. A spot-check
// whose digest differs from its rule's figures checked other figures and is
// void.
func PrecisionDigest(p Precision) string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("sbo-code-rule-precision-v1\n"), b...))
	return hex.EncodeToString(sum[:])
}

// Spotcheck is the independent spot-check of a rule's labels (P-047, P-064):
// a seeded, stratified sample of the rule's labelled results, each answered
// agree or overturn by the operator or by an AI reviewer that labelled none
// of the corpus.
type Spotcheck struct {
	// Date is the day the answers were recorded, YYYY-MM-DD.
	Date string `json:"date"`
	// Reviewer is who answered: SpotcheckerOperator, or "agent:<id>" of an
	// independent AI reviewer (never either labeller).
	Reviewer string `json:"reviewer"`
	// FiguresDigest is PrecisionDigest of the figures the spot-check
	// checked; it is void when they change.
	FiguresDigest string `json:"figures_digest"`
	// SampleSize is how many of the rule's results the operator answered.
	SampleSize int `json:"sample_size"`
	// Disagreements counts results the operator overturned.
	Disagreements int `json:"disagreements"`
	// OverturnedTrue counts overturned results both reviewers had labelled
	// true: one is enough to keep the rule from blocking.
	OverturnedTrue int `json:"overturned_true"`
}

// Rule is one rule's manifest row.
type Rule struct {
	ID        string   `json:"id"`
	File      string   `json:"file"`
	Languages []string `json:"languages"`
	// Category is a policy finding category (code_vuln for G1).
	Category string `json:"category"`
	// Severity is high, medium or low; it must agree with the rule file's
	// Semgrep severity (ERROR, WARNING, INFO).
	Severity string `json:"severity"`
	// CWE is "CWE-<n>".
	CWE       string     `json:"cwe"`
	Precision *Precision `json:"precision,omitempty"`
	// OperatorSpotcheck is the operator's recorded spot-check; nil until
	// they have answered.
	OperatorSpotcheck *Spotcheck `json:"operator_spotcheck,omitempty"`
	// Blocking turns the rule's findings to confidence high (S-791 may
	// then count them). The validator refuses it unless MayBlock.
	Blocking bool `json:"blocking,omitempty"`
	// ExcludeTests drops the rule's results in a test path (TestPathClass)
	// after the engine ran: the driver's post-filter, since the strict
	// decoder refuses a path filter in rule YAML (lane SEC-G5).
	ExcludeTests bool `json:"exclude_tests,omitempty"`
}

// MayBlock reports whether the rule clears the blocking bar: a measured
// precision over every result the rule produced (FullyLabelled; a capped
// figure never blocks, P-077) whose Wilson lower bound, recomputed from its
// counts (the stated wilson_lower is not trusted), is at least
// BlockingLowerBound, and an independent spot-check of exactly these
// figures (its digest matches) with at least MinSpotcheck answers and no
// overturned true positive. A figure from one effective labelling pass
// (Precision.OneEffectivePass: two passes agreeing on every verdict and
// reason code over MinUnanimousResults or more results, the second not
// attested isolated) never blocks.
func (r Rule) MayBlock() bool {
	p, s := r.Precision, r.OperatorSpotcheck
	if p == nil || s == nil || p.Denominator < 1 {
		return false
	}
	return p.FullyLabelled() && !p.OneEffectivePass() && p.RecomputedLower() >= BlockingLowerBound &&
		ValidSpotchecker(s.Reviewer) && s.FiguresDigest == PrecisionDigest(*p) &&
		s.SampleSize >= p.MinSpotcheck() && s.OverturnedTrue == 0
}

// BlockingEligible reports whether the rule's findings count toward the
// commit gate: the pack turns blocking on for it and it clears the bar. A
// rule with no precision figure or no spot-check never does.
func (r Rule) BlockingEligible() bool { return r.Blocking && r.MayBlock() }

// Noisy reports whether the rule's measured precision is under NoisyFloor.
func (r Rule) Noisy() bool { return r.Precision != nil && r.Precision.Figure < NoisyFloor }

// Canary names the self-test rule and the file it must report.
type Canary struct {
	Rule     string `json:"rule"`
	RuleFile string `json:"rule_file"`
	Target   string `json:"target"`
}

// Manifest is pack.json.
type Manifest struct {
	Schema  string `json:"schema"`
	ID      string `json:"id"`
	Version string `json:"version"`
	// Licence is the SPDX expression the rules are published under.
	Licence string `json:"licence"`
	Canary  Canary `json:"canary"`
	Rules   []Rule `json:"rules"`
}

// Pack is a validated pack: its manifest, its files and its digest.
type Pack struct {
	Manifest Manifest
	files    map[string][]byte
	digest   string
	byID     map[string]Rule
}

// Digest is the pack's canonical digest (CanonicalDigest of its files).
func (p *Pack) Digest() string { return p.digest }

// Version is the pack version.
func (p *Pack) Version() string { return p.Manifest.Version }

// Rule returns the rule with id.
func (p *Pack) Rule(id string) (Rule, bool) {
	r, ok := p.byID[id]
	return r, ok
}

// TestExcluded reports whether a result of rule ruleID at rel (a
// project-relative, slash-separated path) is dropped: the rule sets
// exclude_tests and rel is in a test path class.
func (p *Pack) TestExcluded(ruleID, rel string) bool {
	r, ok := p.byID[ruleID]
	if !ok || !r.ExcludeTests {
		return false
	}
	_, test := TestPathClass(rel)
	return test
}

// Files returns a copy of every file of the pack by its path.
func (p *Pack) Files() map[string][]byte {
	out := make(map[string][]byte, len(p.files))
	for k, v := range p.files {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// ErrInvalid wraps every refusal of Parse.
var ErrInvalid = errors.New("secrulepack: rule pack is invalid")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Severity mapping between the manifest and the Semgrep rule file.
var semgrepSeverity = map[string]string{
	string(policy.FindingSeverityHigh):   "ERROR",
	string(policy.FindingSeverityMedium): "WARNING",
	string(policy.FindingSeverityLow):    "INFO",
}

// Languages are the Semgrep language names a pack may target (G1 ships
// Python, JavaScript, TypeScript and Go; Java and C# are planned).
var Languages = []string{"go", "javascript", "typescript", "python", "java", "csharp"}

// Parse validates a pack given as its files (path to bytes, forward
// slashes, relative to the pack root) and returns it.
func Parse(files map[string][]byte) (*Pack, error) {
	if len(files) == 0 || len(files) > MaxFiles {
		return nil, invalid("%d files (want 1 to %d)", len(files), MaxFiles)
	}
	total := 0
	for name, b := range files {
		if err := validPath(name); err != nil {
			return nil, invalid("file %q: %v", name, err)
		}
		total += len(b)
		if !utf8.Valid(b) {
			return nil, invalid("file %q is not UTF-8 text", name)
		}
	}
	if total > MaxPackBytes {
		return nil, invalid("%d bytes over the %d byte cap", total, MaxPackBytes)
	}
	raw, ok := files[ManifestFile]
	if !ok {
		return nil, invalid("no %s", ManifestFile)
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, invalid("%s: %v", ManifestFile, err)
	}
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	p := &Pack{Manifest: m, files: map[string][]byte{}, byID: map[string]Rule{}}
	for k, v := range files {
		p.files[k] = append([]byte(nil), v...)
	}
	listed := map[string]bool{ManifestFile: true, m.Canary.RuleFile: true, m.Canary.Target: true}
	for _, r := range m.Rules {
		b, ok := files[r.File]
		if !ok {
			return nil, invalid("rule %s: file %s is missing", r.ID, r.File)
		}
		if err := checkRuleFile(b, r.ID, r.Languages, semgrepSeverity[r.Severity], r.CWE); err != nil {
			return nil, invalid("rule %s (%s): %v", r.ID, r.File, err)
		}
		listed[r.File] = true
		p.byID[r.ID] = r
	}
	cb, ok := files[m.Canary.RuleFile]
	if !ok {
		return nil, invalid("canary rule file %s is missing", m.Canary.RuleFile)
	}
	if err := checkRuleFile(cb, m.Canary.Rule, nil, "INFO", ""); err != nil {
		return nil, invalid("canary rule: %v", err)
	}
	if _, ok := files[m.Canary.Target]; !ok {
		return nil, invalid("canary target %s is missing", m.Canary.Target)
	}
	for name := range files {
		if !listed[name] {
			return nil, invalid("file %s is not named by the manifest", name)
		}
	}
	p.digest = CanonicalDigest(files)
	return p, nil
}

// validPath allows only a manifest at the root, rule YAML files under
// rules/ and the canary target under canary/: one level, a plain name.
func validPath(name string) error {
	if name == ManifestFile {
		return nil
	}
	dir, base := path.Split(name)
	switch dir {
	case RulesDir + "/":
		if !strings.HasSuffix(base, ".yaml") {
			return errors.New("a rule file must end in .yaml")
		}
	case CanaryDir + "/":
	default:
		return errors.New("only pack.json, rules/<name>.yaml and canary/<name> are allowed")
	}
	if base == "" || len(base) > MaxIDBytes+8 || !plainName(base) {
		return errors.New("bad file name")
	}
	return nil
}

// plainName is a file name of letters, digits, dot, dash and underscore,
// not starting with a dot.
func plainName(s string) bool {
	if s == "" || s[0] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// validID is a rule id: lowercase letters, digits, dot and dash, starting
// with a letter, at most MaxIDBytes.
func validID(s string) bool {
	if s == "" || len(s) > MaxIDBytes || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func validateManifest(m Manifest) error {
	switch {
	case m.Schema != Schema:
		return invalid("unknown schema %q", m.Schema)
	case m.ID != PackID:
		return invalid("pack id %q (want %q)", m.ID, PackID)
	case ParseVersion(m.Version) == nil:
		return invalid("version %q is not MAJOR.MINOR.PATCH", m.Version)
	case m.Licence == "" || len(m.Licence) > 64:
		return invalid("a licence is required")
	case len(m.Rules) == 0 || len(m.Rules) > MaxRules:
		return invalid("%d rules (want 1 to %d)", len(m.Rules), MaxRules)
	case !validID(m.Canary.Rule) || path.Dir(m.Canary.RuleFile) != RulesDir || path.Dir(m.Canary.Target) != CanaryDir:
		return invalid("the canary needs a rule id, a rules/ file and a canary/ target")
	}
	ids := map[string]bool{m.Canary.Rule: true}
	files := map[string]bool{m.Canary.RuleFile: true}
	for i, r := range m.Rules {
		switch {
		case !validID(r.ID):
			return invalid("rule %d: bad id %q", i, r.ID)
		case ids[r.ID]:
			return invalid("rule id %q is used twice", r.ID)
		case path.Dir(r.File) != RulesDir || files[r.File]:
			return invalid("rule %s: file %q must be a rules/ file of its own", r.ID, r.File)
		case len(r.Languages) == 0:
			return invalid("rule %s names no language", r.ID)
		case semgrepSeverity[r.Severity] == "":
			return invalid("rule %s: severity %q (want high, medium or low)", r.ID, r.Severity)
		case !slices.Contains(policy.FindingCategories(), policy.FindingCategory(r.Category)):
			return invalid("rule %s: unknown category %q", r.ID, r.Category)
		case !validCWE(r.CWE):
			return invalid("rule %s: CWE %q (want CWE-<number>)", r.ID, r.CWE)
		}
		for _, l := range r.Languages {
			if !slices.Contains(Languages, l) {
				return invalid("rule %s: language %q is not supported", r.ID, l)
			}
		}
		if err := validateMeasurement(r); err != nil {
			return err
		}
		ids[r.ID] = true
		files[r.File] = true
	}
	return nil
}

// validateMeasurement checks a rule's precision figure, its spot-check and
// its blocking switch: blocking needs every result labelled (P-077) and
// the bar (MayBlock).
func validateMeasurement(r Rule) error {
	if r.Precision != nil {
		if err := validatePrecision(*r.Precision); err != nil {
			return invalid("rule %s precision: %v", r.ID, err)
		}
	}
	if s := r.OperatorSpotcheck; s != nil {
		if r.Precision == nil {
			return invalid("rule %s: an operator spot-check of a rule with no precision figure", r.ID)
		}
		if err := validateSpotcheck(*s, *r.Precision); err != nil {
			return invalid("rule %s operator_spotcheck: %v", r.ID, err)
		}
	}
	if !r.Blocking {
		return nil
	}
	if r.Precision == nil || !r.Precision.FullyLabelled() {
		return invalid("rule %s: blocking needs every result labelled (results recorded, above zero and equal to the denominator); a capped figure measures a flag-only rule (P-077)", r.ID)
	}
	if r.Precision.OneEffectivePass() {
		return invalid("rule %s: blocking needs two labelling passes shown independent; these agree on every verdict and reason code (%d of %d) and the second pass is not attested isolated in the batch manifest, so they are one effective pass", r.ID, r.Precision.Passes.ReasonAgreements, r.Precision.Passes.Results)
	}
	if !r.MayBlock() {
		return invalid("rule %s: blocking needs a Wilson lower bound of at least %.1f recomputed from its counts and an independent spot-check of these figures, at least %d answers (or every true positive when fewer), with no overturned true positive", r.ID, BlockingLowerBound, MinSpotcheckSample)
	}
	return nil
}

func validCWE(s string) bool {
	n, ok := strings.CutPrefix(s, "CWE-")
	if !ok || n == "" || len(n) > 5 {
		return false
	}
	_, err := strconv.Atoi(n)
	return err == nil && n[0] != '0'
}

// validatePrecision checks that a precision figure is a measurement: a
// denominator, a corpus and a method, figures inside 0 to 1, and a lower
// bound that is the Wilson bound of the figure over the denominator (to
// within rounding), so a hand-edited bound cannot clear the bar.
func validatePrecision(p Precision) error {
	switch {
	case p.Denominator < 1:
		return errors.New("a denominator is required")
	case p.Corpus == "" || p.Method == "" || len(p.Corpus) > MaxTextBytes || len(p.Method) > MaxTextBytes:
		return errors.New("a corpus and a method are required")
	case p.Figure < 0 || p.Figure > 1 || p.WilsonLower < 0 || p.WilsonLower > p.Figure:
		return errors.New("figures must lie in 0 to 1 with the lower bound under the figure")
	case p.Results != 0 && p.Results < p.Denominator:
		return errors.New("results must be at least the denominator")
	case p.ReviewerDisagreements < 0 || p.ReviewerDisagreements > p.Denominator:
		return errors.New("reviewer_disagreements must lie in 0 to the denominator")
	case p.Kappa != nil && (*p.Kappa < -1 || *p.Kappa > 1):
		return errors.New("kappa must lie in -1 to 1")
	case p.Passes != nil && (p.Passes.Results < 0 || p.Passes.SecondPassPending < 0 || p.Passes.Results+p.Passes.SecondPassPending < 1 ||
		p.Passes.VerdictAgreements < 0 || p.Passes.VerdictAgreements > p.Passes.Results ||
		p.Passes.ReasonAgreements < 0 || p.Passes.ReasonAgreements > p.Passes.VerdictAgreements):
		return errors.New("passes must hold results (labelled by both passes or pending the second) above zero, verdict agreements in 0 to the results and reason agreements in 0 to the verdict agreements")
	}
	k := int(math.Round(p.Figure * float64(p.Denominator)))
	if math.Abs(float64(k)-p.Figure*float64(p.Denominator)) > 0.01+0.0001*float64(p.Denominator) {
		return fmt.Errorf("figure %.4f is not a count over the denominator %d", p.Figure, p.Denominator)
	}
	// The tool writes the bound to 6 places, so a stated bound above the
	// recomputed one by more than that rounding is refused outright.
	if p.WilsonLower > WilsonLower(k, p.Denominator)+1e-6 {
		return fmt.Errorf("wilson_lower %.6f is above the Wilson bound %.6f of %d of %d", p.WilsonLower, WilsonLower(k, p.Denominator), k, p.Denominator)
	}
	if math.Abs(WilsonLower(k, p.Denominator)-p.WilsonLower) > 0.005 {
		return fmt.Errorf("wilson_lower %.4f is not the Wilson bound %.4f of %d of %d", p.WilsonLower, WilsonLower(k, p.Denominator), k, p.Denominator)
	}
	return nil
}

// validateSpotcheck checks a spot-check record: a date, who answered, the
// digest of the rule's current figures, a sample, and counts that fit
// inside it.
func validateSpotcheck(s Spotcheck, p Precision) error {
	if _, err := time.Parse("2006-01-02", s.Date); err != nil {
		return fmt.Errorf("date %q is not YYYY-MM-DD", s.Date)
	}
	switch {
	case !ValidSpotchecker(s.Reviewer):
		return fmt.Errorf("reviewer %q (want %s or %s<id>)", s.Reviewer, SpotcheckerOperator, SpotcheckerAgentPrefix)
	case s.FiguresDigest != PrecisionDigest(p):
		return errors.New("figures_digest is not the digest of the rule's precision figures (the spot-check checked other figures and is void; record it again)")
	case s.SampleSize < 1 || s.SampleSize > 1000:
		return fmt.Errorf("sample_size %d (want 1 to 1000)", s.SampleSize)
	case s.Disagreements < 0 || s.Disagreements > s.SampleSize:
		return errors.New("disagreements must lie in 0 to the sample size")
	case s.OverturnedTrue < 0 || s.OverturnedTrue > s.Disagreements:
		return errors.New("overturned_true must lie in 0 to the disagreements")
	}
	return nil
}

// WilsonLower is the lower bound of the Wilson score interval at 95
// percent (z = 1.96) for k successes in n trials. The corpus package owns
// the formula; the bar and the corpus share it.
func WilsonLower(k, n int) float64 { return seccorpus.WilsonLower(k, n) }

// CanonicalDigest is the pack digest: sha256 over a domain line and, for
// every file sorted by path, its path, a NUL, the hex sha256 of its bytes
// and a newline. It does not depend on map order or on how the files were
// carried (embedded, bundled or written to disk).
func CanonicalDigest(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	h.Write([]byte("sbo-code-rule-pack-v1\n"))
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write([]byte(hex.EncodeToString(sum[:])))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ParseVersion reads MAJOR.MINOR.PATCH, nil when it is anything else.
func ParseVersion(v string) []int {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 3)
	for i, p := range parts {
		if p == "" || len(p) > 6 || (len(p) > 1 && p[0] == '0') {
			return nil
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		out[i] = n
	}
	return out
}

// CompareVersions compares two pack versions; an unreadable version sorts
// below every readable one.
func CompareVersions(a, b string) int {
	pa, pb := ParseVersion(a), ParseVersion(b)
	switch {
	case pa == nil && pb == nil:
		return 0
	case pa == nil:
		return -1
	case pb == nil:
		return 1
	}
	return slices.Compare(pa, pb)
}

// Source says where the pack in use came from.
type Source string

// The Source values.
const (
	// SourceFloor is the pack embedded in this binary.
	SourceFloor Source = "embedded"
	// SourceImported is a pack verified through the signed content channel.
	SourceImported Source = "signed_channel"
)

// Choose returns the pack to use: an imported pack, which the caller has
// already verified through the signed content channel, wins only when it
// is the same pack id and strictly newer than the embedded floor; anything
// else (none, an older or equal version, another id) keeps the floor, so a
// replayed or downgraded pack never displaces the floor.
func Choose(floor, imported *Pack) (*Pack, Source) {
	if imported != nil && floor != nil && imported.Manifest.ID == floor.Manifest.ID &&
		CompareVersions(imported.Manifest.Version, floor.Manifest.Version) > 0 {
		return imported, SourceImported
	}
	if floor == nil && imported != nil {
		return imported, SourceImported
	}
	return floor, SourceFloor
}

// RulePrefix is the dotted form of a rules directory as Opengrep embeds it
// in a rule id when it rewrites ids (JSP-8: "/a/b/rules" makes rule x
// "a.b.rules.x"); secscan.AdaptOptions.RulePrefix strips it. The driver
// also passes --no-rewrite-rule-ids, so the strip is the second guard.
func RulePrefix(rulesDir string) string {
	d := strings.ReplaceAll(rulesDir, `\`, "/")
	if len(d) >= 2 && d[1] == ':' {
		d = d[2:]
	}
	d = strings.Trim(d, "/")
	return strings.ReplaceAll(d, "/", ".")
}
