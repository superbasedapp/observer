package secassess

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The validator. Validate reads an assessment.json and applies an ordered
// table of rules, V1 to V14 (rules.go lists them). It is pure: the bytes, the
// options and a RefChecker come in, a Result goes out; it opens nothing and
// never trusts a field it can compute.
//
// What it will not take from the file: the band, the reference states and any
// other field tagged computed. What it does with the rest: drop what is not
// valid (counted, with a closed reason code), clean every text with the
// fence-safe cleaner and the injected redactor, and keep the agent's claims
// labelled as claims.

// Severity is how an issue affected the file.
type Severity string

// The issue severities.
const (
	// SevRefused: the file or an item was not accepted.
	SevRefused Severity = "refused"
	// SevDropped: a field, a list entry or part of a text was left out.
	SevDropped Severity = "dropped"
	// SevWarn: accepted, with something a reader should know.
	SevWarn Severity = "warn"
)

// Issue is one finding of the validator, in Observer's words.
type Issue struct {
	// Row is the rule that raised it ("V4").
	Row string `json:"row"`
	// Code is a closed reason code.
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	// Path names the item (by file position up to V7, by id after).
	Path string `json:"path,omitempty"`
	// Item is the id of the item the issue is about, for an issue about one
	// item that the view can show on that item's own row (a finding whose CVSS
	// vector was left out). Row V4 has accepted the id by then (letters, digits,
	// dot, underscore, hyphen), so it is a key and not free text; it is empty
	// for any other issue, and for a record kept before it was recorded.
	Item    string `json:"item,omitempty"`
	Message string `json:"message"`
}

// ValidationState is the outcome of a validation.
type ValidationState string

// The validation states.
const (
	// ValidationValid: the file was read and nothing was refused.
	ValidationValid ValidationState = "valid"
	// ValidationPartial: the file was read; some items were refused or left
	// out (the issues say which).
	ValidationPartial ValidationState = "partial"
	// ValidationInvalid: the file was refused; no model was kept.
	ValidationInvalid ValidationState = "invalid"
)

// Count is how many items of a collection the validator read and kept.
type Count struct {
	Read    int `json:"read"`
	LeftOut int `json:"left_out,omitempty"`
	Refused int `json:"refused,omitempty"`
	Kept    int `json:"kept"`
}

// RefTally counts the references by state.
type RefTally struct {
	Found           int `json:"found"`
	Exists          int `json:"exists"`
	ClaimedNotFound int `json:"claimed_not_found"`
	Missing         int `json:"missing"`
	Invalid         int `json:"invalid"`
	Unchecked       int `json:"unchecked"`
}

// RefCheck says how the references were looked at: the setting and the one
// effect on the files that decide what the tally counts, so a number is never
// read without its conditions (the first live run's check read 192 found and 7
// not found where the kit scorer, on the same file, read 198 and 1). Set only
// when the project's files were looked at, that is when the options carried a
// checker.
type RefCheck struct {
	// WindowLines is the match window in force (setting ref_match_window_lines):
	// a reference reads "found near the cited line" only when its quoted text is on
	// a code line within this many lines of the first cited line (1 is the cited
	// line itself).
	WindowLines int `json:"window_lines"`
	// TextHidden counts the references that quote text the redactor changed
	// before the files were searched for it and that did not read found. What is
	// searched for is then not what the agent wrote, so the reference cannot be
	// found whether or not the agent was right.
	TextHidden int `json:"text_hidden,omitempty"`
}

// Sets records the sets in force when the model was validated, so a later
// settings change never changes how an old run reads.
type Sets struct {
	Frameworks   []string `json:"frameworks,omitempty"`
	MethodExtras []string `json:"method_extras,omitempty"`
	Categories   []string `json:"categories,omitempty"`
	AIApp        bool     `json:"ai_app,omitempty"`
}

// Report is what a validation found.
type Report struct {
	State    ValidationState `json:"state"`
	Contract Contract        `json:"contract"`
	// Fatal is the reason code of a refusal of the whole file.
	Fatal       string           `json:"fatal,omitempty"`
	Issues      []Issue          `json:"issues,omitempty"`
	IssuesMore  int              `json:"issues_more,omitempty"`
	Counts      map[string]Count `json:"counts,omitempty"`
	Refs        RefTally         `json:"refs"`
	Ignored     int              `json:"ignored_fields,omitempty"`
	IgnoredKeys []string         `json:"ignored_keys,omitempty"`
	TM          *TMCoverage      `json:"tm,omitempty"`
	PT          *PTCoverage      `json:"pt,omitempty"`
	// RT counts a retest's labels (a retest only).
	RT *RetestSummary `json:"rt,omitempty"`
	// Evidence is row V14's account of the request helper's log (a pen test or
	// red team only).
	Evidence *EvidenceReport `json:"evidence,omitempty"`
	Sets     Sets            `json:"sets"`
	// RefCheck is how the references were looked at; nil when they were not.
	RefCheck *RefCheck `json:"ref_check,omitempty"`
}

// Result is a validation: the report and, unless the file was refused, the
// checked model.
type Result struct {
	Report Report          `json:"report"`
	TM     *ThreatModelDoc `json:"tm,omitempty"`
	PT     *PentestDoc     `json:"pt,omitempty"`
	RT     *RetestDoc      `json:"rt,omitempty"`
}

// ValidateOptions are the plain values a validation needs; the pure package
// never reads configuration.
type ValidateOptions struct {
	// Contract says which schema the kind uses (the kind row's column).
	Contract Contract
	// RunID is the run the file must name.
	RunID string
	// ScopePaths are the plan's project-relative scope paths; empty or a
	// root entry means the whole project.
	ScopePaths []string
	// TargetURL is the confirmed target of a pen test ("" skips the check).
	TargetURL string
	// Frameworks are the threat-model frameworks in force; STRIDE is always
	// added. Nil means all of them.
	Frameworks []string
	// MethodExtras are the method extras in force (ExtraAbuseCases,
	// ExtraAttackTrees); nil means neither.
	MethodExtras []string
	// Categories are the WSTG category ids in force; empty means all twelve.
	Categories []string
	// AIApp says the project is an AI application (the AI frameworks apply).
	AIApp bool
	// Refs looks up project files; nil leaves every reference unchecked.
	Refs RefChecker
	// MaxBytes is the size cap of the file in bytes (setting model_max_mib); 0
	// reads as MaxModelBytes and nothing above MaxModelBytesCeiling is taken.
	MaxBytes int
	// RefWindow is how many lines from the first cited line a reference's text
	// must sit within to be found (setting ref_match_window_lines); 0 reads as
	// DefaultRefWindow.
	RefWindow int
	// Probe is what the request helper left in the run folder, as the service
	// read it (row V14); the zero value is a run with no helper, whose findings
	// all read as unlogged.
	Probe ProbeFacts
	// Exercise says the kind asks for an exercise (a red team run) and Objective
	// is the developer's own objective the run recorded ("" none); row V16 reads
	// both.
	Exercise  bool
	Objective string
	// Retest is the earlier run's findings a retest replayed, which its results
	// are held to (rows RT3 to RT6); nil for any other kind.
	Retest *RetestBasis
	// Redact removes secrets from a text; nil leaves text as it is.
	Redact func(string) string
}

// modelCap is the size cap in force.
func (o ValidateOptions) modelCap() int {
	switch {
	case o.MaxBytes <= 0:
		return MaxModelBytes
	case o.MaxBytes > MaxModelBytesCeiling:
		return MaxModelBytesCeiling
	}
	return o.MaxBytes
}

// ModelCap is the size cap in bytes the options hold a file to.
func (o ValidateOptions) ModelCap() int { return o.modelCap() }

// DefaultValidateOptions returns the options with every set at its default.
func DefaultValidateOptions(c Contract, runID string) ValidateOptions {
	fw, _ := ResolvePreset(FrameworkPresets, "all")
	ex, _ := ResolvePreset(MethodExtraPresets, "both")
	cat, _ := ResolvePreset(CategoryPresets, "all")
	return ValidateOptions{Contract: c, RunID: runID, Frameworks: fw, MethodExtras: ex, Categories: cat, RefWindow: DefaultRefWindow}
}

// Effect is what a rule does when it fires.
type Effect string

// The rule effects.
const (
	EffectRefuseFile Effect = "refuse_file"
	EffectRefuseItem Effect = "refuse_item"
	EffectDropField  Effect = "drop_field"
	EffectWarn       Effect = "warn"
	EffectSet        Effect = "set"
	EffectReport     Effect = "report"
)

// validator is the state one validation carries through the rule table.
type validator struct {
	o      ValidateOptions
	rep    Report
	fatal  bool
	tm     *ThreatModelDoc
	pt     *PentestDoc
	rt     *RetestDoc
	data   []byte
	dead   map[string][]bool
	ignore map[string]int
	// ignoreMore counts the ignored keys past the maxIgnoredKeys distinct ones
	// tracked in ignore, so the total stays right.
	ignoreMore int
	trims      map[string]int
	// shaped counts what the shape pass left out of the file (a field or list
	// entries, shape.go); like a trim it makes the validation partial.
	shaped int
	// hidden holds the references whose quoted text the redactor changed, by
	// the key the check memoises on; refsHidden counts the ones among them that
	// did not read found (RefCheck.TextHidden).
	hidden     map[refKey]bool
	refsHidden int
	text       map[string]int // truncations by field kind
	memo       map[refKey]RefOutcome
	fw         map[string]bool
	cats       map[string]bool
	extras     map[string]bool
}

type refKey struct {
	path, needle  string
	line, endLine int
}

func newValidator(data []byte, o ValidateOptions) *validator {
	v := &validator{
		o: o, data: data,
		dead: map[string][]bool{}, ignore: map[string]int{}, trims: map[string]int{}, text: map[string]int{},
		memo: map[refKey]RefOutcome{}, hidden: map[refKey]bool{}, fw: map[string]bool{}, cats: map[string]bool{}, extras: map[string]bool{},
	}
	v.rep.Contract = o.Contract
	v.rep.Counts = map[string]Count{}
	fws := o.Frameworks
	if fws == nil {
		fws, _ = ResolvePreset(FrameworkPresets, "all")
	}
	v.fw[FrameworkSTRIDE] = true
	for _, f := range fws {
		v.fw[f] = true
	}
	for _, e := range o.MethodExtras {
		v.extras[e] = true
	}
	cats := o.Categories
	if len(cats) == 0 {
		cats, _ = ResolvePreset(CategoryPresets, "all")
	}
	for _, c := range cats {
		v.cats[c] = true
	}
	v.rep.Sets = Sets{Frameworks: sortedKeys(v.fw), MethodExtras: sortedKeys(v.extras), Categories: orderedCategories(v.cats), AIApp: o.AIApp}
	return v
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// orderedCategories lists the categories in force in test order.
func orderedCategories(m map[string]bool) []string {
	var out []string
	for _, c := range WSTGCategories {
		if m[c.ID] {
			out = append(out, c.ID)
		}
	}
	return out
}

// issue records one issue; past maxIssues only the count grows.
func (v *validator) issue(row, code string, sev Severity, path, msg string) {
	v.issueItem(row, code, sev, path, "", msg)
}

// issueItem records an issue about one item and names it by id. The id is kept
// only when it is an id row V4 accepts; anything else is left out, so the field
// is never free text.
func (v *validator) issueItem(row, code string, sev Severity, path, item, msg string) {
	if len(v.rep.Issues) >= maxIssues {
		v.rep.IssuesMore++
		return
	}
	if !ValidItemID(item) {
		item = ""
	}
	// A message quotes agent text (a clipped, cleaned fragment); the redactor
	// sees the whole message so a secret in a quoted fragment is not stored.
	v.rep.Issues = append(v.rep.Issues, Issue{Row: row, Code: code, Severity: sev, Path: path, Item: item, Message: v.redact(msg)})
}

// fail refuses the whole file.
func (v *validator) fail(row, code, msg string) {
	v.fatal = true
	v.rep.Fatal = code
	v.issue(row, code, SevRefused, "", msg)
}

// read records that a collection held n items.
func (v *validator) read(coll string, n int) {
	c := v.rep.Counts[coll]
	c.Read += n
	v.rep.Counts[coll] = c
}

// leftOut records n items past a cap.
func (v *validator) leftOut(coll string, n int) {
	c := v.rep.Counts[coll]
	c.LeftOut += n
	v.rep.Counts[coll] = c
}

// refuseItem records a refused item of a collection.
func (v *validator) refuseItem(row, coll string, i int, code, msg string) {
	key, path := coll, fmt.Sprintf("%s[%d]", coll, i)
	if base, tree, ok := strings.Cut(coll, "#"); ok {
		key, path = base, fmt.Sprintf("attack_trees[%s].nodes[%d]", tree, i)
	}
	c := v.rep.Counts[key]
	c.Refused++
	v.rep.Counts[key] = c
	v.issue(row, code, SevRefused, path, msg)
}

// refuseNested records a refused nested item (a mitigation, a step).
func (v *validator) refuseNested(row, coll, path, code, msg string) {
	c := v.rep.Counts[coll]
	c.Read++
	c.Refused++
	v.rep.Counts[coll] = c
	v.issue(row, code, SevRefused, path, msg)
}

// refWindow is the reference window in force.
func (v *validator) refWindow() int {
	if v.o.RefWindow <= 0 {
		return DefaultRefWindow
	}
	return v.o.RefWindow
}

// finish computes Kept and the state.
func (v *validator) finish() {
	refused := false
	for k, c := range v.rep.Counts {
		c.Kept = c.Read - c.LeftOut - c.Refused
		if c.Kept < 0 {
			c.Kept = 0
		}
		v.rep.Counts[k] = c
		if c.Refused > 0 || c.LeftOut > 0 {
			refused = true
		}
	}
	if len(v.trims) > 0 || v.shaped > 0 {
		refused = true
	}
	// A reference that was never looked at (the read budget ran out, or no check
	// was available) is not "nothing was refused": the model is partly checked.
	if v.rep.Refs.Unchecked > 0 {
		refused = true
	}
	switch {
	case v.fatal:
		v.rep.State = ValidationInvalid
	case refused:
		v.rep.State = ValidationPartial
	default:
		v.rep.State = ValidationValid
	}
	v.finishIgnored()
	if v.o.Refs != nil {
		v.rep.RefCheck = &RefCheck{WindowLines: v.refWindow(), TextHidden: v.refsHidden}
	}
}

// maxIgnoredKeys is how many distinct ignored keys one validation tracks; a
// hostile file with a million unknown keys costs a counter, not a map.
const maxIgnoredKeys = 1000

// maxListedIgnoredKeys is how many ignored keys the report lists.
const maxListedIgnoredKeys = 20

// finishIgnored totals the ignored keys and lists the first few, sorted.
func (v *validator) finishIgnored() {
	v.rep.Ignored += v.ignoreMore
	keys := make([]string, 0, len(v.ignore))
	for k, n := range v.ignore {
		v.rep.Ignored += n
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxListedIgnoredKeys {
		keys = keys[:maxListedIgnoredKeys]
	}
	for _, k := range keys {
		v.rep.IgnoredKeys = append(v.rep.IgnoredKeys, fmt.Sprintf("%s (%d)", k, v.ignore[k]))
	}
}

// Validate applies the rule table to an assessment.json.
func Validate(data []byte, o ValidateOptions) Result {
	v := newValidator(data, o)
	rules := valRules
	if o.Contract == ContractRetest {
		rules = retestRules
	}
	for _, r := range rules {
		if v.fatal {
			break
		}
		r.Run(v)
	}
	v.finish()
	res := Result{Report: v.rep}
	if !v.fatal {
		res.TM, res.PT, res.RT = v.tm, v.pt, v.rt
	}
	return res
}

// ---- V1 and V2: the file ----

func ruleV1(v *validator) {
	if limit := v.o.modelCap(); len(v.data) > limit {
		v.fail("V1", "too_large", fmt.Sprintf("The file is over its size cap of %d MiB (\"%s\" in %s), so it was not read.", limit>>20, LabelModelMaxMiB, WhereSettings))
		return
	}
	if sarifDepth(v.data) > MaxModelDepth {
		v.fail("V1", "too_deep", fmt.Sprintf("The file is nested more than %d levels deep, so it was not read.", MaxModelDepth))
	}
}

// fieldInfo is one JSON field of a model struct.
type fieldInfo struct {
	typ      reflect.Type
	computed bool
	// optional is the json tag's omitempty: the file may leave the field out.
	optional bool
	// lone is the tag lone:"list": a single value reads as a list of one
	// (shape.go).
	lone bool
}

// jsonFields maps a struct type's JSON names to their types.
func jsonFields(t reflect.Type) map[string]fieldInfo {
	out := map[string]fieldInfo{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" || !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = fieldInfo{
			typ: f.Type, computed: f.Tag.Get("computed") == "true",
			optional: slices.Contains(strings.Split(opts, ","), "omitempty"), lone: f.Tag.Get("lone") == "list",
		}
	}
	return out
}

// indirect strips the pointers off a type.
func indirect(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// prune removes from a generic JSON value every key the struct type does not
// carry, and every computed key, counting them by field path. It also spells
// a whole number written as a float ("3.0") as an integer where the field is
// an integer, so one such value does not refuse the file, and reads each field
// through the shape pass (shape.go: a lone value where a list belongs, a value
// of the wrong kind in an optional leaf field). Keys are visited in sorted
// order so which ignored keys are tracked past the bound is the same on every
// run.
func (v *validator) prune(val any, t reflect.Type, path string) {
	v.pruneAt(val, t, path, "")
}

// pruneAt is prune with the position of the value in the file ("results[3]"),
// which the shape pass names in its issues. path is the field path the ignored
// keys are counted under (a list's items share one, "results[]").
func (v *validator) pruneAt(val any, t reflect.Type, path, at string) {
	t = indirect(t)
	switch x := val.(type) {
	case map[string]any:
		if t.Kind() != reflect.Struct {
			return
		}
		fields := jsonFields(t)
		// A type that decodes itself (lenient.go) reads its own shapes; the shape pass
		// leaves its fields alone.
		self := readsItself(t)
		for _, k := range slices.Sorted(maps.Keys(x)) {
			f, ok := fields[k]
			if !ok || f.computed {
				delete(x, k)
				v.noteIgnored(path, k)
				continue
			}
			here := joinAt(at, k)
			child := x[k]
			if !self {
				child = v.shapeField(child, f, here)
			}
			x[k] = v.pruneValue(child, f.typ, path+"."+k, here)
		}
	case []any:
		if t.Kind() != reflect.Slice {
			return
		}
		for i := range x {
			x[i] = v.pruneValue(x[i], t.Elem(), path+"[]", at+"["+strconv.Itoa(i)+"]")
		}
	}
}

// pruneValue prunes a child value and returns the value to keep in its place:
// the child itself, or, for an integer field holding a whole number written as
// a float, the integer spelling.
func (v *validator) pruneValue(child any, t reflect.Type, path, at string) any {
	v.pruneAt(child, t, path, at)
	if n, ok := child.(json.Number); ok && isIntKind(indirect(t).Kind()) {
		if whole, ok := wholeNumber(n); ok {
			return whole
		}
	}
	return child
}

// isIntKind reports whether k is an integer kind.
func isIntKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	}
	return false
}

// Whole numbers written as floats are taken only when they are exact and small.
const (
	maxWholeNumber   = 1 << 53 // the largest magnitude a float holds exactly
	maxNumberSpelled = 40      // longest number text looked at
	maxNumberExp     = 1000    // largest exponent looked at
)

// wholeNumber returns the integer spelling of a number written with a point or
// an exponent ("3.0", "1e1", "-0.0") when its value is exactly an integer of
// magnitude at most 2^53. It reads the decimal digits, not a float, so
// "3.0000000000000000001" is not a 3, and it gives up on anything long or with
// a huge exponent so a hostile token costs nothing. Anything else comes back
// false and is left for the typed decode to refuse as before.
func wholeNumber(n json.Number) (json.Number, bool) {
	s := string(n)
	if len(s) > maxNumberSpelled || !strings.ContainsAny(s, ".eE") {
		return "", false
	}
	neg := strings.HasPrefix(s, "-")
	digits, e10, ok := decimalParts(strings.TrimPrefix(s, "-"))
	switch {
	case !ok:
		return "", false
	case digits == "": // zero, however it is spelled ("-0.0", "0e5")
		return "0", true
	case e10 < 0 || len(digits)+e10 > 16: // a fraction, or past 2^53 (16 digits at most)
		return "", false
	}
	mag, err := strconv.ParseInt(digits+strings.Repeat("0", e10), 10, 64)
	if err != nil || mag > maxWholeNumber {
		return "", false
	}
	if neg {
		mag = -mag
	}
	return json.Number(strconv.FormatInt(mag, 10)), true
}

// decimalParts splits an unsigned JSON number into its significant digits
// (leading and trailing zeros removed, "" for zero) and the power of ten they
// are scaled by. e10 < 0 means the value has a fraction. ok is false for an
// exponent past maxNumberExp or text that is not a number.
func decimalParts(s string) (digits string, e10 int, ok bool) {
	mant, exp, hasExp := strings.Cut(strings.ToLower(s), "e")
	if hasExp {
		n, err := strconv.Atoi(exp)
		if err != nil || n > maxNumberExp || n < -maxNumberExp {
			return "", 0, false
		}
		e10 = n
	}
	whole, frac, _ := strings.Cut(mant, ".")
	if whole == "" || strings.Trim(whole+frac, "0123456789") != "" {
		return "", 0, false
	}
	digits = strings.TrimLeft(whole+frac, "0")
	e10 -= len(frac)
	if t := strings.TrimRight(digits, "0"); len(t) < len(digits) {
		e10 += len(digits) - len(t)
		digits = t
	}
	return digits, e10, true
}

// ignoredKey is the display form of a key the model does not carry. The key is
// the agent's own text (any characters, up to the size of the file), so it is
// redacted and cleaned like every other stored text and cut to 80 runes; its
// work is bounded by reading only the first maxKeyScan bytes.
func (v *validator) ignoredKey(k string) string {
	if len(k) > maxKeyScan {
		k = k[:maxKeyScan]
	}
	return clip(v.redactClean(k, 256), 80)
}

// maxKeyScan is how many bytes of an ignored key are read.
const maxKeyScan = 4096

// noteIgnored counts one key the model does not carry (or a computed one) at a
// field path. At most maxIgnoredKeys distinct keys are tracked; past that a
// new key only grows the total.
func (v *validator) noteIgnored(path, key string) {
	k := path + "." + v.ignoredKey(key)
	if _, tracked := v.ignore[k]; !tracked && len(v.ignore) >= maxIgnoredKeys {
		v.ignoreMore++
		return
	}
	v.ignore[k]++
}

func ruleV2(v *validator) {
	schema := v.o.Contract.Schema()
	if schema == "" {
		v.fail("V2", "no_model_contract", "This kind of assessment has no model file.")
		return
	}
	dec := json.NewDecoder(bytes.NewReader(v.data))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		v.fail("V2", "not_json", "The file is not valid JSON ("+jsonErrWord(err)+").")
		return
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		v.fail("V2", "trailing_data", "The file holds more than one JSON value.")
		return
	}
	if _, ok := generic.(map[string]any); !ok {
		v.fail("V2", "not_object", "The file must be one JSON object.")
		return
	}
	root := reflect.TypeOf(ThreatModelDoc{})
	switch v.o.Contract {
	case ContractPentest:
		root = reflect.TypeOf(PentestDoc{})
	case ContractRetest:
		root = reflect.TypeOf(RetestDoc{})
	}
	v.prune(generic, root, "")
	clean, err := json.Marshal(generic)
	if err != nil {
		v.fail("V2", "not_json", "The file could not be read as JSON.")
		return
	}
	var runID, got string
	var target any
	switch v.o.Contract {
	case ContractPentest:
		v.pt = &PentestDoc{}
		target = v.pt
	case ContractRetest:
		v.rt = &RetestDoc{}
		target = v.rt
	default:
		v.tm = &ThreatModelDoc{}
		target = v.tm
	}
	if err := json.Unmarshal(clean, target); err != nil {
		v.fail("V2", "bad_shape", shapeMessage(err))
		return
	}
	switch {
	case v.pt != nil:
		runID, got = v.pt.RunID, v.pt.Schema
	case v.rt != nil:
		runID, got = v.rt.RunID, v.rt.Schema
	default:
		runID, got = v.tm.RunID, v.tm.Schema
	}
	if got != schema {
		v.fail("V2", "schema_mismatch", fmt.Sprintf("The file says its schema is %q; this assessment expects %q.", clip(got, 60), schema))
		return
	}
	if runID != v.o.RunID {
		v.fail("V2", "run_id_mismatch", fmt.Sprintf("The file names run %q; this run is %q.", clip(runID, 40), v.o.RunID))
	}
}

// jsonErrWord turns a decoder error into a short phrase without echoing
// file content.
func jsonErrWord(err error) string {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Sprintf("a syntax error near byte %d", se.Offset)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "the file ends too early"
	}
	return "it could not be decoded"
}

// shapeMessage names the field a typed decode failed on.
func shapeMessage(err error) string {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return fmt.Sprintf("The field %q has the wrong type: expected %s, got %s.", clip(te.Field, 80), te.Type.Kind(), te.Value)
	}
	return "The file does not match the schema."
}

// clip cuts s to at most n runes for an error message, cleaned so a
// message never carries control characters or fence lookalikes.
func clip(s string, n int) string {
	s = clean(s, n+1)
	if utf8.RuneCountInString(s) > n {
		return string([]rune(s)[:n]) + "..."
	}
	return s
}

// redact applies the injected redactor.
func (v *validator) redact(s string) string {
	if v.o.Redact == nil {
		return s
	}
	return v.o.Redact(s)
}

// redactClean is the one order an agent's text goes through before it is
// stored: redact the text as written (a pattern that needs a dash run, a line
// break or a space, as a private key block does, still sees them), clean it,
// redact again, and clean what the redactor returned. Cleaning drops invisible
// format characters, backticks, invalid bytes and dash runs, which can join
// the halves of a token the first pass could not see ("ghp_", a zero-width
// space, the rest); the second redaction catches the joined token before it is
// stored. limit bounds each cleaned text in runes.
func (v *validator) redactClean(s string, limit int) string {
	t, _ := v.redactCleanChanged(s, limit)
	return t
}

// redactCleanChanged is redactClean that also says whether either redaction pass
// changed the text.
func (v *validator) redactCleanChanged(s string, limit int) (string, bool) {
	r1 := v.redact(s)
	c1 := clean(r1, limit)
	r2 := v.redact(c1)
	return clean(r2, limit), r1 != s || r2 != c1
}

// cleanText redacts, cleans and caps a free text. kind names the field for
// the truncation tally.
func (v *validator) cleanText(s string, limit int, kind string) string {
	t, _ := v.cleanTextChanged(s, limit, kind)
	return t
}

// cleanTextChanged is cleanText that also says whether the redactor changed the
// text.
func (v *validator) cleanTextChanged(s string, limit int, kind string) (string, bool) {
	t, changed := v.redactCleanChanged(s, 1<<20)
	if utf8.RuneCountInString(t) > limit {
		v.text[kind]++
		t = strings.TrimSpace(string([]rune(t)[:limit]))
	}
	return t, changed
}
