package secassess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Caps on the agent's SARIF file. The import's own decoder caps it again; the
// result cap is the import's (a driver keeps at most 1000 results).
const (
	MaxSARIFBytes   = 32 << 20
	maxSARIFDepth   = 64
	maxSARIFRuns    = 16
	maxRunResults   = 10000
	MaxKeptResults  = 1000
	maxRuleSuffix   = 64
	maxLine         = 10_000_000
	maxURIBytes     = 1024
	fingerprintName = "assess/v1"
)

// SARIF preparation errors.
var (
	ErrSARIFTooLarge = errors.New("secassess: the SARIF file is over its size cap")
	ErrSARIFTooDeep  = errors.New("secassess: the SARIF file is nested too deeply")
	ErrNotSARIF      = errors.New("secassess: not a SARIF 2.1.0 document")
	ErrNoPreparable  = errors.New("secassess: the SARIF file holds no usable result")
)

// Prepared is the SARIF document the import is handed, with what the
// preparation kept, refused and dropped.
type Prepared struct {
	// Data is the new SARIF document.
	Data []byte
	// Kept is the number of results in Data.
	Kept int
	// Refused counts refused results by closed reason.
	Refused map[string]int
	// Dropped counts results the parse could not read at all.
	Dropped int
	// Truncated: more usable results existed than MaxKeptResults.
	Truncated bool
}

type inLog struct {
	Version string  `json:"version"`
	Runs    []inRun `json:"runs"`
}

// inRule is one rule of the agent's driver. Properties stay raw: a malformed
// properties value must never refuse the whole file, only lose its tags.
type inRule struct {
	ID         string          `json:"id"`
	Properties json.RawMessage `json:"properties"`
}

type inRun struct {
	Tool struct {
		Driver struct {
			Rules []inRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []json.RawMessage `json:"results"`
}

type inResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Level     string `json:"level"`
	Locations []struct {
		Physical struct {
			Artifact struct {
				URI       string `json:"uri"`
				URIBaseID string `json:"uriBaseId"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
				EndLine   int `json:"endLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

type outLog struct {
	Schema  string   `json:"$schema"`
	Version string   `json:"version"`
	Runs    []outRun `json:"runs"`
}

type outRun struct {
	Tool    outTool     `json:"tool"`
	Results []outResult `json:"results"`
}

type outTool struct {
	Driver struct {
		Name    string    `json:"name"`
		Version string    `json:"version"`
		Rules   []outRule `json:"rules,omitempty"`
	} `json:"driver"`
}

// outRule is the metadata the import reads back for a rule: its rewritten id
// and its CWE tags, nothing else (no description or help text, which the
// import never keeps and the agent controls).
type outRule struct {
	ID         string       `json:"id"`
	Properties outRuleProps `json:"properties"`
}

type outRuleProps struct {
	Tags []string `json:"tags"`
}

type outResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   outText           `json:"message"`
	Locations []outLocation     `json:"locations"`
	Partial   map[string]string `json:"partialFingerprints"`
}

type outText struct {
	Text string `json:"text"`
}

type outLocation struct {
	Physical struct {
		Artifact struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *outRegion `json:"region,omitempty"`
	} `json:"physicalLocation"`
}

type outRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

// sarifDepth is the deepest JSON nesting in data (strings are skipped).
func sarifDepth(data []byte) int {
	depth, max := 0, 0
	inStr, esc := false, false
	for _, c := range data {
		switch {
		case inStr:
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '{' || c == '[':
			depth++
			if depth > max {
				max = depth
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return max
}

// levelFor maps an agent's severity word to a SARIF level. The import's level
// map knows only error, warning, note and none and would read any other word
// as its lowest severity, so the words are mapped here.
func levelFor(word string) string {
	switch strings.ToLower(strings.TrimSpace(word)) {
	case "error", "critical", "high":
		return "error"
	case "warning", "medium", "moderate":
		return "warning"
	default:
		return "note"
	}
}

// cleanRuleSuffix cleans an agent's rule id to [A-Za-z0-9._:-], at most
// maxRuleSuffix bytes, "unnamed" when nothing is left.
func cleanRuleSuffix(s string) string {
	var b strings.Builder
	last := byte(0)
	for i := 0; i < len(s) && b.Len() < maxRuleSuffix; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == ':':
		default:
			c = '-'
		}
		if c == '-' && (last == '-' || b.Len() == 0) {
			continue
		}
		b.WriteByte(c)
		last = c
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unnamed"
	}
	return out
}

// RuleID is the imported rule id (before the import's own "other/" prefix):
// assess.<tag>.<run id>.<cleaned original>.
func RuleID(tag, runID, original string) string {
	return "assess." + tag + "." + runID + "." + cleanRuleSuffix(original)
}

// relPath normalizes an agent's artifact URI to a project-relative,
// slash-separated path, or returns the closed reason it was refused.
func relPath(uri string) (string, string) {
	if uri == "" {
		return "", "empty_uri"
	}
	if len(uri) > maxURIBytes {
		return "", "uri_too_long"
	}
	for _, r := range uri {
		if hiddenPathRune(r) {
			return "", "control_character"
		}
	}
	u := strings.ReplaceAll(uri, "\\", "/")
	if strings.ContainsAny(u, "?#") {
		return "", "query_or_fragment"
	}
	if i := strings.Index(u, ":"); i >= 0 && (!strings.Contains(u[:i], "/") || i == 1) {
		return "", "absolute_or_remote"
	}
	if strings.HasPrefix(u, "/") {
		return "", "absolute_or_remote"
	}
	var parts []string
	for _, seg := range strings.Split(u, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			return "", "parent_segment"
		}
		parts = append(parts, seg)
	}
	if len(parts) == 0 {
		return "", "empty_uri"
	}
	return strings.Join(parts, "/"), ""
}

// rootBase reports whether a uriBaseId names the project root.
func rootBase(id string) bool {
	switch id {
	case "", "%SRCROOT%", "SRCROOT", "PROJECTROOT":
		return true
	}
	return false
}

// preparer collects the usable results of one findings file. It holds the
// state the per-result rules share (the refusal counts, the fingerprints seen,
// the results kept) so each rule is a small function and PrepareSARIF stays a
// short pipeline.
type preparer struct {
	kind    Kind
	runID   string
	out     Prepared
	results []outResult
	seen    map[string]bool
	// runRules maps the current run's agent rule ids to their CWE tags (set by
	// addRun); rules and ruleOrder are the emitted rule metadata, keyed by the
	// rewritten rule id, in first-use order.
	runRules  map[string][]string
	rules     map[string][]string
	ruleOrder []string
}

// maxRuleTags caps the CWE tags emitted for one rule.
const maxRuleTags = 8

// cweTagID reads the CWE number out of an agent's rule tag: any case, with or
// without the SARIF "external/cwe/" prefix, optionally followed by ":" or a
// space and a title. "" when the tag is not a well-formed CWE id (one to five
// digits, not zero).
func cweTagID(tag string) string {
	t := strings.ToLower(strings.TrimSpace(tag))
	t = strings.TrimPrefix(t, "external/cwe/")
	t, ok := strings.CutPrefix(t, "cwe-")
	if !ok {
		return ""
	}
	n := 0
	for n < len(t) && t[n] >= '0' && t[n] <= '9' {
		n++
	}
	if n == 0 || n > 5 || (n < len(t) && t[n] != ':' && t[n] != ' ') {
		return ""
	}
	v, err := strconv.Atoi(t[:n])
	if err != nil || v == 0 {
		return ""
	}
	return strconv.Itoa(v)
}

// ruleCWETags returns the canonical CWE tags ("external/cwe/cwe-79") of an
// agent rule's properties.tags, de-duplicated, at most maxRuleTags; every other
// tag, and a properties value that is not the expected shape, is dropped.
func ruleCWETags(props json.RawMessage) []string {
	var p struct {
		Tags []string `json:"tags"`
	}
	if len(props) == 0 || json.Unmarshal(props, &p) != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, t := range p.Tags {
		id := cweTagID(t)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, "external/cwe/cwe-"+id)
		if len(out) == maxRuleTags {
			break
		}
	}
	return out
}

// noteRule records the CWE tags of a kept result's rule under its rewritten id.
func (p *preparer) noteRule(ruleID string, tags []string) {
	if len(tags) == 0 {
		return
	}
	if _, ok := p.rules[ruleID]; ok {
		return
	}
	p.rules[ruleID] = tags
	p.ruleOrder = append(p.ruleOrder, ruleID)
}

func (p *preparer) refuse(why string) { p.out.Refused[why]++ }

// resultRuleID is the agent's rule id of a result, resolved through ruleIndex
// when the result has no ruleId of its own ("" when there is none).
func resultRuleID(r inResult, run inRun) string {
	if r.RuleID != "" {
		return r.RuleID
	}
	rules := run.Tool.Driver.Rules
	if r.RuleIndex != nil && *r.RuleIndex >= 0 && *r.RuleIndex < len(rules) {
		return rules[*r.RuleIndex].ID
	}
	return ""
}

// place is a result's checked location: a project-relative path and a line
// range.
type place struct {
	rel    string
	sl, el int
}

// resultPlace checks a result's first location; why is the closed refusal
// reason, "" when the location is usable.
func resultPlace(r inResult) (p place, why string) {
	if len(r.Locations) == 0 {
		return place{}, "no_location"
	}
	loc := r.Locations[0].Physical
	if !rootBase(loc.Artifact.URIBaseID) {
		return place{}, "foreign_base_id"
	}
	rel, why := relPath(loc.Artifact.URI)
	if why != "" {
		return place{}, why
	}
	sl, el := loc.Region.StartLine, loc.Region.EndLine
	if sl < 0 || sl > maxLine || el < 0 || el > maxLine {
		return place{}, "line_out_of_range"
	}
	if el < sl {
		el = sl
	}
	return place{rel: rel, sl: sl, el: el}, ""
}

// addResult applies the refusal rules, in order, to one raw result and keeps
// it when none refuses.
func (p *preparer) addResult(raw json.RawMessage, run inRun) {
	var r inResult
	if json.Unmarshal(raw, &r) != nil {
		p.out.Dropped++
		return
	}
	id := resultRuleID(r, run)
	if strings.TrimSpace(id) == "" {
		p.refuse("no_rule_id")
		return
	}
	pl, why := resultPlace(r)
	if why != "" {
		p.refuse(why)
		return
	}
	ruleID := RuleID(p.kind.Tag, p.runID, id)
	tags := p.runRules[id]
	sum := sha256.Sum256([]byte(ruleID + "\x00" + pl.rel + "\x00" + strconv.Itoa(pl.sl)))
	fp := hex.EncodeToString(sum[:8])
	if p.seen[fp] {
		p.refuse("duplicate")
		return
	}
	p.seen[fp] = true
	if len(p.results) >= MaxKeptResults {
		p.out.Truncated = true
		return
	}
	p.noteRule(ruleID, tags)
	var ol outLocation
	ol.Physical.Artifact.URI = pl.rel
	if pl.sl > 0 {
		ol.Physical.Region = &outRegion{StartLine: pl.sl, EndLine: pl.el}
	}
	p.results = append(p.results, outResult{
		RuleID: ruleID, Level: levelFor(r.Level),
		Message:   outText{Text: "Reported in assessment " + p.runID},
		Partial:   map[string]string{fingerprintName: fp},
		Locations: []outLocation{ol},
	})
}

// addRun reads one run's results, at most maxRunResults of them.
func (p *preparer) addRun(run inRun) {
	p.runRules = map[string][]string{}
	for _, r := range run.Tool.Driver.Rules {
		if _, dup := p.runRules[r.ID]; !dup && r.ID != "" {
			p.runRules[r.ID] = ruleCWETags(r.Properties)
		}
	}
	raws := run.Results
	if len(raws) > maxRunResults {
		p.out.Dropped += len(raws) - maxRunResults
		raws = raws[:maxRunResults]
	}
	for _, raw := range raws {
		p.addResult(raw, run)
	}
}

// prepareChecks are the file-level refusals of PrepareSARIF, in order: each
// returns the error that refuses the file, nil to go on.
var prepareChecks = []func(data []byte, k Kind, runID string) error{
	func(_ []byte, k Kind, _ string) error {
		if !k.Launchable || !k.HasSARIF() {
			return errors.New("secassess.PrepareSARIF: this kind has no SARIF file")
		}
		return nil
	},
	func(_ []byte, _ Kind, runID string) error {
		if !ValidRunID(runID) {
			return errors.New("secassess.PrepareSARIF: bad run id")
		}
		return nil
	},
	func(data []byte, _ Kind, _ string) error {
		if len(data) > MaxSARIFBytes {
			return ErrSARIFTooLarge
		}
		return nil
	},
	func(data []byte, _ Kind, _ string) error {
		if sarifDepth(data) > maxSARIFDepth {
			return ErrSARIFTooDeep
		}
		return nil
	},
}

// PrepareSARIF turns the agent's findings.sarif into the document the SARIF
// import is handed: one run, and per usable result only a rewritten rule id,
// a level, one project-relative location and a fingerprint. Everything else
// in the agent's file, message text included, is dropped. Nothing here reads
// a path or the network.
func PrepareSARIF(data []byte, kind ID, runID string) (Prepared, error) {
	k, ok := KindByID(string(kind))
	if !ok {
		return Prepared{}, errors.New("secassess.PrepareSARIF: this kind has no SARIF file")
	}
	for _, check := range prepareChecks {
		if err := check(data, k, runID); err != nil {
			return Prepared{}, err
		}
	}
	var log inLog
	if err := json.Unmarshal(data, &log); err != nil || log.Version != "2.1.0" {
		return Prepared{}, ErrNotSARIF
	}
	p := &preparer{kind: k, runID: runID, out: Prepared{Refused: map[string]int{}}, seen: map[string]bool{}, rules: map[string][]string{}}
	runs := log.Runs
	if len(runs) > maxSARIFRuns {
		runs = runs[:maxSARIFRuns]
	}
	for _, run := range runs {
		p.addRun(run)
	}
	if len(p.results) == 0 {
		return p.out, ErrNoPreparable
	}
	doc := outLog{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0", Runs: []outRun{{Results: p.results}}}
	doc.Runs[0].Tool.Driver.Name = "observer-assessment"
	doc.Runs[0].Tool.Driver.Version = string(k.ID)
	for _, id := range p.ruleOrder {
		doc.Runs[0].Tool.Driver.Rules = append(doc.Runs[0].Tool.Driver.Rules, outRule{ID: id, Properties: outRuleProps{Tags: p.rules[id]}})
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return p.out, fmt.Errorf("secassess.PrepareSARIF: %w", err)
	}
	p.out.Data, p.out.Kept = b, len(p.results)
	return p.out, nil
}

// RefusedList renders a refusal map as "reason: n" in reason order (a stable
// shape for the run row).
func RefusedList(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+": "+strconv.Itoa(m[k]))
	}
	return out
}

// hiddenPathRune reports a rune no project path needs and that hides what a
// path says when it is shown: a control character, a format character (zero
// width, bidi, soft hyphen), a line or paragraph separator, or a backtick (it
// would end a code span in any text that quotes the path).
func hiddenPathRune(r rune) bool {
	return r < 0x20 || r == 0x7f || r == '`' || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029
}
