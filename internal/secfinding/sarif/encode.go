package sarif

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// SchemaURI is the SARIF 2.1.0 schema GitHub code scanning accepts.
const SchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

// ToolInfo names the producer of an exported log.
type ToolInfo struct {
	Name           string
	Version        string
	InformationURI string
}

// Lineage property names in each result's properties bag (section 4.5.3
// "Out": how Observer feeds lineage to the vendors' scanners).
const (
	PropSession     = "superbased/session"
	PropModel       = "superbased/model"
	PropTool        = "superbased/tool"
	PropAttribution = "superbased/inferred_attribution"
	PropTaint       = "superbased/taint_at_write"
	PropPrompt      = "superbased/prompt_action"
	PropCategory    = "superbased/category"
	PropConfidence  = "superbased/confidence"
	PropBaseline    = "superbased/baseline"
	// PropLineageScope says where a result's line lineage sits (lane
	// LEFT-SEC): LineageRegion when the finding has a line, so the region
	// carries the session, model, tool, prompt, attribution and taint of
	// that line; LineageResult for a file-level finding, whose lineage is
	// the result's bag alone.
	PropLineageScope = "superbased/lineage_scope"
)

// The PropLineageScope values.
const (
	LineageRegion = "region"
	LineageResult = "result"
)

// LevelFor maps a finding severity to a SARIF level.
func LevelFor(s secfinding.Severity) string {
	switch s {
	case policy.FindingSeverityCritical, policy.FindingSeverityHigh:
		return "error"
	case policy.FindingSeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity is the GitHub security-severity score per severity.
func securitySeverity(s secfinding.Severity) string {
	switch s {
	case policy.FindingSeverityCritical:
		return "9.5"
	case policy.FindingSeverityHigh:
		return "8.0"
	case policy.FindingSeverityMedium:
		return "5.5"
	case policy.FindingSeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

type outLog struct {
	Schema  string   `json:"$schema"`
	Version string   `json:"version"`
	Runs    []outRun `json:"runs"`
}

type outRun struct {
	Tool       outTool        `json:"tool"`
	Results    []outResult    `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}

// PropWorktree is the result property carrying the per-checkout sighting
// key ("[worktree:<16 hex>]") of a finding in an out-of-tree linked
// worktree (lane LEFT-SEC audit F3); its artifact URI is the relative
// WorktreeURIPrefix form.
const PropWorktree = "superbased/worktree"

// WorktreeURIPrefix is the first segment of the artifact URI of a finding in
// an out-of-tree linked worktree: `.observer-worktree/<16 hex>/<path>`, a
// valid relative URI reference (the store's `[worktree:<hex>]/path`
// sighting path is not one: brackets, and a colon in the first segment,
// which GitHub code scanning drops the whole upload for, decision log
// P-115).
const WorktreeURIPrefix = ".observer-worktree"

// worktreeSighting matches the store's out-of-tree worktree sighting path
// (store.WorktreeSightingPath): its key and the path in that checkout.
var worktreeSighting = regexp.MustCompile(`^(\[worktree:([0-9a-f]{16})\])/(.+)$`)

// ArtifactURI is the SARIF artifact URI of a finding's project-relative
// path: each segment percent-encoded where a URI path segment needs it, and
// an out-of-tree worktree sighting rewritten under WorktreeURIPrefix. key
// is the sighting key ("" for any other path).
func ArtifactURI(rel string) (uri, key string) {
	if m := worktreeSighting.FindStringSubmatch(rel); m != nil {
		return WorktreeURIPrefix + "/" + m[2] + "/" + escapePath(m[3]), m[1]
	}
	return escapePath(rel), ""
}

// escapePath percent-encodes every byte of a slash-separated path that a
// URI path segment does not allow, and a colon too (so no first segment
// reads as a scheme).
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		var b strings.Builder
		for j := 0; j < len(seg); j++ {
			c := seg[j]
			if uriSegmentByte(c) {
				b.WriteByte(c)
				continue
			}
			fmt.Fprintf(&b, "%%%02X", c)
		}
		segs[i] = b.String()
	}
	return strings.Join(segs, "/")
}

// uriSegmentByte reports whether c may stand unescaped in a URI path
// segment (RFC 3986 pchar less ':' and '%'): unreserved, sub-delims, '@'.
func uriSegmentByte(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-._~!$&'()*+,;=@", c) >= 0
}

// uriScheme matches an absolute URI's scheme.
var uriScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// validArtifactURI reports whether u is a URI reference GitHub code
// scanning places: only RFC 3986 characters, every '%' a two-hex escape,
// and, when it is relative, no colon in its first segment and no brackets.
func validArtifactURI(u string) bool {
	if u == "" {
		return false
	}
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c == '%' {
			if i+2 >= len(u) || !isHex(u[i+1]) || !isHex(u[i+2]) {
				return false
			}
			i += 2
			continue
		}
		if !uriSegmentByte(c) && strings.IndexByte(":/?#[]", c) < 0 {
			return false
		}
	}
	if uriScheme.MatchString(u) {
		return true
	}
	first, _, _ := strings.Cut(u, "/")
	return !strings.ContainsAny(first, ":") && !strings.ContainsAny(u, "[]")
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// PropUnlocated is the run property counting the findings left out of the
// results because they name no project-relative file (GitHub code scanning
// rejects a whole upload when any result lacks a physical location).
const PropUnlocated = "superbased/unlocated_findings"

type outTool struct {
	Driver outDriver `json:"driver"`
}

type outDriver struct {
	Name           string    `json:"name"`
	Version        string    `json:"version,omitempty"`
	InformationURI string    `json:"informationUri,omitempty"`
	Rules          []outRule `json:"rules"`
}

type outText struct {
	Text string `json:"text"`
}

type outRule struct {
	ID               string         `json:"id"`
	ShortDescription outText        `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type outResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             outText           `json:"message"`
	Locations           []outLocation     `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type outLocation struct {
	Physical outPhysical `json:"physicalLocation"`
}

type outPhysical struct {
	Artifact outArtifact `json:"artifactLocation"`
	Region   *outRegion  `json:"region,omitempty"`
}

type outArtifact struct {
	URI string `json:"uri"`
}

type outRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
	// Properties is the line's lineage (lane LEFT-SEC), only on a finding
	// that has a line.
	Properties map[string]string `json:"properties,omitempty"`
}

// Encode writes findings as one SARIF 2.1.0 run that GitHub code scanning
// accepts, with Observer's lineage in each result's properties bag and,
// for a finding that has a line, in its region's properties too
// (PropLineageScope, lane LEFT-SEC). Only
// project-relative locations, templated messages and ids are written,
// never evidence (it may be content under the share rules). Every result
// has a physical location with a region (line 1 for a file-level
// finding); a finding with no project-relative file is left out and
// counted in the run property PropUnlocated.
func Encode(findings []secfinding.Finding, tool ToolInfo) ([]byte, error) {
	rules := map[string]outRule{}
	run := outRun{Tool: outTool{Driver: outDriver{Name: tool.Name, Version: tool.Version, InformationURI: tool.InformationURI}}, Results: []outResult{}}
	unlocated := 0
	for _, f := range findings {
		f = secfinding.Normalize(f)
		id := f.Rule.ID
		if id == "" {
			continue
		}
		if f.Location.RelPath == "" {
			unlocated++
			continue
		}
		if _, ok := rules[id]; !ok {
			rules[id] = outRule{
				ID: id, ShortDescription: outText{Text: firstNonEmpty(f.Message, id)},
				Properties: map[string]any{"security-severity": securitySeverity(f.Severity), "tags": []string{"security", string(f.Category)}},
			}
		}
		res := outResult{
			RuleID: id, Level: LevelFor(f.Severity), Message: outText{Text: firstNonEmpty(f.Message, id)},
			Properties: lineage(f),
		}
		if f.EvidenceHash != "" {
			res.PartialFingerprints = map[string]string{"superbased/evidence/v1": f.EvidenceHash}
		}
		start, end := f.Location.StartLine, f.Location.EndLine
		region := &outRegion{StartLine: start, EndLine: end}
		res.Properties[PropLineageScope] = LineageResult
		if start < 1 {
			region.StartLine, region.EndLine = 1, 0
		} else {
			// The line has a place: its lineage rides on the region too, so
			// a consumer that splits results by line keeps it.
			region.Properties = lineLineage(f)
			res.Properties[PropLineageScope] = LineageRegion
		}
		uri, key := ArtifactURI(f.Location.RelPath)
		if key != "" {
			res.Properties[PropWorktree] = key
		}
		res.Locations = []outLocation{{Physical: outPhysical{
			Artifact: outArtifact{URI: uri},
			Region:   region,
		}}}
		run.Results = append(run.Results, res)
	}
	if unlocated > 0 {
		run.Properties = map[string]any{PropUnlocated: unlocated}
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	run.Tool.Driver.Rules = []outRule{}
	for _, id := range ids {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rules[id])
	}
	data, err := json.MarshalIndent(outLog{Schema: SchemaURI, Version: "2.1.0", Runs: []outRun{run}}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sarif.Encode: %w", err)
	}
	return data, nil
}

func lineage(f secfinding.Finding) map[string]string {
	p := map[string]string{
		PropCategory:    string(f.Category),
		PropConfidence:  string(f.Confidence),
		PropBaseline:    string(f.Baseline),
		PropAttribution: string(f.Attribution.Class),
		PropTaint:       strconv.FormatBool(f.TaintAtWrite.Tainted),
	}
	for k, v := range map[string]string{PropSession: f.Lineage.SessionID, PropModel: f.Lineage.Model, PropTool: f.Lineage.Tool, PropPrompt: f.Lineage.PromptActionID} {
		if v != "" {
			p[k] = v
		}
	}
	return p
}

// lineLineage is the lineage of a finding's line: who wrote it (session,
// model, tool, prompt action), how that was told (attribution class) and
// whether the write was tainted. Ids and closed values only.
func lineLineage(f secfinding.Finding) map[string]string {
	p := map[string]string{
		PropAttribution: string(f.Attribution.Class),
		PropTaint:       strconv.FormatBool(f.TaintAtWrite.Tainted),
	}
	for k, v := range map[string]string{PropSession: f.Lineage.SessionID, PropModel: f.Lineage.Model, PropTool: f.Lineage.Tool, PropPrompt: f.Lineage.PromptActionID} {
		if v != "" {
			p[k] = v
		}
	}
	return p
}

// LocationProblems lists the results of a SARIF log that GitHub code
// scanning would reject the whole upload for (decision log P-115): every
// result needs a physical location with a valid artifact URI reference
// (validArtifactURI; lane LEFT-SEC audit F3) and a region whose start line
// is 1 or more. It reads only the fields it checks; a log that
// does not parse is one problem.
func LocationProblems(data []byte) []string {
	var lg struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					Physical *struct {
						Artifact *struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &lg); err != nil {
		return []string{"not a SARIF log: " + err.Error()}
	}
	var out []string
	for ri, run := range lg.Runs {
		for i, r := range run.Results {
			ok := len(r.Locations) > 0
			for _, l := range r.Locations {
				if l.Physical == nil || l.Physical.Artifact == nil || l.Physical.Artifact.URI == "" || l.Physical.Region == nil || l.Physical.Region.StartLine < 1 {
					ok = false
				}
			}
			if !ok {
				out = append(out, fmt.Sprintf("run %d result %d (%s): no physical location with a file and a start line", ri, i, r.RuleID))
				continue
			}
			for _, l := range r.Locations {
				if u := l.Physical.Artifact.URI; !validArtifactURI(u) {
					out = append(out, fmt.Sprintf("run %d result %d (%s): artifact URI %q is not a valid URI reference", ri, i, r.RuleID, u))
					break
				}
			}
		}
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
