package secverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// SARIF output (security plan 4.5.3 "Out"). Every struct below lists the
// only fields verify ever writes: there is no snippet, no context region,
// no code flow, no fix and no attachment field, so no repository content
// can reach the file by construction (pinned by a test over the encoded
// bytes).

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
	// ToolName is the SARIF tool.driver.name.
	ToolName = "SuperBased Observer security verify"
	// srcRoot is the uriBaseId every location is relative to.
	srcRoot = "%SRCROOT%"
	// FingerprintKey is the partialFingerprints key.
	FingerprintKey = "superbased/v1"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool         `json:"tool"`
	AutomationDetails sarifAutomation   `json:"automationDetails"`
	Invocations       []sarifInvocation `json:"invocations"`
	Results           []sarifResult     `json:"results"`
	Properties        map[string]any    `json:"properties"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	DefaultConfiguration sarifLevel     `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifLevel struct {
	Level string `json:"level"`
}

type sarifAutomation struct {
	ID string `json:"id"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                `json:"executionSuccessful"`
	Notifications       []sarifNotification `json:"toolExecutionNotifications"`
}

type sarifNotification struct {
	Descriptor sarifDescriptor `json:"descriptor"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Properties map[string]any  `json:"properties"`
}

type sarifDescriptor struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

// sarifLogical names a commit, for the provenance results. It rides beside
// their physical location, never in place of it: code scanning rejects the
// whole upload when a result has no physical location.
type sarifLogical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifPhysical struct {
	ArtifactLocation sarifAL     `json:"artifactLocation"`
	Region           sarifRegion `json:"region"`
}

type sarifAL struct {
	URI       string `json:"uri,omitempty"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// securitySeverity is GitHub code scanning's numeric severity per level.
var securitySeverity = map[Severity]string{
	SeverityCritical: "9.5",
	SeverityHigh:     "8.0",
	SeverityMedium:   "5.5",
	SeverityLow:      "3.0",
	SeverityInfo:     "1.0",
}

// sarifResultLevel maps an action and severity to a SARIF level: a deny is
// an error; a flag is a warning from medium up and a note below.
func sarifResultLevel(a Action, s Severity) string {
	switch {
	case a == ActionDeny:
		return "error"
	case s == SeverityLow || s == SeverityInfo:
		return "note"
	}
	return "warning"
}

// coverageLevel maps a detector's coverage to a notification level.
var coverageLevel = map[CoverageStatus]string{
	CoverageComplete:   "note",
	CoverageOff:        "note",
	CoverageNotInBuild: "warning",
	CoveragePartial:    "warning",
	CoverageFailed:     "error",
}

// WriteSARIF writes the report as SARIF 2.1.0. root is the absolute
// project root with forward slashes; every finding path goes through
// ProjectRelPath against it, and a path it refuses fails the write (the
// caller then exits unknown) rather than reaching the file. version is the
// observer release version, empty for a development build.
func WriteSARIF(w io.Writer, rep Report, root, version string) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:            ToolName,
			InformationURI:  "https://superbased.app",
			SemanticVersion: strings.TrimPrefix(version, "v"),
			Rules:           []sarifRule{},
		}},
		AutomationDetails: sarifAutomation{ID: "observer-security-verify/"},
		Results:           []sarifResult{},
		Properties: map[string]any{
			"superbased/verdict":       string(rep.Verdict),
			"superbased/verdict_rule":  rep.Rule,
			"superbased/policy_source": string(rep.Policy.Source),
			"superbased/mode":          string(rep.Policy.Mode),
			"superbased/base":          clipSafe(rep.Base, 64),
			"superbased/head":          clipSafe(rep.Head, 64),
			"superbased/files":         rep.Files,
		},
	}
	// The versions the run used (lane LEFT2-SEC item R-019): the org's
	// signed CI policy version when the policy came from the org, and the
	// native detector pack, which is compiled into the release, so its
	// version is the release's (none on a development build). The result
	// upload reads both from here and the org checks them.
	if rep.Policy.Source == SourceOrg && rep.Policy.OrgVersion > 0 {
		run.Properties["superbased/policy_version"] = rep.Policy.OrgVersion
	}
	if pack := strings.TrimPrefix(version, "v"); pack != "" {
		run.Properties["superbased/pack_version"] = pack
	}
	// An empty result list is not "clean": the invocation says whether the
	// run finished, and every detector's coverage is a notification.
	inv := sarifInvocation{ExecutionSuccessful: rep.Verdict != VerdictUnknown, Notifications: []sarifNotification{}}
	if rep.Error != "" {
		inv.Notifications = append(inv.Notifications, sarifNotification{
			Descriptor: sarifDescriptor{ID: "verify"},
			Level:      "error",
			Message:    sarifText{Text: "The change could not be read: " + rep.Error},
			Properties: map[string]any{},
		})
	}
	if rep.Verdict == VerdictUnknown {
		inv.Notifications = append(inv.Notifications, sarifNotification{
			Descriptor: sarifDescriptor{ID: "verify"},
			Level:      "error",
			Message:    sarifText{Text: "Verdict unknown: " + rep.Reason + ". This run proves nothing about the change; an empty result list here is not a clean result."},
			Properties: map[string]any{"superbased/verdict_rule": rep.Rule},
		})
	}
	for _, c := range rep.Coverage {
		msg := fmt.Sprintf("Detector %s: %s, %d file(s) read", c.Detector, c.Status, c.Files)
		if c.Skipped > 0 {
			msg += fmt.Sprintf(", %d skipped (%s)", c.Skipped, c.SkipReason)
		}
		if c.Note != "" {
			msg += "; " + c.Note
		}
		inv.Notifications = append(inv.Notifications, sarifNotification{
			Descriptor: sarifDescriptor{ID: c.Detector},
			Level:      coverageLevel[c.Status],
			Message:    sarifText{Text: msg},
			Properties: map[string]any{"superbased/coverage": string(c.Status)},
		})
	}
	run.Invocations = []sarifInvocation{inv}

	ruleIndex := map[string]int{}
	for _, f := range rep.Findings {
		rel, err := ProjectRelPath(root, f.Path)
		if err != nil {
			return fmt.Errorf("secverify.WriteSARIF: finding %s: %w", f.RuleID, err)
		}
		idx, ok := ruleIndex[f.RuleID]
		if !ok {
			idx = len(run.Tool.Driver.Rules)
			ruleIndex[f.RuleID] = idx
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:                   f.RuleID,
				Name:                 ruleName(f.RuleID),
				ShortDescription:     sarifText{Text: ruleDescription(f)},
				DefaultConfiguration: sarifLevel{Level: sarifResultLevel(f.DefaultAction, f.Severity)},
				Properties: map[string]any{
					"tags":              []string{"security", string(f.Category)},
					"security-severity": securitySeverity[f.Severity],
				},
			})
		}
		line := f.Line
		if line < 1 {
			line = 1
		}
		props := map[string]any{
			"superbased/detector":   f.Detector,
			"superbased/category":   string(f.Category),
			"superbased/severity":   string(f.Severity),
			"superbased/confidence": string(f.Confidence),
			"superbased/action":     string(f.Action),
		}
		if f.Lowered != "" {
			props["superbased/lowered"] = f.Lowered
		}
		run.Results = append(run.Results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: idx,
			Level:     sarifResultLevel(f.Action, f.Severity),
			Message:   sarifText{Text: f.Message},
			Locations: []sarifLocation{{PhysicalLocation: &sarifPhysical{
				ArtifactLocation: sarifAL{URI: RelURI(rel), URIBaseID: srcRoot},
				Region:           sarifRegion{StartLine: line},
			}}},
			PartialFingerprints: map[string]string{FingerprintKey: f.Fingerprint},
			Properties:          props,
		})
	}
	addProvenanceResults(&run, rep.Provenance)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}}); err != nil {
		return fmt.Errorf("secverify.WriteSARIF: %w", err)
	}
	return nil
}

// The provenance SARIF rule ids (lane SEC-F2B): stable, one per outcome a
// reviewer needs to see. They report; they never change the verdict, which
// the verdict table decides from the same counts (P-059: a failed record
// fails whatever the floor; a missing one only under the floor "fail").
const (
	RuleProvenanceFailed  = "provenance/verification_failed"
	RuleProvenanceUnknown = "provenance/unknown_provenance"
)

// provenanceRules are the two rules' closed descriptions and levels.
var provenanceRules = map[secchange.Provenance]struct {
	id, desc, level, severity string
}{
	secchange.ProvenanceFailed:  {RuleProvenanceFailed, "A commit carries an AI change record that fails verification (forged, revoked or expired key, or bound to another commit)", "error", "8.0"},
	secchange.ProvenanceUnknown: {RuleProvenanceUnknown, "A commit carries no verified AI change record (node-reported attribution is missing)", "note", "1.0"},
}

// ProvenanceFallbackPath is where a provenance result is located when its
// commit changes no file and its tree has no root README: the policy file
// path the workflow template uses.
const ProvenanceFallbackPath = DefaultPolicyPath

// readmeNames are the root README names ProvenanceAnchor tries, in order.
var readmeNames = []string{"README.md", "README", "README.rst", "README.txt", "README.adoc"}

// ProvenanceAnchor picks the file a commit's provenance SARIF result is
// located at. GitHub code scanning rejects a whole upload when any result
// lacks a physical location (the analysis is dropped, its secret findings
// with it), so a result about a commit still needs a file: the first path
// the commit changes, in sorted byte order (changed); for a commit that
// changes no file, the first root README of its tree (rootEntries, in the
// readmeNames order); else "" and the writer uses ProvenanceFallbackPath.
// A path ValidRelPath refuses is skipped.
func ProvenanceAnchor(changed, rootEntries []string) string {
	ok := make([]string, 0, len(changed))
	for _, p := range changed {
		if ValidRelPath(p) == nil {
			ok = append(ok, p)
		}
	}
	if len(ok) > 0 {
		sort.Strings(ok)
		return ok[0]
	}
	present := map[string]bool{}
	for _, e := range rootEntries {
		present[e] = true
	}
	for _, n := range readmeNames {
		if present[n] {
			return n
		}
	}
	return ""
}

// addProvenanceResults adds one result per commit whose change record is
// missing or fails. Each is located at a file (ProvenanceAnchor, line 1)
// AND by the commit (a logical location, commit/<sha>). Closed text and
// codes only.
func addProvenanceResults(run *sarifRun, p ProvenanceReport) {
	if !p.Checked {
		return
	}
	idx := map[string]int{}
	for _, c := range p.Commits {
		r, ok := provenanceRules[c.Provenance]
		if !ok {
			continue
		}
		i, seen := idx[r.id]
		if !seen {
			i = len(run.Tool.Driver.Rules)
			idx[r.id] = i
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID: r.id, Name: ruleName(r.id), ShortDescription: sarifText{Text: r.desc},
				DefaultConfiguration: sarifLevel{Level: r.level},
				Properties:           map[string]any{"tags": []string{"security", "provenance"}, "security-severity": r.severity},
			})
		}
		sha := clipSafe(c.SHA, 64)
		msg := fmt.Sprintf("Commit %s: %s (%s).", shortSHA(sha), c.Provenance, clipSafe(c.Reason, 64))
		if len(c.Errors) > 0 {
			msg += " Refused: " + clipSafe(strings.Join(c.Errors, ", "), 200) + "."
		}
		sum := sha256.Sum256([]byte("provenance|" + r.id + "|" + sha))
		anchor := c.Path
		if ValidRelPath(anchor) != nil {
			anchor = ProvenanceFallbackPath
		}
		run.Results = append(run.Results, sarifResult{
			RuleID: r.id, RuleIndex: i, Level: r.level, Message: sarifText{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: &sarifPhysical{
					ArtifactLocation: sarifAL{URI: RelURI(anchor), URIBaseID: srcRoot},
					Region:           sarifRegion{StartLine: 1},
				},
				LogicalLocations: []sarifLogical{{FullyQualifiedName: "commit/" + sha, Kind: "module"}},
			}},
			PartialFingerprints: map[string]string{FingerprintKey: hex.EncodeToString(sum[:16])},
			Properties:          map[string]any{"superbased/provenance": string(c.Provenance), "superbased/commit": sha, "superbased/floor": string(p.Floor)},
		})
	}
}

// ruleName turns "secret/aws_access_key" into "SecretAwsAccessKey".
func ruleName(id string) string {
	var b strings.Builder
	up := true
	for _, r := range id {
		switch {
		case r == '/' || r == '_' || r == '-' || r == '.':
			up = true
		case up && r >= 'a' && r <= 'z':
			b.WriteRune(r - 'a' + 'A')
			up = false
		default:
			b.WriteRune(r)
			up = false
		}
	}
	return b.String()
}

// ruleDescription is the rule's one-line description, from closed data.
func ruleDescription(f Finding) string {
	_, tail, _ := strings.Cut(f.RuleID, "/")
	switch f.Category {
	case CategorySecret:
		return "A credential with the shape of a " + typeLabel(tail) + " added to the repository"
	case CategoryAgentConfig:
		return "An agent " + strings.ReplaceAll(clipSafe(tail, 32), "_", " ") + " file a coding agent loads from the repository was added or changed"
	}
	return "Observer security finding (" + clipSafe(string(f.Category), 32) + ")"
}

// WriteSummary writes the human summary verify prints on stdout. Paths
// are quoted and capped (QuotePath); every other word is from closed
// tables or templates.
func WriteSummary(w io.Writer, rep Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "observer security verify: %s (%s: %s)\n", strings.ToUpper(string(rep.Verdict)), rep.Rule, rep.Reason)
	fmt.Fprintf(&b, "  base %s  head %s  policy %s  mode %s  files %d\n",
		shortSHA(rep.Base), shortSHA(rep.Head), rep.Policy.Source, rep.Policy.Mode, rep.Files)
	if rep.Policy.Source == SourceBaseCommit {
		b.WriteString("  ADVISORY: the policy was read from the base commit of a repository-local setup; this check binds only as a required workflow from a protected repository.\n")
	}
	if rep.Error != "" {
		fmt.Fprintf(&b, "  error: %s\n", rep.Error)
	}
	if len(rep.Findings) > 0 {
		b.WriteString("findings:\n")
	}
	for _, f := range rep.Findings {
		loc := QuotePath(f.Path)
		if f.Line > 0 {
			loc += fmt.Sprintf(":%d", f.Line)
		}
		lowered := ""
		if f.Lowered != "" {
			lowered = " (lowered: " + f.Lowered + ")"
		}
		fmt.Fprintf(&b, "  %-4s %s %s %s/%s%s\n", f.Action, f.RuleID, loc, f.Severity, f.Confidence, lowered)
	}
	writeProvenanceSummary(&b, rep.Provenance)
	b.WriteString("coverage:\n")
	for _, c := range rep.Coverage {
		note := ""
		if c.Note != "" {
			note = "  " + c.Note
		}
		if c.Skipped > 0 {
			note += fmt.Sprintf("  (%d skipped: %s)", c.Skipped, c.SkipReason)
		}
		fmt.Fprintf(&b, "  %-15s %-13s %d file(s)%s\n", c.Detector, c.Status, c.Files, note)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func shortSHA(s string) string {
	s = clipSafe(s, 64)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// writeProvenanceSummary adds the change record lines: one per commit,
// the label, and the squash statement's inputs. Closed codes only.
func writeProvenanceSummary(b *strings.Builder, p ProvenanceReport) {
	if !p.Checked {
		b.WriteString("provenance: not checked (no --keys file or org policy named)\n")
		return
	}
	fmt.Fprintf(b, "provenance: %d verified, %d unknown_provenance, %d verification_failed (floor %s)", p.Verified, p.Unknown, p.Failed, p.Floor)
	if p.Label != "" {
		fmt.Fprintf(b, ", label %s", p.Label)
	}
	b.WriteString("\n")
	for _, c := range p.Commits {
		extra := ""
		if c.Trailer != "" {
			extra = "  (Assisted-by trailer, unsigned)"
		}
		if c.Countersigned {
			extra += "  (org countersigned)"
		}
		if len(c.Errors) > 0 {
			extra += "  refused: " + strings.Join(c.Errors, ", ")
		}
		fmt.Fprintf(b, "  %s %-18s %s%s\n", shortSHA(c.SHA), c.Provenance, c.Reason, extra)
	}
	if p.Truncated {
		fmt.Fprintf(b, "  (more than %d commits: the rest were not checked)\n", MaxProvenanceCommits)
	}
	fmt.Fprintf(b, "  squash statement: %d verified input record(s), %d unverified commit(s)\n", len(p.Squash.Inputs), p.Squash.Unverified)
	if len(p.TrustIssues) > 0 {
		fmt.Fprintf(b, "  keys file: %d entr(ies) dropped\n", len(p.TrustIssues))
	}
	if o := p.Org; o != nil {
		fmt.Fprintf(b, "  org %s policy v%d, lookup %s: %d countersigned, %d not countersigned, %d without envelope, %d refused by the org\n",
			clipSafe(o.OrgID, 64), o.PolicyVersion, o.Lookup, o.Countersigned, o.Pending, o.EnvelopeMissing, o.Refused)
	}
}
