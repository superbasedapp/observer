package depscan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// Group is one package's advisories folded by alias: every id that names
// the same flaw (an advisory's own id and its aliases, transitively).
type Group struct {
	// Index is the ChildResponse.Packages index of the package.
	Index int
	// IDs are every id in the group, sorted.
	IDs []string
	// Primary is the id the finding carries (idPreference).
	Primary string
	// Severity is the strongest severity label of the group's advisories.
	Severity secfinding.Severity
}

// idPreference orders an id's prefix for Primary: a CVE names the flaw
// across databases, then the GitHub advisory, then the ecosystem's own.
var idPreference = []string{"CVE-", "GHSA-", "GO-", "PYSEC-", "RUSTSEC-", "MAL-"}

func idRank(id string) int {
	for i, p := range idPreference {
		if strings.HasPrefix(id, p) {
			return i
		}
	}
	return len(idPreference)
}

// validID reports whether an advisory id is safe to carry as a rule id
// (secscan's rule-id charset, at most 128 bytes): engine text never
// reaches a finding otherwise.
func validID(id string) bool {
	if id == "" || len(id) > secfinding.MaxRuleID {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-', c == ':':
		default:
			return false
		}
	}
	return true
}

// severityLabels maps advisory severity labels (GHSA's database_specific
// severity, osv-scanner's max_severity bands) onto the finding vocabulary.
var severityLabels = map[string]secfinding.Severity{
	"critical": policy.FindingSeverityCritical,
	"high":     policy.FindingSeverityHigh,
	"moderate": policy.FindingSeverityMedium,
	"medium":   policy.FindingSeverityMedium,
	"low":      policy.FindingSeverityLow,
}

// severityRank orders severities, weakest first.
func severityRank(s secfinding.Severity) int {
	for i, v := range policy.FindingSeverities() {
		if v == s {
			return i
		}
	}
	return -1
}

// GroupByAliases folds each package's advisories by shared ids. It never
// compares versions; it only joins ids that the advisories themselves say
// are the same flaw. defaultSeverity is used for a group with no label.
func GroupByAliases(advs []Advisory, defaultSeverity secfinding.Severity) []Group {
	byPkg := map[int][]Advisory{}
	for _, a := range advs {
		byPkg[a.Index] = append(byPkg[a.Index], a)
	}
	idxs := make([]int, 0, len(byPkg))
	for i := range byPkg {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	var out []Group
	for _, i := range idxs {
		out = append(out, groupOne(i, byPkg[i], defaultSeverity)...)
	}
	return out
}

func groupOne(index int, advs []Advisory, def secfinding.Severity) []Group {
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if parent[x] == "" || parent[x] == x {
			parent[x] = x
			return x
		}
		r := find(parent[x])
		parent[x] = r
		return r
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra != rb {
			if ra < rb {
				parent[rb] = ra
			} else {
				parent[ra] = rb
			}
		}
	}
	sev := map[string]secfinding.Severity{}
	for _, a := range advs {
		if !validID(a.ID) {
			continue
		}
		find(a.ID)
		for _, al := range a.Aliases {
			if validID(al) {
				union(a.ID, al)
			}
		}
		if s, ok := severityLabels[strings.ToLower(strings.TrimSpace(a.Severity))]; ok {
			if cur, has := sev[a.ID]; !has || severityRank(s) > severityRank(cur) {
				sev[a.ID] = s
			}
		}
	}
	members := map[string][]string{}
	for id := range parent {
		r := find(id)
		members[r] = append(members[r], id)
	}
	roots := make([]string, 0, len(members))
	for r := range members {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	var out []Group
	for _, r := range roots {
		ids := members[r]
		sort.Slice(ids, func(a, b int) bool {
			if ra, rb := idRank(ids[a]), idRank(ids[b]); ra != rb {
				return ra < rb
			}
			return ids[a] < ids[b]
		})
		g := Group{Index: index, Primary: ids[0], Severity: def}
		labelled := false
		for _, id := range ids {
			if s, ok := sev[id]; ok && (!labelled || severityRank(s) > severityRank(g.Severity)) {
				g.Severity, labelled = s, true
			}
		}
		g.IDs = append([]string(nil), ids...)
		sort.Strings(g.IDs)
		out = append(out, g)
	}
	return out
}

// FindingInput is what Findings needs besides the groups.
type FindingInput struct {
	Packages []Package
	Groups   []Group
	// RootHash is the project root hash (secposture.ProjectRootHash).
	RootHash string
	Scope    secfinding.Scope
	Engine   secscan.EngineIdentity
	// Epochs are the database epochs per ecosystem.
	Epochs map[string]string
	// DriverID is the registry id ("scalibr" or "osv").
	DriverID string
}

// MaxFindings caps one run's findings (secscan.Budget.MaxFindings default).
const MaxFindings = 2000

// Findings maps grouped advisories onto findings through the "osv"
// semantic adapter row: its category and confidence; the advisory's own
// severity label when it carries one, else the row's default. The message
// and fix hint are templates; the package name and version ride only in
// the redacted evidence, which ships to an org only under
// shipsRawContent(). The second result reports truncation.
func Findings(in FindingInput) ([]secfinding.Finding, bool) {
	row, _ := secscan.Adapter("osv")
	var out []secfinding.Finding
	truncated := false
	for _, g := range in.Groups {
		if g.Index < 0 || g.Index >= len(in.Packages) {
			continue
		}
		if len(out) >= MaxFindings {
			truncated = true
			break
		}
		p := in.Packages[g.Index]
		rule := g.Primary
		id := secfinding.DependencyIdentity(p.Ecosystem, p.Name, p.Version, rule)
		evidence := secfinding.Clip(p.Ecosystem+" "+p.Name+"@"+p.Version, secfinding.MaxEvidence)
		f := secfinding.Finding{
			LocalKey:         secfinding.LocalKey(in.RootHash, rule, id),
			Location:         secfinding.Location{RelPath: strings.ReplaceAll(p.Path, `\`, "/")},
			Rule:             secfinding.Rule{ID: rule, Pack: "osv"},
			Category:         row.Category,
			Severity:         g.Severity,
			Confidence:       row.Confidence,
			Scope:            in.Scope,
			Project:          secfinding.Project{RootHash: in.RootHash},
			EvidenceRedacted: evidence,
			EvidenceHash:     secfinding.EvidenceHash(evidence),
			Message:          message(p.Ecosystem, g.IDs),
			FixHint:          "Upgrade the dependency to a version the advisory lists as fixed, then regenerate the lockfile.",
			Engine: secfinding.Engine{
				Driver: in.DriverID, DriverVersion: in.Engine.Version, EngineDigest: in.Engine.Digest,
				DatabaseEpoch: in.Epochs[p.Ecosystem],
			},
			Status: policy.FindingStatusOpen,
		}
		if f.Severity == "" {
			f.Severity = row.Default
		}
		out = append(out, f)
	}
	return out, truncated
}

// message is the finding's template text: the ecosystem and the advisory
// ids (charset-checked), never engine prose.
func message(eco string, ids []string) string {
	if _, known := canaries[eco]; !known {
		eco = "package"
	}
	shown := ids
	more := ""
	if len(shown) > 6 {
		more = fmt.Sprintf(" and %d more", len(shown)-6)
		shown = shown[:6]
	}
	return secfinding.Clip(fmt.Sprintf("Known vulnerability in a %s dependency (%s%s).", eco, strings.Join(shown, ", "), more), secfinding.MaxMessage)
}

// EcosystemOfFinding returns the ecosystem a dependency finding was built
// for (the first word of its redacted evidence, written by Findings), or
// "" for a finding Findings did not build.
func EcosystemOfFinding(f secfinding.Finding) string {
	eco, _, ok := strings.Cut(f.EvidenceRedacted, " ")
	if !ok || f.Category != policy.FindingVulnerableDependency {
		return ""
	}
	return eco
}

// StaleFindings returns the ids of the open findings a new run no longer
// reports: same driver, an ecosystem the run scanned (a not-scanned
// ecosystem proves nothing), and a local key the run did not produce. They
// become not_reproduced; nothing is deleted.
func StaleFindings(open []secfinding.Finding, driverID string, run []secfinding.Finding, scanned map[string]bool) []string {
	seen := map[string]bool{}
	for _, f := range run {
		seen[f.LocalKey] = true
	}
	var out []string
	for _, f := range open {
		if f.Status != policy.FindingStatusOpen || f.Engine.Driver != driverID || f.ID == "" {
			continue
		}
		if eco := EcosystemOfFinding(f); eco == "" || !scanned[eco] {
			continue
		}
		if !seen[f.LocalKey] {
			out = append(out, f.ID)
		}
	}
	sort.Strings(out)
	return out
}

// ScannedEcosystems returns the ecosystems a run scanned in full
// (Coverage.Scanned). Only those may close an older finding: an ecosystem
// the run did not name, a skipped one, one with a gap and every ecosystem
// of a run with a failed extractor prove nothing.
func ScannedEcosystems(cov secscan.Coverage) map[string]bool {
	out := map[string]bool{}
	for _, e := range cov.Scanned {
		out[e] = true
	}
	return out
}
