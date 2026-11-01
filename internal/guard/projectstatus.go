package guard

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// Per-section project policy status (security plan section 7.11, lane
// sec-p2b): READ ACCESSORS ONLY. Nothing here writes a file or changes what
// the hook loads; it reads the same three things the project layer reads
// (orgproject.go): the signed mapping the org client cached, the per-project
// envelopes, and the daemon's match records, and states per mapped project
// one closed status the policy-state reporter sends to the org
// (orgcontract.ProjectSectionState). No path or directory leaves this file:
// the answer carries org project ids and statuses only.

// projectSectionRule is one row of the per-section status table, walked top
// down: the first row whose check holds names the status.
type projectSectionRule struct {
	status string
	holds  func(f projectSectionFacts) bool
}

// projectSectionFacts is what the node knows about one mapped project.
type projectSectionFacts struct {
	mappingCurrent bool
	envelope       envelopeState
	matched        bool
	// unknownRoot: a current match record says the matcher could not decide
	// a root on this node (projectmatch.MatchFile.Unknown). That root might
	// be this project, so an unmatched section there is unknown, never an
	// ACK (SEC-P2B audit finding 1).
	unknownRoot bool
}

// envelopeState is what the node found for one project's envelope file.
type envelopeState int

const (
	envelopeVerified envelopeState = iota
	envelopeMissing
	envelopeInvalid
)

// projectSectionTable decides one section's status.
var projectSectionTable = []projectSectionRule{
	// A mapping that is not this delivery's, or past its offline lifetime,
	// leaves every section unknown (the layer is unknown on every root).
	{orgcontract.ProjectSectionUnknown, func(f projectSectionFacts) bool { return !f.mappingCurrent }},
	// The project is mapped but its envelope never arrived.
	{orgcontract.ProjectSectionNotDelivered, func(f projectSectionFacts) bool { return f.envelope == envelopeMissing }},
	// An envelope that does not verify is never loaded.
	{orgcontract.ProjectSectionUnknown, func(f projectSectionFacts) bool { return f.envelope == envelopeInvalid }},
	{orgcontract.ProjectSectionApplied, func(f projectSectionFacts) bool { return f.matched }},
	// A root the guard floors as unknown may belong to this project: the
	// node cannot say the section is not matched.
	{orgcontract.ProjectSectionUnknown, func(f projectSectionFacts) bool { return f.unknownRoot }},
	{orgcontract.ProjectSectionNotMatched, func(projectSectionFacts) bool { return true }},
}

// projectSectionStatusOf walks projectSectionTable.
func projectSectionStatusOf(f projectSectionFacts) string {
	for _, r := range projectSectionTable {
		if r.holds(f) {
			return r.status
		}
	}
	return orgcontract.ProjectSectionUnknown
}

// ProjectSectionReport is the per-section status the node reports on the
// gen5 guard row: the sections, sorted by project id, and whether the list
// was cut to what the server accepts (more projects than
// orgcontract.MaxProjectMappingProjects, or an entry the server's check
// would refuse), so the org reads a cut list as partial rather than whole.
type ProjectSectionReport struct {
	Sections  []orgcontract.ProjectSectionState
	Truncated bool
}

// OrgProjectSectionStatus is OrgProjectSectionReport's section list.
func (g *Guard) OrgProjectSectionStatus(now time.Time, listDir func(dir string) ([]string, error)) []orgcontract.ProjectSectionState {
	return g.OrgProjectSectionReport(now, listDir).Sections
}

// OrgProjectSectionReport reports, per project in the cached signed mapping
// plus every project a current resolve record names (an above-cap member's
// project is not in the mapping, lane sec-p2a), the status of its section on
// this node at now, sorted by project id and capped at
// orgcontract.MaxProjectMappingProjects. The list always passes
// orgcontract.ValidProjectSectionStatus, so the server never refuses it and
// the reporter never falls to the gen4 rung over a bad list (SEC-P2B audit
// finding 2); what had to be dropped sets Truncated. Empty when the org
// layer in force carries no project audience (no v3 delivery) or the mapping
// is not readable at all (nothing to enumerate; `observer guard status`
// reports that as a load issue). listDir lists the file names in the
// match-record directory (nil: the real directory); the files are read
// through the guard's own reader.
func (g *Guard) OrgProjectSectionReport(now time.Time, listDir func(dir string) ([]string, error)) ProjectSectionReport {
	sections, ok := g.orgProjectSections(now, listDir)
	if !ok {
		return ProjectSectionReport{}
	}
	var rep ProjectSectionReport
	rep.Sections = make([]orgcontract.ProjectSectionState, 0, len(sections))
	for _, sec := range sections {
		e := orgcontract.ProjectSectionState{OrgProjectID: sec.id, Status: sec.status}
		if !orgcontract.ValidProjectSectionStatus([]orgcontract.ProjectSectionState{e}) {
			rep.Truncated = true // an id the server would refuse (never one the org minted)
			continue
		}
		if len(rep.Sections) == orgcontract.MaxProjectMappingProjects {
			rep.Truncated = true
			break
		}
		rep.Sections = append(rep.Sections, e)
	}
	if len(rep.Sections) == 0 {
		rep.Sections = nil // nothing to report: the wire omits it either way
	}
	if !orgcontract.ValidProjectSectionStatus(rep.Sections) {
		// Unreachable (each entry checked, ids unique, capped); never send a
		// list the server refuses.
		return ProjectSectionReport{Truncated: true}
	}
	return rep
}

// orgProjectSection is one enumerated project of the report: its id, its
// section status and, when its envelope verified, the envelope.
type orgProjectSection struct {
	id     string
	status string
	env    *orgcontract.PolicyBundle
}

// orgProjectSections enumerates, per project in the cached signed mapping
// plus every project a current resolve record names, its section status and
// verified envelope, sorted by project id (uncapped; each report caps). ok is
// false when the org layer in force carries no project audience or the
// mapping is not readable at all.
func (g *Guard) orgProjectSections(now time.Time, listDir func(dir string) ([]string, error)) ([]orgProjectSection, bool) {
	es := g.set.Load()
	composed, key, ok := es.orgProjectEnvelope()
	if !ok || composed.ProjectBinding == nil || !es.orgLayerReported() {
		// No v3 delivery, or a lazy base that dropped the org layer: the
		// project sections fold into that layer, so none is in force (P-058).
		return nil, false
	}
	layout := projectmatch.LayoutFor(g.orgBundlePath)
	raw, err := g.readFile(layout.MappingPath())
	if err != nil {
		return nil, false
	}
	mf, err := projectmatch.DecodeMappingFile(raw)
	if err != nil {
		return nil, false
	}
	bind := composed.ProjectBinding
	current := mf.BundleVersion == composed.Version && mf.Mapping.Epoch == bind.Epoch &&
		orgcontract.ProjectMappingDigest(mf.Mapping) == bind.MappingDigest && !mf.Expired(now)
	var recs matchRecords
	if current {
		if listDir == nil {
			listDir = dirNames
		}
		recs = currentMatches(layout.MatchDir(), bind, composed.Version, now, listDir, g.readFile)
	}
	// The mapping's projects plus the resolved ones, once each, sorted.
	seen := map[string]bool{}
	var ids []string
	add := func(id string) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, e := range mf.Mapping.Projects {
		add(e.OrgProjectID)
	}
	for _, id := range recs.resolved {
		add(id)
	}
	sort.Strings(ids)
	out := make([]orgProjectSection, 0, len(ids))
	for _, id := range ids {
		f := projectSectionFacts{mappingCurrent: current, matched: recs.matched[id], unknownRoot: recs.unknown}
		env, state := g.envelopeOf(id, composed, key)
		f.envelope = state
		out = append(out, orgProjectSection{id: id, status: projectSectionStatusOf(f), env: env})
	}
	return out, true
}

// ProjectFamilySection is one family section the node holds in a mapped
// project's verified envelope, with the project's section status (the same
// table as the guard section of that envelope).
type ProjectFamilySection struct {
	OrgProjectID string
	Status       string
	Member       orgcontract.ProjectFamilyMember
}

// OrgProjectFamilySections lists, for the per-section report (lane sec-p3),
// every family member of every mapped project whose envelope verifies, with
// that project's section status, sorted by project, family and sequence. A
// project whose envelope is missing or invalid lists nothing: the org reads
// its family sections as not delivered. Empty when no project audience is in
// force. Read accessor only, like OrgProjectSectionReport.
func (g *Guard) OrgProjectFamilySections(now time.Time, listDir func(dir string) ([]string, error)) []ProjectFamilySection {
	sections, ok := g.orgProjectSections(now, listDir)
	if !ok {
		return nil
	}
	var out []ProjectFamilySection
	for _, sec := range sections {
		if sec.env == nil {
			continue
		}
		for _, m := range sec.env.Families {
			out = append(out, ProjectFamilySection{OrgProjectID: sec.id, Status: sec.status, Member: m})
		}
	}
	return out
}

// envelopeOf reads one project's envelope through the project layer's one
// reader (readOrgProjectEnvelope: the delivered file, else the resolved one)
// and checks it against the composed bundle in force, exactly as the project
// layer does before loading; it returns the envelope when it verifies.
func (g *Guard) envelopeOf(id string, composed orgcontract.PolicyBundle, key ed25519.PublicKey) (*orgcontract.PolicyBundle, envelopeState) {
	_, raw, err := g.readOrgProjectEnvelope(id)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, envelopeMissing
		}
		return nil, envelopeInvalid
	}
	var env orgcontract.PolicyBundle
	if json.Unmarshal(raw, &env) != nil {
		return nil, envelopeInvalid
	}
	if projectmatch.CheckEnvelope(env, composed, id, key) != nil {
		return nil, envelopeInvalid
	}
	return &env, envelopeVerified
}

// matchRecords is what the daemon's current match records say.
type matchRecords struct {
	// matched: the org project ids some directory on this node matched.
	matched map[string]bool
	// resolved: the ids named by resolve-sourced records (possibly outside
	// the mapping), in directory order.
	resolved []string
	// unknown: a current record the matcher could not decide.
	unknown bool
}

// currentMatches reads the daemon's CURRENT match records: those of the
// delivery in force (projectmatch.MatchFile.CurrentFor: this epoch and
// mapping digest, and for a resolve record this composed bundle version),
// inside their lifetime. A record the guard cannot read or decode is
// skipped.
func currentMatches(dir string, bind *orgcontract.ProjectBinding, version int64, now time.Time, listDir func(string) ([]string, error), readFile func(string) ([]byte, error)) matchRecords {
	out := matchRecords{matched: map[string]bool{}}
	names, err := listDir(dir)
	if err != nil {
		return out
	}
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, rerr := readFile(filepath.Join(dir, name))
		if rerr != nil {
			continue
		}
		rec, derr := projectmatch.DecodeMatchFile(raw)
		if derr != nil || !rec.CurrentFor(bind, version) {
			continue
		}
		if !rec.ValidUntil.IsZero() && !now.Before(rec.ValidUntil) {
			continue
		}
		if rec.Unknown {
			out.unknown = true
			continue
		}
		for _, id := range rec.OrgProjectIDs {
			out.matched[id] = true
			if rec.Source == projectmatch.SourceResolve {
				out.resolved = append(out.resolved, id)
			}
		}
	}
	return out
}

// dirNames lists the regular file names in dir.
func dirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
