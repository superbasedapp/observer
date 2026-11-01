package guard

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// The org project layer (security plan section 7.11, spike JSP-10, lane
// sec-p): the project sections an organization published for a project,
// delivered as per-project envelopes signed by the org (internal/orgclient,
// projectaudience.go) and loaded here only for a project root whose identity
// matched that project in the org-signed mapping.
//
// It is an ORG-signed layer, as trusted as a team layer: it folds into the
// org layer escalate-only (strictest wins), never into the in-repo project
// layer, which is the least trusted. It can add rules and tighten
// decisions; it cannot relax an org decision, grant `overridable`, cap a rule
// at flag with `enforce = false`, or redefine a rule id the org layer already
// defines (each is dropped with a load issue).
//
// Inert unless the org layer in force is a v3 (project audience) bundle: a
// node with no project-scoped bundle reads no extra file here.

// layerOrgProject names an org project envelope's PolicyState.
const layerOrgProject = "org_project"

// orgProjectEnvelope returns the composed org bundle envelope of the snapshot
// and its key, when that bundle carries a project binding (ok=false
// otherwise, or when the envelope does not decode).
func (es *engineSet) orgProjectEnvelope() (orgcontract.PolicyBundle, ed25519.PublicKey, bool) {
	if es == nil || es.orgProject == nil {
		return orgcontract.PolicyBundle{}, nil, false
	}
	return *es.orgProject, es.orgProjectKey, true
}

// decodeOrgProjectEnvelope reads the org layer's verified envelope bytes
// once per snapshot (newEngineSet): its composed bundle and key when it
// carries a project binding.
func decodeOrgProjectEnvelope(org *policyFile) (orgcontract.PolicyBundle, ed25519.PublicKey, bool) {
	if org == nil || len(org.envelope) == 0 {
		return orgcontract.PolicyBundle{}, nil, false
	}
	var b orgcontract.PolicyBundle
	if err := json.Unmarshal(org.envelope, &b); err != nil || b.ProjectBinding == nil {
		return orgcontract.PolicyBundle{}, nil, false
	}
	pub, err := base64.RawURLEncoding.DecodeString(b.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return orgcontract.PolicyBundle{}, nil, false
	}
	return b, ed25519.PublicKey(pub), true
}

// orgProjectMatch is one root's org project layer as a build saw it.
type orgProjectMatch struct {
	// inForce: the org layer in force carries the project audience.
	inForce bool
	// layers and states are the loaded envelopes (one state each).
	layers []*policyFile
	states []PolicyState
	// unknown says why the project layer is unknown here ("" when known):
	// the decision itself was unknown (the mapping is missing, of another
	// delivery, past its offline lifetime, or truncated with no resolve
	// answer), or a matched project's envelope could not be loaded. It is
	// what the project_unknown floor reads (projectfloor.go).
	unknown string
	// key identifies the match (the decision and the bytes of every matched
	// envelope), so a long-lived guard notices a change (projectMatchStale).
	key string
}

// Reasons the org project layer is unknown, beside projectmatch's own.
const (
	// projectUnknownDecision: projectmatch.Decide answered unknown with no
	// reason of its own (the mapping is missing, of another delivery or past
	// its offline lifetime).
	projectUnknownDecision = "mapping_unavailable"
	// projectUnknownUnloadable: a matched project's envelope is missing, was
	// rejected or does not parse, so its sections are unknown here.
	projectUnknownUnloadable = "envelope_unavailable"
)

// orgProjectDecision resolves which org projects apply to projectRoot
// (projectmatch.Decide over the cached mapping and the daemon's match record,
// falling back to the root's own identity hashes from git files). ok is
// false when the org layer in force carries no project audience.
func (g *Guard) orgProjectDecision(es *engineSet, projectRoot string) (projectmatch.Decision, orgcontract.PolicyBundle, ed25519.PublicKey, bool) {
	composed, key, ok := es.orgProjectEnvelope()
	if !ok || projectRoot == "" {
		return projectmatch.Decision{}, composed, key, false
	}
	layout := projectmatch.LayoutFor(g.orgBundlePath)
	in := projectmatch.DecideInput{
		Composed: composed.ProjectBinding, ComposedVersion: composed.Version, Now: time.Now(),
		Signals: func() (projectmatch.Signals, error) { return projectmatch.SignalsFor(projectRoot, "") },
	}
	in.LoadMapping = func() *projectmatch.MappingFile {
		raw, err := g.readFile(layout.MappingPath())
		if err != nil {
			return nil
		}
		mf, derr := projectmatch.DecodeMappingFile(raw)
		if derr != nil {
			return nil
		}
		return &mf
	}
	for _, root := range matchRecordRoots(projectRoot) {
		if raw, err := g.readFile(layout.MatchPath(projectmatch.RootHash(root))); err == nil {
			if rec, derr := projectmatch.DecodeMatchFile(raw); derr == nil {
				in.Record = &rec
				break
			}
		}
	}
	return projectmatch.Decide(in), composed, key, true
}

// matchRecordRoots are the roots a directory's match record is looked up
// under, in order: the identity root the matcher keys every record by (the
// main repository for a linked worktree, the repository root for a
// subdirectory; plans decision log P-041, lane sec-p2a audit finding 3), then
// the directory as given when it differs (a record written under it before
// the identity key, or a directory whose identity cannot be read).
// git.FindRoot is the identity root projectmatch.SignalsFor keys by (the same
// locate step, file reads only, no remote read).
func matchRecordRoots(projectRoot string) []string {
	// A root that is not rooted on this host is looked up as given, never
	// resolved against the working directory (audit row 8).
	if !git.HostRooted(projectRoot) {
		return []string{projectRoot}
	}
	root, ok := git.FindRoot(projectRoot)
	if !ok || root == "" || root == projectRoot {
		return []string{projectRoot}
	}
	return []string{root, projectRoot}
}

// readOrgProjectEnvelope reads a matched project's envelope: the delivered
// one, else the one the resolve call returned (an above-cap member's project
// is not in the delivery). Both are checked by the caller exactly alike.
func (g *Guard) readOrgProjectEnvelope(id string) (string, []byte, error) {
	layout := projectmatch.LayoutFor(g.orgBundlePath)
	path := layout.EnvelopePath(id)
	raw, err := g.readFile(path)
	if os.IsNotExist(err) {
		if rraw, rerr := g.readFile(layout.ResolvedEnvelopePath(id)); rerr == nil {
			return layout.ResolvedEnvelopePath(id), rraw, nil
		}
	}
	return path, raw, err
}

// orgProjectMatchKey is the match key of projectRoot now (no issue is
// recorded): the decision and the hash of every matched envelope's bytes.
func (g *Guard) orgProjectMatchKey(es *engineSet, projectRoot string) string {
	dec, _, _, ok := g.orgProjectDecision(es, projectRoot)
	if !ok {
		return ""
	}
	return g.matchKeyFor(dec)
}

func (g *Guard) matchKeyFor(dec projectmatch.Decision) string {
	var b strings.Builder
	b.WriteString(dec.State)
	b.WriteString("|")
	b.WriteString(dec.Reason)
	for _, id := range dec.IDs {
		b.WriteString("|")
		b.WriteString(id)
		b.WriteString("=")
		if _, raw, err := g.readOrgProjectEnvelope(id); err == nil {
			b.WriteString(sha256hex(raw))
		} else {
			b.WriteString("missing")
		}
	}
	return b.String()
}

// orgProjectLayers resolves which org project envelopes apply to projectRoot
// (orgProjectDecision) and loads each one, re-verified against the composed
// bundle in force. It returns the parsed layers and one PolicyState per
// loaded envelope; a project layer that is unknown (mapping missing, of
// another delivery, past its offline lifetime, or truncated with no resolve
// answer), or a matched envelope that cannot be loaded, records an issue and
// sets unknown, which the project_unknown floor reads.
func (g *Guard) orgProjectLayers(es *engineSet, projectRoot string) orgProjectMatch {
	dec, composed, key, ok := g.orgProjectDecision(es, projectRoot)
	if !ok {
		return orgProjectMatch{}
	}
	out := orgProjectMatch{inForce: true, key: g.matchKeyFor(dec)}
	switch dec.State {
	case projectmatch.StateUnknown:
		out.unknown = dec.Reason
		if out.unknown == "" {
			out.unknown = projectUnknownDecision
		}
		g.recordIssues([]string{fmt.Sprintf(
			"org project layer for %s is unknown (%s: the project mapping is missing, of another delivery, past its offline lifetime, or above its cap with no resolve answer): the org, team and member layers apply, plus the org's project_unknown decision", projectRoot, out.unknown)})
		return out
	case projectmatch.StateMatched:
	default:
		return out
	}
	for _, id := range dec.IDs {
		path, raw, err := g.readOrgProjectEnvelope(id)
		if err != nil {
			// The mapping lists only projects whose sections reach this
			// member, so a matched project with no envelope file is
			// UNLOADABLE, never "nothing to load" (audit finding 4): its
			// sections are unknown here, the issue says so, and the org's
			// project_unknown decision applies (lane sec-p2a). The other
			// matched projects still load, the org, team and member layers
			// apply, and the org client fetches in full while a mapped
			// envelope file is missing (projectFilesPresent).
			out.unknown = projectUnknownUnloadable
			if os.IsNotExist(err) {
				g.recordIssues([]string{fmt.Sprintf("org project envelope for %s is missing (%s): the project is in the signed mapping, so its sections are unknown here; the org, team and member layers apply until the next policy poll fetches it", id, path)})
			} else {
				g.recordIssues([]string{fmt.Sprintf("org project envelope %s: %v", path, err)})
			}
			continue
		}
		var env orgcontract.PolicyBundle
		if err := json.Unmarshal(raw, &env); err != nil {
			out.unknown = projectUnknownUnloadable
			g.recordIssues([]string{fmt.Sprintf("org project envelope %s: not an envelope: %v", path, err)})
			continue
		}
		if err := projectmatch.CheckEnvelope(env, composed, id, key); err != nil {
			out.unknown = projectUnknownUnloadable
			g.recordIssues([]string{fmt.Sprintf("org project envelope %s rejected: %v", path, err)})
			continue
		}
		pf, perr := parsePolicyFile([]byte(env.BundleTOML), layerOrg)
		if perr != nil {
			out.unknown = projectUnknownUnloadable
			g.recordIssues([]string{fmt.Sprintf("org project envelope %s: %v", path, perr)})
			continue
		}
		out.layers = append(out.layers, pf)
		out.states = append(out.states, PolicyState{
			Layer: layerOrgProject, Path: path, Version: strconv.FormatInt(env.Version, 10),
			ContentHash: sha256hex([]byte(env.BundleTOML)), Notes: orgParseNotes(pf.notes),
		})
	}
	return out
}

// OrgProjectUnknown returns the org's `[project_audience] unknown` decision
// ("none" or "ask") and ok=true while the org layer in force carries the
// project audience (a v3 bundle); ok=false otherwise. `observer guard status`
// prints it.
func (g *Guard) OrgProjectUnknown() (string, bool) {
	es := g.set.Load()
	if !es.orgProjectsInForce() || !es.orgLayerReported() {
		return "", false
	}
	return es.orgProjectUnknownDecision(), true
}

// OrgProjectCacheIssues checks the project half of the cached org bundle
// with no project root (audit finding 4): while the org layer in force carries
// the project audience, the signed mapping must be readable and every project
// it lists must have its envelope file. `observer guard status` prints these
// as load issues; the hook learns of a missing file only when a matched root
// needs it. Empty when the org layer carries no project audience.
func (g *Guard) OrgProjectCacheIssues() []string {
	es := g.set.Load()
	if _, _, ok := es.orgProjectEnvelope(); !ok || !es.orgLayerReported() {
		return nil
	}
	layout := projectmatch.LayoutFor(g.orgBundlePath)
	raw, err := g.readFile(layout.MappingPath())
	if err != nil {
		return []string{fmt.Sprintf("org project mapping %s is not readable (%v): the project layer is unknown on every project root", layout.MappingPath(), err)}
	}
	mf, err := projectmatch.DecodeMappingFile(raw)
	if err != nil {
		return []string{fmt.Sprintf("org project mapping %s does not decode (%v): the project layer is unknown on every project root", layout.MappingPath(), err)}
	}
	var out []string
	for _, e := range mf.Mapping.Projects {
		path := layout.EnvelopePath(e.OrgProjectID)
		if _, err := g.readFile(path); err != nil {
			out = append(out, fmt.Sprintf("org project envelope for %s is missing (%s): its sections are unknown on a project root that matches it", e.OrgProjectID, path))
		}
	}
	return out
}

// withOrgProjectLayers folds project envelopes into a copy of the org layer,
// escalate-only. The org layer's own rows come first; a project rule whose id
// the org layer (or an earlier project) already defines is dropped, and a
// project override loses `overridable` and `enforce = false` (both would
// relax). Every drop is a load issue. The org layer is never modified.
func withOrgProjectLayers(org *policyFile, projects []*policyFile) (*policyFile, []string) {
	if len(projects) == 0 {
		return org, nil
	}
	out := &policyFile{layer: layerOrg}
	if org != nil {
		out.rules = append(out.rules, org.rules...)
		out.overrides = append(out.overrides, org.overrides...)
		out.notes = append(out.notes, org.notes...)
		out.fallbacks = org.fallbacks
		out.fallbackProblems = org.fallbackProblems
		out.projectUnknown = org.projectUnknown
		out.projectAudienceProblems = org.projectAudienceProblems
		out.envelope = org.envelope
	}
	defined := map[string]bool{}
	for i := range out.rules {
		defined[out.rules[i].ID] = true
	}
	var issues []string
	for _, p := range projects {
		if p.projectUnknown != "" {
			// The decision is org-wide: a project section cannot set or
			// lower it (lane sec-p2a).
			issues = append(issues, "org project section [project_audience] ignored (the project_unknown decision is set by the org-wide bundle)")
		}
		for i := range p.rules {
			r := p.rules[i]
			if defined[r.ID] {
				issues = append(issues, fmt.Sprintf("org project section rule %s dropped: the id is already defined by the organization's policy (give the project rule its own id)", r.ID))
				continue
			}
			defined[r.ID] = true
			out.rules = append(out.rules, r)
		}
		for _, ov := range p.overrides {
			if ov.Overridable {
				issues = append(issues, fmt.Sprintf("org project section override on %s: `overridable` ignored (a project section can only add or tighten)", ov.RuleID))
				ov.Overridable = false
			}
			if ov.EnforceOff {
				issues = append(issues, fmt.Sprintf("org project section override on %s: `enforce = false` ignored (a project section can only add or tighten)", ov.RuleID))
				ov.EnforceOff = false
			}
			ov.Layer = layerOrg
			out.overrides = append(out.overrides, ov)
		}
	}
	return out, issues
}
