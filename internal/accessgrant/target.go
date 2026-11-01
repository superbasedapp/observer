package accessgrant

import (
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// target.go - the non-guard grant kinds (request-grants G8): tool access,
// model access and feature access each name ONE target (a tool id, a model
// id, a pinnable setting key) and lift exactly that one block. Matching is
// one pure function shared by every consumer (the launcher gates, the org
// gateway's model check, the governance sidecar writer), so they cannot
// disagree about what a grant covers.

// TargetQuery is one "may this target pass" question.
type TargetQuery struct {
	// Type is TypeToolAllow, TypeModelAccess or TypeFeatureEnable.
	Type string
	// Target is the exact tool / model / setting id being blocked.
	Target string
	// ProjectRootHash is the caller's project, "" when unknown (then only a
	// grant for every project matches).
	ProjectRootHash string
}

// targetTypes are the request types whose grants name a Target.
var targetTypes = map[string]bool{TypeToolAllow: true, TypeModelAccess: true, TypeFeatureEnable: true, TypePageAccess: true, TypeConfigEdit: true, TypeComponentEnable: true, TypeFindingException: true}

// IsTargetType reports whether a grant of this type names a Target.
func IsTargetType(t string) bool { return targetTypes[t] }

// MatchTarget returns the honoured grant that lifts q's block, if any. The
// target compares EXACTLY (no case folding, no prefix): a grant for one id
// never reaches another. A grant pinned to a project matches only that
// project. Among several: the project-pinned grant, then the earliest
// expiry (a perpetual grant last), then the lowest id.
func MatchTarget(q TargetQuery, grants []Cached, rc Receipt, now time.Time) (Hit, bool) {
	if !targetTypes[q.Type] || q.Target == "" {
		return Hit{}, false
	}
	var hits []Hit
	for _, c := range grants {
		g := c.Grant
		if g.Type != q.Type || g.Target != q.Target {
			continue
		}
		narrow := 0
		if g.ProjectRootHash != "" {
			if g.ProjectRootHash != q.ProjectRootHash {
				continue
			}
			narrow = 1
		}
		if ok, _ := Honoured(g, c.UsesUsed, rc, now); !ok {
			continue
		}
		left := int64(-1)
		if g.MaxUses > 0 {
			left = g.MaxUses - c.UsesUsed
		}
		hits = append(hits, Hit{GrantID: g.ID, ExpiresAtNs: g.ExpiresAtNs, UsesLeft: left, Narrowness: narrow})
	}
	if len(hits) == 0 {
		return Hit{}, false
	}
	sort.Slice(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if a.Narrowness != b.Narrowness {
			return a.Narrowness > b.Narrowness
		}
		ae, be := expirySortKey(a.ExpiresAtNs), expirySortKey(b.ExpiresAtNs)
		if ae != be {
			return ae < be
		}
		return a.GrantID < b.GrantID
	})
	return hits[0], true
}

// HonouredUntilNs is the node wall-clock instant g stops being honoured if
// nothing changes (no new sync, no revocation): the earliest of its absolute
// expiry, its remaining TTL measured at receipt (GRANT-3) and the offline
// window after the last verified sync (D-087). A reader that holds no grant
// cache (the governance sidecar's readers) ends an exception at this instant
// on its own; the writer recomputes it on every pass.
func HonouredUntilNs(g orgcontract.AccessGrantWire, rc Receipt) int64 {
	window := time.Duration(rc.MaxOfflineS) * time.Second
	if window <= 0 {
		window = OnlineOnlyWindow
	}
	until := rc.LastVerifiedNs + int64(window)
	if g.ExpiresAtNs > 0 {
		if g.ExpiresAtNs < until {
			until = g.ExpiresAtNs
		}
		if ttl := rc.ReceivedAtNs + (g.ExpiresAtNs - rc.ServerNowNs); ttl < until {
			until = ttl
		}
	}
	return until
}

// TargetFacts are what the org knows about a non-guard grant's target.
type TargetFacts struct {
	// KnownTool: the target is a tool id in the integration registry.
	KnownTool bool
	// PinnableSetting: the target is a setting key the org can pin on a
	// node (policyfam/nodegov.PinnableKeys).
	PinnableSetting bool
	// NodeFeature: the target is a node.features feature id the org can
	// disable (policyfam/nodefeatures.Features: terminals, remote, ...).
	NodeFeature bool
	// NodePage: the target is a node dashboard page or page tab id
	// (policyfam/nodegov.NavSectionIDs / NavTabIDs) the org can hide.
	NodePage bool
	// ConfigSetting: the target is an AI tool catalogue setting id Observer
	// writes, or "<tool>/*" for a catalogue tool (agentconfigorg's grant
	// vocabulary).
	ConfigSetting bool
	// NodeComponent: the target is a non-core node component id of the
	// server's catalog (internal/components), the one a node.components
	// policy governs.
	NodeComponent bool
	// FindingRef: the target is the wire handle of a code security finding
	// the org holds for the grantee (org_sec_findings.finding_ref), lane
	// SEC-E3.
	FindingRef bool
}

// targetRule is one row of the per-type target check (decideTarget).
type targetRule struct {
	field, message string
	refuse         func(p Proposal, f TargetFacts) bool
}

// targetRules is the per-type table (CLAUDE.md #5). Tool access covers the
// tools Observer launches; an MCP server is approved in Agent Access (design
// §1.1: never a second path), or, with Agent Access off, through a guardrail
// exemption on the MCP rule that blocked it. Feature access names a setting
// the org pins and is time-bound only: a use count has no meaning for a
// setting that stays unpinned while the grant lasts.
var targetRules = map[string][]targetRule{
	TypeToolAllow: {{
		field: "target",
		message: "tool access covers the tools Observer launches (a registry id such as codex); an MCP server is approved in " +
			"Agent Access under MCP approvals, or, with Agent Access off, through a guardrail exemption on the rule that blocked it",
		refuse: func(_ Proposal, f TargetFacts) bool { return !f.KnownTool },
	}},
	TypeFeatureEnable: {
		{
			field:   "target",
			message: "feature access names a node feature your organization can turn off (terminals, remote, routing_apply, patterns_write) or a setting it pins on its nodes (node governance)",
			refuse:  func(_ Proposal, f TargetFacts) bool { return !f.PinnableSetting && !f.NodeFeature },
		},
		{
			field:   "max_uses",
			message: "feature access is time-bound only; leave uses at 0 and choose how long it lasts",
			refuse:  func(p Proposal, _ TargetFacts) bool { return p.MaxUses != 0 },
		},
	},
	// MP-GOV: a component grant activates one governable node component.
	TypeComponentEnable: {
		{
			field:   "target",
			message: "component access names one node component id your organization governs (observer components list shows them, for example codeintel or adapter.zed); core components always run",
			refuse:  func(_ Proposal, f TargetFacts) bool { return !f.NodeComponent },
		},
		{
			field:   "max_uses",
			message: "component access is time-bound only; leave uses at 0 and choose how long it lasts",
			refuse:  func(p Proposal, _ TargetFacts) bool { return p.MaxUses != 0 },
		},
	},
	// T-436: an edit grant opens one AI tool setting (or one tool's settings).
	TypeConfigEdit: {
		{
			field:   "target",
			message: "an AI tool setting edit names a catalogue setting id Observer writes (for example claude-code/permissions.defaultMode) or <tool>/* for every setting of one tool",
			refuse:  func(_ Proposal, f TargetFacts) bool { return !f.ConfigSetting },
		},
		{
			field:   "max_uses",
			message: "an AI tool setting edit is time-bound only; leave uses at 0 and choose how long it lasts",
			refuse:  func(p Proposal, _ TargetFacts) bool { return p.MaxUses != 0 },
		},
	},
	// Lane SEC-E3: a finding exception names one finding the org holds.
	TypeFindingException: {
		{
			field:   "target",
			message: "a finding exception names one code finding your organization holds for this member (its finding reference); it is never rule-wide",
			refuse:  func(_ Proposal, f TargetFacts) bool { return !f.FindingRef },
		},
		{
			field:   "max_uses",
			message: "a finding exception is time-bound only; leave uses at 0 and choose how long it lasts",
			refuse:  func(p Proposal, _ TargetFacts) bool { return p.MaxUses != 0 },
		},
	},
	// T-435: a page grant shows one hidden page or tab, read-only.
	TypePageAccess: {
		{
			field:   "target",
			message: "page access names a node dashboard page (for example cost) or a page tab (for example security/rules) your organization can hide",
			refuse:  func(_ Proposal, f TargetFacts) bool { return !f.NodePage },
		},
		{
			field:   "max_uses",
			message: "page access is time-bound only; leave uses at 0 and choose how long it lasts",
			refuse:  func(p Proposal, _ TargetFacts) bool { return p.MaxUses != 0 },
		},
	},
}

// decideTarget applies the per-type target table.
func decideTarget(d *Decision, t RequestType, p Proposal, f Facts, _ Settings) {
	for _, r := range targetRules[t.ID] {
		if r.refuse(p, f.Target) {
			d.Problems = append(d.Problems, Problem{Field: r.field, Code: CodeBadValue, Message: r.message})
		}
	}
}

// HonouredTargets lists the targets of the honoured grants of type typ, in
// order, once each (T-435: the pages a page-access grant shows). Nothing is
// counted: a time-bound grant has no uses.
func HonouredTargets(typ string, grants []Cached, rc Receipt, now time.Time) []string {
	if !targetTypes[typ] {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range grants {
		g := c.Grant
		if g.Type != typ || g.Target == "" || seen[g.Target] {
			continue
		}
		if ok, _ := Honoured(g, c.UsesUsed, rc, now); !ok {
			continue
		}
		seen[g.Target] = true
		out = append(out, g.Target)
	}
	sort.Strings(out)
	return out
}
