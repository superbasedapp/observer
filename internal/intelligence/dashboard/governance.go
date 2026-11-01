package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentconfigorg"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// Admin-controlled Plane B, the node-dashboard enforcement point
// (docs/plans/admin-controlled-plane-b-spec-2026-08-15.md §3.5, Phase 1a).
//
// TWO layers, always, and the API one is the load-bearing one:
//
//  1. API REFUSAL (this file). A request for a route belonging to a hidden
//     section is 404; a MUTATING request for a route in a read-only section
//     is 409. A frontend-only hide is theatre — the threat model assumes the
//     developer can open devtools.
//  2. UI HIDING (the SPA, via GET /api/governance).
//
// The middleware is installed on BOTH branches of guardedHandler — the
// loopback listener and the remotely-exposed one. The adversarial review
// found the natural-looking home for it (beside capMap, inside remoteAuthz)
// is REMOTE-ONLY: Server.Handler() discards capMap and remoteAuthz's own
// comment records that "the direct owner-trusted loopback listener never
// runs remoteAuthz". Installing it there would have put governance
// everywhere EXCEPT the normal developer node dashboard.

// The closed section vocabulary. Kept as a flat list rather than derived
// from nodegov's slice so the constants are usable at the registration site;
// TestDashboardSectionsMatchNodegovVocabulary pins the two together. The
// UNHIDEABLE floor, by contrast, is read straight from nodegov below —
// there must be exactly one definition of "cannot be hidden".
const (
	SectionOverview Section = "overview"
	SectionLive     Section = "live"
	SectionSessions Section = "sessions"
	SectionActions  Section = "actions"
	SectionProjects Section = "projects"
	SectionSecurity Section = "security"
	// SectionCodeSecurity is the security pillar's Code security page,
	// beside Guard's page (security pillar plan section 4.10).
	SectionCodeSecurity Section = "code-security"

	SectionSearch      Section = "search"
	SectionCost        Section = "cost"
	SectionPlans       Section = "plans" // the Plans & limits page
	SectionAnalysis    Section = "analysis"
	SectionTools       Section = "tools"
	SectionCompression Section = "compression"
	SectionCache       Section = "cache"
	SectionSuggestions Section = "suggestions"
	SectionRouting     Section = "routing"
	SectionBenchmarks  Section = "benchmarks"
	SectionDiscovery   Section = "discovery"
	SectionPatterns    Section = "patterns"

	// SectionAgentConfig is the AI tool settings page (adapter config
	// editor, backlog items 2 and 7).
	SectionAgentConfig Section = "agent-config"
	SectionPrivacy     Section = "privacy"
	SectionTerminals   Section = "terminals"
	SectionRemote      Section = "remote"
	SectionSettings    Section = "settings"
	SectionRequests    Section = "requests"
	// SectionMessages is the admin and developer Messages page (T-854). It
	// sits on the unhideable floor (D-695), so its routes are never refused.
	SectionMessages Section = "messages"
)

// AllSections is the closed set, for the coverage test and for callers that
// need to validate a section id.
var AllSections = []Section{
	SectionOverview, SectionLive, SectionSessions, SectionActions, SectionProjects, SectionSecurity,
	SectionCodeSecurity, SectionEgress, SectionSearch, SectionCost, SectionPlans, SectionAnalysis, SectionTools,
	SectionCompression, SectionCache, SectionSuggestions, SectionRouting,
	SectionBenchmarks, SectionDiscovery, SectionPatterns, SectionPolicies, SectionAgentConfig,
	SectionPrivacy, SectionTerminals, SectionRemote, SectionMessages, SectionRequests, SectionSettings,
}

// configSectionPrefix is the one route whose SUB-resource is itself a
// governed unit: /api/config/section/<settings-section-id> is how the SPA
// writes one Settings sub-section. Honouring settings_read_only /
// settings_hidden at the API therefore needs this single explicit rule —
// without it those two directive classes would be pure UI theatre.
const configSectionPrefix = "/api/config/section/"

// governanceGuard wraps next with the §3.5 API-refusal layer. mux is used
// only to resolve the matched route pattern (reusing ServeMux's own
// matching, exactly as remoteAuthz does); sections maps that pattern to its
// nav section.
func (s *Server) governanceGuard(mux *http.ServeMux, sections map[string]Section, next http.Handler) http.Handler {
	if s.opts.Governance == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eff := s.opts.Governance(r.Context())
		// Short-circuit BEFORE any route resolution when nothing can change a
		// page's visibility on this node (no applied body, not a managed
		// machine), so an ungoverned node's request path never changes shape.
		if !eff.VisibilityActive() {
			next.ServeHTTP(w, r)
			return
		}
		_, pattern := mux.Handler(r)
		if ref := s.governanceRouteRefusal(r, sections[pattern], eff); ref.status != 0 {
			writeGovernanceRefusal(w, ref.status, ref.code, ref.section, eff, ref.message)
			return
		}
		// The generic batched write (PUT /api/config/keys) has no <id> in its
		// path and would sail straight past the rule above — the plan's §4.5
		// bypass. Its BODY names the keys; every key's section is resolved
		// from the schema and the whole batch is refused if any is hidden or
		// read-only, failing closed on a key the schema cannot map.
		if r.URL.Path == configKeysPath && isUnsafeMethod(strings.ToUpper(r.Method)) {
			refused := governanceConfigKeys(w, r, eff, func(w http.ResponseWriter, status int, code, section, msg string) {
				writeGovernanceRefusal(w, status, code, section, eff, msg)
			})
			if refused {
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// routeRefusal is governanceRouteRefusal's answer: status 0 means the
// request passes.
type routeRefusal struct {
	status                 int
	code, section, message string
}

// governanceRouteRefusal is the ONE set of route rules governanceGuard
// applies before the body-reading config-keys rule: the hidden rules
// (concealment), the read-only page, tab and Settings subsection rules and
// the config-backup restore rule. A handler that must say whether a write it
// offers would be refused (the trust chip's accept_allowed) asks this with
// the write's request, so the answer cannot drift from the guard.
func (s *Server) governanceRouteRefusal(r *http.Request, registered Section, eff govern.Effective) routeRefusal {
	unsafe := isUnsafeMethod(strings.ToUpper(r.Method))
	// Every HIDDEN (404) rule is one function, concealment, which the
	// SPA's concealed-route list is computed from too (T-401), so the UI
	// cannot fetch a route this guard would refuse as hidden.
	if c := concealment(registered, r.URL.Path, !unsafe, eff); c.hidden {
		return routeRefusal{status: http.StatusNotFound, code: "governance_hidden", section: c.section, message: c.message}
	}
	sec, sub := registered.Split()
	if sec != SectionNone && !nodegov.IsUnhideableNavSection(string(sec)) &&
		s.navSectionReadOnly(r.Context(), eff, sec) && unsafe && !isReadShapedPost(r) {
		return routeRefusal{status: http.StatusConflict, code: "governance_read_only", section: string(sec), message: "This setting is pinned by your organization and cannot be changed here."}
	}
	// A tab a page-access grant shows on an otherwise visible page is
	// read-only too (T-435): the grant shows it, it never unlocks it.
	if tab := registered.Tab(); tab != "" && sec != SectionNone && unsafe && !isReadShapedPost(r) {
		if id := nodegov.NavTabID(string(sec), tab); tabGrantReadOnly(eff, id) {
			return routeRefusal{status: http.StatusConflict, code: "governance_read_only", section: id, message: "Your organization shows this part of the page to you read-only."}
		}
	}
	if id := settingsSubsectionFor(sub, r.URL.Path); id != "" && !nodegov.IsUnhideableSettingsSection(id) &&
		eff.IsSettingsSectionReadOnly(id) && unsafe && !isReadShapedPost(r) && !isOrgDecidedSettingsPost(r) {
		return routeRefusal{status: http.StatusConflict, code: "governance_read_only", section: id, message: "This setting is pinned by your organization and cannot be changed here."}
	}
	// Restoring a config backup rewrites the WHOLE file, every Settings
	// section at once, so it cannot be attributed to one section: it is
	// refused whenever any section is hidden or read-only on this machine
	// (a restore would otherwise be the way round every lock).
	if r.URL.Path == configBackupPath && unsafe {
		if v := eff.DashboardVisibility(); len(v.HiddenSettings)+len(v.ReadOnlySettings) > 0 {
			return routeRefusal{status: http.StatusConflict, code: "governance_read_only", section: "config_restore", message: "Restoring a config backup is turned off because your organization manages some settings on this machine."}
		}
	}
	return routeRefusal{}
}

// settingsSharedRoutes is the closed list of routes registered under the
// Settings page WITHOUT a single owning subsection, each with the reason and
// the rule that governs it instead (Sol A3-01). Every other Settings route
// must declare its subsection at registration (SectionSettings.WithSettings);
// TestEverySettingsRouteDeclaresItsSubsection fails on a Settings route that
// does neither, so a new Settings API cannot quietly escape governance again.
var settingsSharedRoutes = map[string]string{
	"/api/config":                   "composite read: handleConfig withholds every hidden subsection's values (withholdHiddenSettings)",
	"/api/config/section/":          "the subsection is the path's <id> (configSectionID)",
	"/api/config/keys":              "each patched key's subsection is resolved from the schema (governanceConfigKeys)",
	"/api/config/backup":            "whole file: the preview is concealed while any subsection is hidden, a restore refused while any is hidden or read-only",
	"/api/config/schema":            "static descriptor of every key; carries no values",
	"/api/config/reload":            "re-reads the developer-owned file and changes no value itself; the file is not governed (D-134)",
	"/api/demo":                     "demo mode is driven from the shell's demo banner and onboarding card, not a Settings subsection",
	"/api/demo/start":               "demo mode is driven from the shell's demo banner and onboarding card, not a Settings subsection",
	"/api/demo/stop":                "demo mode is driven from the shell's demo banner and onboarding card, not a Settings subsection",
	"/api/update/status":            "the update banner reads it; developer-own banners are never governed (docs/managed-node-visibility.md)",
	"/api/update/extension-version": "loopback self-report from the VS Code extension; renders on no page",
	"/api/backfill/jobs/":           "one job by id in the shared job registry, which the Security page's evidence buttons also poll",
}

// readShapedPosts lists the routes that use POST but are READS: they change no
// state, write no config, and make no network call. Read-only means "cannot
// be changed here", not "cannot be looked at", so these pass a READ-ONLY
// section (they are still refused under a HIDDEN one, which means the page is
// not available at all). Table-driven (CLAUDE.md #5): a new read-shaped POST
// is one row with its reason. Exact paths only, never a prefix.
var readShapedPosts = map[string]string{
	// `observer cloud preview` builds the evidence envelope from the local DB
	// and prints the exact bytes that WOULD upload; no network, no write. It is
	// the developer's transparency tool, which the managed cloud default keeps
	// readable ("its status stays readable", nodegov managed defaults). G11.
	"/api/cloud/preview": "network-free, write-free evidence preview",
	// The AI tool settings editor's hygiene preview runs the sanity check
	// and renders the diff of a proposed save; it writes nothing (the save
	// is the separate /api/agent-config/save). A read-only page can still
	// show what a change would do.
	"/api/agent-config/preview":        "write-free hygiene preview of a vendor config save",
	"/api/agent-config/common/preview": "write-free fan-out preview of an all-adapters value",
	// `observer guard test`: one dry run of a command or file write against
	// the policy with fresh engines; nothing executes or persists.
	"/api/guard/test": "write-free guard dry run of one command or file write",
}

// isReadShapedPost reports whether r is a POST to a route in readShapedPosts.
func isReadShapedPost(r *http.Request) bool {
	if !strings.EqualFold(r.Method, http.MethodPost) {
		return false
	}
	_, ok := readShapedPosts[r.URL.Path]
	return ok
}

// orgDecidedSettingsPosts lists the POSTs that pass a READ-ONLY Settings
// subsection because they change no setting and the organization's OWN signed
// setting already decides whether they are allowed (and its server enforces
// it). A read-only lock means "the settings are the organization's"; these are
// actions inside those settings, not changes to them. They are still refused
// under a HIDDEN subsection. Exact paths only, one row with its reason.
var orgDecidedSettingsPosts = map[string]string{
	// Starting an org-plane enrichment of one session (Cloud Intelligence
	// parity phase 3, design 2.3 / 3.2): a managed developer may enrich when
	// the org's developer_actions setting allows it (default yes), and the org
	// server refuses it otherwise (developer_actions_off, the per-developer
	// cap). The managed `intel` default is read-only, which must not turn the
	// org's own "yes" into a "no".
	"/api/intel/enrich": "org-plane enrichment, allowed by the organization's developer_actions setting and enforced by its server",
}

// isOrgDecidedSettingsPost reports whether r is a POST to a route in
// orgDecidedSettingsPosts.
func isOrgDecidedSettingsPost(r *http.Request) bool {
	if !strings.EqualFold(r.Method, http.MethodPost) {
		return false
	}
	_, ok := orgDecidedSettingsPosts[r.URL.Path]
	return ok
}

// configBackupPath is the whole-file backup/restore route.
const configBackupPath = "/api/config/backup"

// concealed is concealment's answer: whether the request is refused as hidden
// (404) and, if so, the id and message the refusal names.
type concealed struct {
	hidden  bool
	section string
	message string
}

// concealment is the ONE owner of the guard's HIDDEN rules (T-401): the
// route registered as `registered`, requested at path, is refused 404 when
//
//  1. its nav page is hidden (never a floor page), unless it is a READ that
//     a shown page shares (sharedReadSections),
//  2. the one tab that owns it exclusively is hidden (WithTab),
//  3. its Settings subsection (declared at registration, or the <id> of
//     /api/config/section/<id>) is hidden (never a floor subsection; T8's
//     structural floor, enforced here a second time because the guard also
//     runs against postures that did not come through today's compiler: an
//     LKG cache from an older build, a hand-edited DB), or
//  4. it READS the config backup (safeMethod) while any Settings subsection
//     is hidden: the backup is the WHOLE previous file, hidden sections
//     included (Sol A3-01: a composite read must not be the way round a
//     hidden section).
//
// governanceGuard refuses with it, and concealedRoutes evaluates it for every
// registered route so the SPA skips the fetches it would refuse.
func concealment(registered Section, path string, safeMethod bool, eff govern.Effective) concealed {
	sec, sub := registered.Split()
	if sec != SectionNone && !nodegov.IsUnhideableNavSection(string(sec)) {
		if eff.IsNavSectionHidden(string(sec)) && !(safeMethod && sharedReadShown(path, eff)) {
			return concealed{true, string(sec), "This page is managed by your organization and is not available on this machine."}
		}
		if tab := registered.Tab(); tab != "" {
			if id := nodegov.NavTabID(string(sec), tab); eff.IsNavTabHidden(id) {
				return concealed{true, id, "This part of the page is managed by your organization and is not available on this machine."}
			}
		}
	}
	if id := settingsSubsectionFor(sub, path); id != "" && !nodegov.IsUnhideableSettingsSection(id) && eff.IsSettingsSectionHidden(id) {
		return concealed{true, id, "This page is managed by your organization and is not available on this machine."}
	}
	if path == configBackupPath && safeMethod {
		if v := eff.DashboardVisibility(); len(v.HiddenSettings) > 0 {
			return concealed{true, "config_backup", "The config backup preview is not available because your organization hides some settings on this machine."}
		}
	}
	return concealed{}
}

// sharedReadSections lists the routes whose READ another page also makes, so
// the read passes while the route's own page is hidden and any page listed
// here is shown (lane gov-tabs, roadmap section 8 item 4). The write stays
// with the registered page alone. Exact paths only, one row with its reason
// in the comment; TestSharedReadSectionsAreRegistered pins each row.
var sharedReadSections = map[string][]Section{
	// The New Terminal dialog (Terminals page) reads the trust chip for the
	// chosen directory; accepting trust stays a Code security action.
	"/api/security/trust": {SectionTerminals},
}

// sharedReadShown reports whether a page that shares path's read is shown.
func sharedReadShown(path string, eff govern.Effective) bool {
	for _, sec := range sharedReadSections[path] {
		if nodegov.IsUnhideableNavSection(string(sec)) || !eff.IsNavSectionHidden(string(sec)) {
			return true
		}
	}
	return false
}

// concealedRoutes lists the API routes a READ of which concealment refuses on
// this machine right now (T-401): the GET /api/governance
// `concealed_routes` block, which the SPA's one shared fetch guard (useApi)
// consults so a component never polls a route the posture hid (the 404
// console errors on governed nodes: /api/cloud/status, /api/config/backup).
// Entries are mux patterns without a method: an exact path, a prefix ending
// in "/", or path segments with {wildcards}. /api/config/section/ is listed
// per hidden subsection id. nil on a node where nothing can be hidden.
func concealedRoutes(sections map[string]Section, eff govern.Effective) []string {
	if len(sections) == 0 || !eff.VisibilityActive() {
		return nil
	}
	seen := map[string]bool{}
	add := func(path string, registered Section) {
		if !seen[path] && concealment(registered, path, true, eff).hidden {
			seen[path] = true
		}
	}
	for pattern, registered := range sections {
		path := pattern
		if method, rest, ok := strings.Cut(path, " "); ok {
			if method != http.MethodGet {
				continue // only a GET-able route is a read the SPA can make
			}
			path = rest
		}
		if path == configSectionPrefix {
			for _, id := range nodegov.SettingsSectionIDs {
				add(configSectionPrefix+id, registered)
			}
			continue
		}
		add(path, registered)
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// settingsSubsectionFor resolves the Settings subsection a request belongs to:
// the subsection its route declared at registration, else the <id> of the one
// dynamic route, /api/config/section/<id>. "" means none.
func settingsSubsectionFor(declared, path string) string {
	if declared != "" {
		return declared
	}
	if id, ok := configSectionID(path); ok {
		return id
	}
	return ""
}

// hiddenSettingsSet returns the Settings subsections hidden on this machine
// right now, or nil when nothing is (ungoverned node, dormant posture). The
// floor is never in it.
func (s *Server) hiddenSettingsSet(ctx context.Context) map[string]bool {
	if s.opts.Governance == nil {
		return nil
	}
	eff := s.opts.Governance(ctx)
	if !eff.VisibilityActive() {
		return nil
	}
	var out map[string]bool
	for _, id := range nodegov.SettingsSectionIDs {
		if nodegov.IsUnhideableSettingsSection(id) || !eff.IsSettingsSectionHidden(id) {
			continue
		}
		if out == nil {
			out = map[string]bool{}
		}
		out[id] = true
	}
	return out
}

// withholdHiddenSettings renders cfg as GET /api/config's `config` object with
// every value belonging to a hidden Settings subsection removed (Sol A3-01).
// The cut is per schema LEAF (configschema.Leaves: each leaf's FieldPath and
// subsection), so a top-level block shared by several subsections ([observer]
// spans eight) loses only the hidden ones' values. The enclosing objects stay,
// so a page that reads config.Observability.Judge still finds an object and
// renders an absence instead of throwing. Returns the withheld ids, sorted.
func withholdHiddenSettings(cfg any, hidden map[string]bool) (map[string]any, []string, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("withholdHiddenSettings: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, nil, fmt.Errorf("withholdHiddenSettings: %w", err)
	}
	withheld := map[string]bool{}
	for _, leaf := range configschema.Leaves() {
		if !hidden[leaf.Section] || leaf.FieldPath == "" {
			continue
		}
		deleteFieldPath(out, strings.Split(leaf.FieldPath, "."))
		withheld[leaf.Section] = true
	}
	ids := make([]string, 0, len(withheld))
	for id := range withheld {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return out, ids, nil
}

// withholdHiddenSecretKeys drops the redacted_secrets entries (dotted key ->
// "a credential is configured here") that belong to a hidden Settings
// section: even the PRESENCE of a credential in a section the organization
// hid is not this read's to reveal. A key no schema leaf maps to a section is
// dropped too (fail closed). Read-only sections keep their entries.
func withholdHiddenSecretKeys(present map[string]bool, hidden map[string]bool) map[string]bool {
	out := make(map[string]bool, len(present))
	for key, v := range present {
		section, ok := configschema.SectionOf(key)
		if !ok || hidden[section] {
			continue
		}
		out[key] = v
	}
	return out
}

// deleteFieldPath removes the value at path from a decoded JSON object tree.
func deleteFieldPath(m map[string]any, path []string) {
	for len(path) > 1 {
		next, ok := m[path[0]].(map[string]any)
		if !ok {
			return
		}
		m, path = next, path[1:]
	}
	if len(path) == 1 {
		delete(m, path[0])
	}
}

// configSectionID extracts the settings sub-section id from a
// /api/config/section/<id> path.
func configSectionID(path string) (string, bool) {
	if !strings.HasPrefix(path, configSectionPrefix) {
		return "", false
	}
	id := strings.TrimPrefix(path, configSectionPrefix)
	if id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

// governanceRefusal is the refusal body. It NAMES the cause — the honest
// -disabled-copy rule applied to an HTTP response: a developer inspecting a
// 404 must be able to tell "your organization hid this" from "this endpoint
// does not exist".
type governanceRefusal struct {
	Error   string `json:"error"`
	Section string `json:"section"`
	Family  string `json:"family"`
	Version int64  `json:"version"`
	OrgName string `json:"org_name,omitempty"`
	Message string `json:"message"`
}

func writeGovernanceRefusal(w http.ResponseWriter, status int, code, section string, eff govern.Effective, msg string) {
	orgName := eff.Notice.OrgDisplayName
	if orgName == "" {
		orgName = eff.OrgName
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(governanceRefusal{
		Error:   code,
		Section: section,
		Family:  "node.governance",
		Version: eff.Version,
		OrgName: orgName,
		Message: msg,
	})
}

// handleGovernance serves GET /api/governance: the node's resolved
// governance posture, which the SPA reads to filter its nav and render the
// managed notice.
//
// It is registered UNCONDITIONALLY and returns the DORMANT posture
// (active:false, empty lists) on any node without a grant — including every
// solo node — so the SPA needs no capability probing and the solo behaviour
// is a value, not a missing route.
func (s *Server) handleGovernance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	var eff govern.Effective
	if s.opts.Governance != nil {
		eff = s.opts.Governance(r.Context())
	} else {
		// No provider wired: resolve the zero inputs so the shape is
		// identical to a governed build's ungranted answer.
		eff = govern.Resolve(govern.Delivered{}, nil, govern.LiveIdentity{}, time.Now())
	}
	var sections map[string]Section
	if p := s.routeSections.Load(); p != nil {
		sections = *p
	}
	writeJSON(w, governanceResponse{
		Effective:       eff,
		Share:           s.resolveShareBlock(eff),
		Pricing:         s.resolvePricingBlock(r.Context()),
		Visibility:      s.dashboardVisibility(r.Context(), eff),
		ConcealedRoutes: concealedRoutes(sections, eff),
	})
}

// pageDefaultSupersedes lists the pages whose MANAGED-DEFAULT read-only
// yields to the page's own org policy once a verified one is held on this
// node (agentconfigorg.PagePinned). Table-driven (CLAUDE.md #5): one row per
// page that carries its own grant. An explicit org read-only directive is
// never superseded.
var pageDefaultSupersedes = map[Section]func(s *Server, ctx context.Context) bool{
	// The AI tool policy carries the developer access and grants (D-102).
	SectionAgentConfig: (*Server).agentConfigPolicyHeld,
}

// tabGrantReadOnly reports a page tab shown read-only by a page-access grant
// (T-435). Only a grant makes a tab read-only on its own; a tab of a
// read-only page is already refused by the page's check.
func tabGrantReadOnly(eff govern.Effective, id string) bool {
	lvl, src := eff.TabVisibility(id)
	return lvl == nodegov.VisibilityReadOnly && src == govern.VisibilitySourceGrant
}

// navSectionReadOnly is IsNavSectionReadOnly with pageDefaultSupersedes
// applied: what the API guard, the visibility block and the page's own
// access all read, so they cannot disagree.
func (s *Server) navSectionReadOnly(ctx context.Context, eff govern.Effective, sec Section) bool {
	lvl, src := eff.NavVisibility(string(sec))
	if lvl != nodegov.VisibilityReadOnly {
		return false
	}
	held := false
	if f, ok := pageDefaultSupersedes[sec]; ok && src == govern.VisibilitySourceDefault {
		held = f(s, ctx)
	}
	return agentconfigorg.PagePinned(true, src == govern.VisibilitySourceDefault, held)
}

// dashboardVisibility is eff.DashboardVisibility with the superseded
// managed defaults lifted (the SPA's read-only bar follows the API guard).
func (s *Server) dashboardVisibility(ctx context.Context, eff govern.Effective) govern.DashboardVisibility {
	v := eff.DashboardVisibility()
	for sec := range pageDefaultSupersedes {
		id := string(sec)
		e, ok := v.Sections[id]
		if !ok || e.Level != nodegov.VisibilityReadOnly || s.navSectionReadOnly(ctx, eff, sec) {
			continue
		}
		e.Level = nodegov.VisibilityVisible
		v.Sections[id] = e
		kept := v.ReadOnlySections[:0]
		for _, r := range v.ReadOnlySections {
			if r != id {
				kept = append(kept, r)
			}
		}
		v.ReadOnlySections = kept
	}
	return v
}

// resolvePricingBlock reports WHICH PRICE TABLE this node is applying
// (enterprise-pricing plan §3.3, node surfaces).
//
// It belongs on the governance endpoint rather than on a new one because it
// answers the same question every other row here answers: what did my
// organization decide for this machine, and how do I know? An org that
// distributes negotiated rates is changing every dollar figure this developer
// sees, and before this arc there was no surface anywhere that said so.
//
// It is read from the ENGINE, not from the config or the stored document, so
// it cannot drift from the rates the proxy will actually stamp onto the next
// turn. A nil engine yields a nil block and the card renders nothing — an
// absence, never a claim.
func (s *Server) resolvePricingBlock(ctx context.Context) *governancePricing {
	e := s.opts.CostEngine
	if e == nil {
		return nil
	}
	out := &governancePricing{
		OrgVersion:       e.OrgPricingVersion(),
		OrgAuthoritative: e.OrgPricingAuthoritative(),
		HasOrgPricing:    e.HasOrgPricing(),
		Warnings:         e.PricingWarnings(),
	}
	// A STANDALONE node composes the public feed through the same org-rows input
	// (§G), so a composed "org" rate there IS the feed. Relabel honestly rather
	// than claim an org this node is not enrolled with supplied the rate.
	feed := s.feedPosture(ctx)
	switch {
	case out.HasOrgPricing && feed.Active:
		out.Source = "feed"
		out.FeedVersion = feed.Version
		out.FeedFetchedAt = feed.FetchedAt
	case out.HasOrgPricing && out.OrgAuthoritative:
		out.Source = "org_authoritative"
	case out.HasOrgPricing:
		out.Source = "org"
	default:
		out.Source = "local"
	}
	return out
}

// governanceResponse is the wire shape of GET /api/governance: the resolved
// posture, with the `share` block REPLACED by the resolved per-key rows the
// Privacy page renders.
//
// The embedded Effective carries its own `share` field (the org's directives
// as delivered, map[string]any). This outer field shadows it — encoding/json
// resolves a tag collision in favour of the shallower field — which is the
// point: serializing Effective verbatim emitted bare booleans
// ({"share":{"cache_detail":true}}) where the SPA expects
// {effective, local, source} objects, so every consumer read `.source` off a
// boolean. That produced "not shared" for a tier the org had just RAISED and
// an undefined label lookup, on the one card whose entire job is telling a
// developer what their employer configured — and it fired only once an org
// actually published a share directive, i.e. exactly when it mattered.
type governanceResponse struct {
	govern.Effective
	Share map[string]governanceShareKey `json:"share,omitempty"`
	// Pricing is the node's own price-table posture. Omitted entirely when
	// this dashboard was assembled without a cost engine, so the SPA renders
	// an absence rather than a fabricated "seed".
	Pricing *governancePricing `json:"pricing,omitempty"`
	// Visibility is the RESOLVED per-page / per-Settings-section answer on
	// this machine (govern.Effective.DashboardVisibility): the org's applied
	// directives composed with the managed-node defaults. Every SPA surface
	// filters on it (nav, route guard, command palette, tour, help, Settings
	// rail), so the UI cannot disagree with governanceGuard. Always present;
	// on an ungoverned individual node every id is visible.
	Visibility govern.DashboardVisibility `json:"visibility"`
	// ConcealedRoutes lists the API routes whose READ the guard refuses as
	// hidden on this machine right now (concealedRoutes, T-401). The SPA's
	// shared fetch guard skips them, so a component on a visible page never
	// polls a hidden section's API. Omitted when nothing is concealed; an
	// older SPA ignores it.
	ConcealedRoutes []string `json:"concealed_routes,omitempty"`
}

// governancePricing is what the Privacy page's governance card says about
// rates: whose table is in force, which document version, and anything the
// engine refused.
type governancePricing struct {
	// Source is local (this machine's own seed + overrides), org (the org's
	// signed rates, under any local override), or org_authoritative (the org's
	// rates ABOVE this machine's own, on a managed node holding
	// enforce.budget).
	Source string `json:"source"`
	// OrgVersion is the org_pricing_version this node has applied, 0 for none.
	OrgVersion int64 `json:"org_version,omitempty"`
	// OrgAuthoritative and HasOrgPricing are carried separately from Source so
	// a future surface can render the two facts independently without
	// re-parsing an enum.
	OrgAuthoritative bool `json:"org_authoritative,omitempty"`
	HasOrgPricing    bool `json:"has_org_pricing,omitempty"`
	// Warnings are org rows the engine REFUSED. An admin who typed a rate and
	// saw nothing change deserves to find out why on the machine where it did
	// not apply.
	Warnings []string `json:"warnings,omitempty"`
	// FeedVersion / FeedFetchedAt are set only when Source == "feed" — the
	// standalone public-feed case (§G). They name the applied feed version and
	// when it was pulled, so the Privacy card can say "market list prices from
	// the Tokenomics feed vN (fetched T)".
	FeedVersion   int64  `json:"feed_version,omitempty"`
	FeedFetchedAt string `json:"feed_fetched_at,omitempty"`
}

// governanceShareKey is one row of the `share` block: what is in force, what
// this machine's own config asks for, and which of the two decided it.
//
// Local is `any` and may be null: it is the node's own setting for the key,
// and a key this build has no local counterpart for (see shareLocalTable) has
// no honest value to report there.
type governanceShareKey struct {
	Effective any                `json:"effective"`
	Local     any                `json:"local"`
	Source    govern.ShareSource `json:"source"`
	// PolicyVersion is the delivered body's version, so the Source column can
	// name the policy that decided the row. Omitted on a dormant posture.
	PolicyVersion int64 `json:"policy_version,omitempty"`
}

// shareLocalTable maps each org-directable share key (the closed
// nodegov.ShareKeys vocabulary) onto this node's own [org_client.share]
// setting. Table-driven rather than a switch so the coverage test can walk it
// against nodegov.ShareKeys and fail the moment the vocabulary grows a key
// this surface would silently mis-report.
//
// Values are `any` because the vocabulary is mixed-kind: bool for every tier,
// []string for target_action_allowlist. The getter takes the whole config
// because not every org-directable key roots under [org_client.share]
// (intelligence.org_enrichment lives under [intelligence]).
var shareLocalTable = map[string]func(config.Config) any{
	"full_content":        func(c config.Config) any { return c.OrgClient.Share.FullContent },
	"full_tool_bodies":    func(c config.Config) any { return c.OrgClient.Share.FullToolBodies },
	"routing_summary":     func(c config.Config) any { return c.OrgClient.Share.RoutingSummary },
	"cache_detail":        func(c config.Config) any { return c.OrgClient.Share.CacheDetail },
	"routing_detail":      func(c config.Config) any { return c.OrgClient.Share.RoutingDetail },
	"limit_gauge":         func(c config.Config) any { return c.OrgClient.Share.LimitGauge },
	"codeintel_detail":    func(c config.Config) any { return c.OrgClient.Share.CodeintelDetail },
	"process_detail":      func(c config.Config) any { return c.OrgClient.Share.ProcessDetail },
	"terminal_detail":     func(c config.Config) any { return c.OrgClient.Share.TerminalDetail },
	"task_detail":         func(c config.Config) any { return c.OrgClient.Share.TaskDetail },
	"tool_account_detail": func(c config.Config) any { return c.OrgClient.Share.ToolAccountDetail },
	"hook_activity":       func(c config.Config) any { return c.OrgClient.Share.HookActivity },
	"policy_state":        func(c config.Config) any { return c.OrgClient.Share.PolicyState },
	// intelligence.org_enrichment roots under [intelligence], not
	// [org_client.share] - the reason the getter takes the whole config.
	"intelligence.org_enrichment": func(c config.Config) any { return c.Intelligence.OrgEnrichment },
	"target_action_allowlist":     func(c config.Config) any { return c.OrgClient.Share.TargetActionAllowlist },
	"obs.summary":                 func(c config.Config) any { return c.OrgClient.Share.Obs.Summary },
	"obs.traces":                  func(c config.Config) any { return c.OrgClient.Share.Obs.Traces },
	"obs.content":                 func(c config.Config) any { return c.OrgClient.Share.Obs.Content },
	"obs.eval_summary":            func(c config.Config) any { return c.OrgClient.Share.Obs.EvalSummary },
	"obs.admission":               func(c config.Config) any { return c.OrgClient.Share.Obs.Admission },
	"obs.eval_items":              func(c config.Config) any { return c.OrgClient.Share.Obs.EvalItems },
	"obs.egress":                  func(c config.Config) any { return c.OrgClient.Share.Obs.Egress },
}

// resolveShareBlock resolves the org's delivered share directives against this
// node's own [org_client.share] settings, one row per key the org PUBLISHED —
// and only those, so the block's key set is unchanged and a key the org said
// nothing about keeps resolving to "you" in the SPA without a row.
//
// The merge is govern's, not this package's: MergeBool/LowerList are the same
// functions the push seam applies, so the "In force" column cannot drift from
// what actually ships. Reading the node's own config here (the same
// loadConfigForDashboard the Settings page uses) rather than taking an
// injected ShareOptions keeps the seam count at zero — /api/governance is
// fetched once per SPA mount, not on a hot path.
func (s *Server) resolveShareBlock(eff govern.Effective) map[string]governanceShareKey {
	if len(eff.Share) == 0 {
		return nil
	}
	var local config.Config
	if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
		local = cfg
	} else if s.opts.Logger != nil {
		// A config this process cannot parse is a real condition, not a
		// reason to drop the block: the org's directives are still in force
		// and the developer still gets to see them. The rows degrade to the
		// zero-value floor for `local`, which is what the push seam would
		// also fall back to.
		s.opts.Logger.Warn("governance: could not read local share settings", "error", err)
	}
	out := make(map[string]governanceShareKey, len(eff.Share))
	for key, directive := range eff.Share {
		row := governanceShareKey{PolicyVersion: eff.Version}
		fn, known := shareLocalTable[key]
		switch {
		case !known:
			// Unreachable while TestShareLocalTableCoversNodegovVocabulary
			// passes — nodegov.Compile refuses any share key outside its own
			// table on both the publish and the accept path. Kept so a drift
			// shows the key with the org named as its only source, rather
			// than dropping it (an invisible directive is the worst outcome
			// on a transparency surface).
			row.Effective, row.Local, row.Source = directive, nil, govern.ShareSourceOrg
		case isListDirective(directive):
			lv, _ := fn(local).([]string)
			ev := eff.LowerList(key, lv)
			// Normalize nil to [] on the wire only. govern preserves the
			// nil/empty distinction because the ALGEBRA needs it; the SPA
			// types both halves as string[] and renders either as "none", so
			// emitting null here would buy nothing and break the type.
			row.Effective, row.Local = orEmpty(ev), orEmpty(lv)
			row.Source = sourceForList(lv, ev)
		default:
			lv, _ := fn(local).(bool)
			// Gated (W-8), not the plain MergeBool/SourceForBool: this card
			// is the transparency surface, so it must report the exact
			// per-tier answer (ExtractionAuthorized) the push seam itself
			// gates on, not MergeBool's documented conservative
			// over-report. See internal/govern/sharetiers.go.
			row.Effective = eff.MergeBoolGated(key, lv)
			row.Local = lv
			row.Source = eff.SourceForBoolGated(key, lv)
		}
		out[key] = row
	}
	return out
}

// isListDirective reports whether an org directive is the list-kind
// (target_action_allowlist). Branching on the DIRECTIVE's shape rather than on
// the key name keeps the kind knowledge in one place — nodegov's compiler,
// which normalized it.
func isListDirective(v any) bool {
	_, ok := v.([]string)
	return ok
}

// sourceForList attributes a list-valued key. The list algebra is
// intersection-only in BOTH tenancies (there is no RaiseList), so the org can
// only ever have narrowed the node's own list or left it alone.
func sourceForList(local, effective []string) govern.ShareSource {
	if len(effective) < len(local) {
		return govern.ShareSourceOrg
	}
	return govern.ShareSourceBoth
}

// orEmpty renders a nil string slice as [] rather than null.
func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
