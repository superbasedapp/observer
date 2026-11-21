//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_assess.go serves the Code security page's "Security assessments"
// (docs/plans/security-assessments-module-plan-2026-11-13.md section 8):
//
//	GET  /api/security/assessments          the kinds and the recent runs
//	GET  /api/security/assessments/plan     one project's plan: the verdict, the
//	                                        target candidates, the prompt, the
//	                                        run id; mints the confirm token
//	POST /api/security/assessments/launch   the launch, a fresh terminal launch
//	                                        (startFreshTerminal)
//	GET  /api/security/assessments/report   a run's report.md as text/plain
//	POST /api/security/assessments/import   a run's findings.sarif through the
//	                                        existing SARIF import seam
//	POST /api/security/assessments/request  files the org request for a run's
//	                                        org-approved relaxations and holds the run
//	                                        (security_assess_org.go)
//	POST /api/security/assessments/cancel   withdraws a held run's requests
//
// Owner-local. This file is the only place HTTP, the sandbox probe and the
// SARIF seam meet the module (internal/secassess is the pure core,
// internal/secassesssvc the I/O). It adds no guard rule, approval or egress:
// the launch route is held for agents (agentLaunchRoutes) and asked about by
// R-168, and every gate a New terminal launch passes still runs.

// securityAssessRunsShown is how many runs the list reads (each is stat-ed).
const securityAssessRunsShown = 20

// securityAssessBodyMax caps the launch and import bodies.
const securityAssessBodyMax = 16 << 10

type securityAssessKindJS struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Summary    string   `json:"summary"`
	Mode       string   `json:"mode"`
	Launchable bool     `json:"launchable"`
	Reason     string   `json:"reason,omitempty"`
	Pointer    string   `json:"pointer,omitempty"`
	Sandbox    string   `json:"sandbox"`
	Target     string   `json:"target"`
	Files      []string `json:"files"`
	Note       string   `json:"note,omitempty"`
	// Blocked is why a launch of this kind cannot start on this machine right
	// now (the first refusing rule's sentence, with a placeholder project and
	// target), "" when nothing blocks it.
	Blocked     string `json:"blocked,omitempty"`
	BlockedCode string `json:"blocked_code,omitempty"`
	// Relaxable says the kind has relaxation rows (plan section 13.2).
	Relaxable bool `json:"relaxable"`
	// Exercise says the kind asks for an objective and a chain of steps (the red
	// team); FromRun says it is started from an earlier run's findings, never from
	// the list of assessments (the retest).
	Exercise bool `json:"exercise,omitempty"`
	FromRun  bool `json:"from_run,omitempty"`
}

type securityAssessFilesJS struct {
	Report   bool `json:"report"`
	SARIF    bool `json:"sarif"`
	Commands bool `json:"commands"`
	// Model is the run's assessment.json (kinds with a model contract).
	Model bool `json:"model"`
}

type securityAssessRunJS struct {
	ID              string                     `json:"id"`
	CreatedAt       time.Time                  `json:"created_at"`
	Kind            string                     `json:"kind"`
	KindTitle       string                     `json:"kind_title"`
	Tool            string                     `json:"tool"`
	ProjectRootHash string                     `json:"project_root_hash"`
	ProjectName     string                     `json:"project_name"`
	Handle          string                     `json:"handle,omitempty"`
	Seeded          bool                       `json:"seeded"`
	Sandboxed       bool                       `json:"sandboxed"`
	Backend         string                     `json:"backend,omitempty"`
	Tier            string                     `json:"tier,omitempty"`
	Target          string                     `json:"target,omitempty"`
	State           string                     `json:"state"`
	Files           securityAssessFilesJS      `json:"files"`
	ReportBytes     int64                      `json:"report_bytes"`
	Cloud           *secassess.CloudCounts     `json:"cloud,omitempty"`
	BoundaryCrossed bool                       `json:"boundary_crossed,omitempty"`
	Import          *secassesssvc.ImportRecord `json:"import,omitempty"`
	ProjectGone     bool                       `json:"project_gone,omitempty"`
	// Scope is the places a threat model was limited to and the developer's
	// note; PreviousRun is the earlier run its model is compared with once it is
	// checked (depth plan W3.3, W3.4).
	Scope       *securityAssessRunScopeJS `json:"scope,omitempty"`
	PreviousRun string                    `json:"previous_run,omitempty"`
	// CompareState says how the comparison with PreviousRun went once the model
	// was checked (ok, previous_missing, too_large; omitted until it was).
	CompareState string `json:"compare_state,omitempty"`
	// SecretMode is the environment-files mode that was in force for the run
	// (mask reads warn), not the one the setting says.
	SecretMode string `json:"secret_mode,omitempty"`
	// Objective is the developer's own objective of a red team run; RetestOf and
	// RetestFindings are the earlier run a retest replays and the findings it was
	// asked to replay (depth plan W7.3, W7.2).
	Objective      string   `json:"objective,omitempty"`
	RetestOf       string   `json:"retest_of,omitempty"`
	RetestFindings []string `json:"retest_findings,omitempty"`
	// SecretModeWhy is the closed reason a configured mask acted as warn, and
	// SecretMask what the workspace secret mask covered when the run asked for
	// it (counts and words, never a path).
	SecretModeWhy string                `json:"secret_mode_why,omitempty"`
	SecretMask    *securityAssessMaskJS `json:"secret_mask,omitempty"`

	// The time box, Stop and the boundary audit (plan W0).
	securityAssessTimeJS

	// Contract is the result contract the run was launched under ("" is the
	// SARIF contract); Validation is the outcome of the last validation of its
	// assessment.json (plan W1b).
	Contract   string                      `json:"contract,omitempty"`
	Validation *securityAssessValidationJS `json:"validation,omitempty"`

	// Phase is held (waiting for the organization), started or cancelled.
	Phase string `json:"phase"`
	// Held is a held run's per-rule answer, derived live from the grant cache.
	Held         *securityAssessHeldJS   `json:"held,omitempty"`
	Relax        []securityAssessRelaxJS `json:"relax,omitempty"`
	RelaxMinutes int                     `json:"relax_minutes,omitempty"`
	// Reported says the run writes audit rows to the org rail.
	Reported bool       `json:"reported"`
	Tenancy  string     `json:"tenancy,omitempty"`
	EndedAt  *time.Time `json:"ended_at,omitempty"`
	// Relaxed is how many verdicts the run's relaxations changed (Approx is the
	// org-grant half, counted by grant rather than by run).
	Relaxed *secassesssvc.RelaxedCount `json:"relaxed,omitempty"`
}

// securityAssessRelaxJS is one relaxation on a run, as the runs list shows it.
type securityAssessRelaxJS struct {
	Key        string     `json:"key"`
	Type       string     `json:"type"`
	Route      string     `json:"route"`
	State      string     `json:"state"`
	Scope      string     `json:"scope,omitempty"`
	ApprovalID int64      `json:"approval_id,omitempty"`
	GrantID    int64      `json:"grant_id,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	EndReason  string     `json:"end_reason,omitempty"`
	Note       string     `json:"note,omitempty"`
	Hosts      []string   `json:"hosts,omitempty"`
}

type securityAssessListJS struct {
	Kinds []securityAssessKindJS `json:"kinds"`
	Runs  []securityAssessRunJS  `json:"runs"`
	// ImportAvailable: the SARIF import is selected on this node.
	ImportAvailable bool `json:"import_available"`
	// Launch: this dashboard can start a terminal at all.
	Launch bool `json:"launch"`
	// RunsUnreadable says the run record exists but cannot be read, so the list
	// above is empty because of that, not because nothing was run; RunsError is
	// the closed reason.
	RunsUnreadable bool   `json:"runs_unreadable,omitempty"`
	RunsError      string `json:"runs_error,omitempty"`
	// RunsFile is the path of the run record, given while it cannot be read so
	// the callout can name the file to move aside.
	RunsFile string `json:"runs_file,omitempty"`
}

type securityAssessProjectJS struct {
	Hash     string `json:"project_root_hash"`
	Name     string `json:"name"`
	RootPath string `json:"root_path"`
	OnDisk   bool   `json:"on_disk"`
}

type securityAssessPlanJS struct {
	ConfirmToken string                  `json:"confirm_token"`
	RunID        string                  `json:"run_id"`
	Kind         securityAssessKindJS    `json:"kind"`
	Project      securityAssessProjectJS `json:"project"`
	OK           bool                    `json:"ok"`
	Rule         string                  `json:"rule,omitempty"`
	Code         string                  `json:"code,omitempty"`
	Reason       string                  `json:"reason,omitempty"`
	// Target is the normalized target the prompt names ("" until one is
	// chosen); TargetTyped says the caller named it (false: a placeholder
	// stood in for the checks).
	Target      string                `json:"target,omitempty"`
	TargetTyped bool                  `json:"target_typed"`
	Candidates  []secassess.Candidate `json:"candidates"`
	Boundary    []string              `json:"boundary"`
	Prompt      string                `json:"prompt,omitempty"`
	Backend     string                `json:"backend,omitempty"`
	Tier        string                `json:"tier,omitempty"`
	// AllowedTools narrows the agent picker for a sandboxed kind (a tool that
	// can be sandboxed and is routed through the proxy); nil means any.
	AllowedTools []string          `json:"allowed_tools"`
	Seeds        map[string]string `json:"seeds"`
	// Residual says the proxy-lane residual in words for a confined kind.
	Residual string `json:"residual,omitempty"`
	// Relax is the relaxations addendum's part of the plan (plan section 13);
	// nil for a kind with no relaxation rows.
	Relax *securityAssessRelaxPlanJS `json:"relax,omitempty"`
	// Held is the answer for the held run this plan replays (run=...).
	Held *securityAssessHeldJS `json:"held,omitempty"`
	// Limits are the time box, the deadline action and the boundary audit in
	// force for this run: the plan dialog's "settings in force".
	Limits *securityAssessLimitsJS `json:"limits,omitempty"`
	// PromptSHA256 is the digest of Prompt: the launch sends it back, and a
	// launch whose prompt no longer matches is refused (plan_changed) with the
	// new prompt. Empty while there is no prompt.
	PromptSHA256 string `json:"prompt_sha256,omitempty"`
	// Model is the model contract settings in force; nil for a kind without
	// one.
	Model *securityAssessModelLimitsJS `json:"model,omitempty"`
	// The blocks below belong to threat-model and penetration-test depth (plan
	// W3 and W4); each is present only for the kinds it applies to.
	Scope     *securityAssessScopeJS     `json:"scope,omitempty"`
	Grounding *securityAssessGroundingJS `json:"grounding,omitempty"`
	Previous  *securityAssessPreviousJS  `json:"previous,omitempty"`
	Start     *securityAssessStartJS     `json:"start,omitempty"`
	Preflight []secassess.Note           `json:"preflight,omitempty"`
	Tools     []securityAssessToolJS     `json:"tools,omitempty"`
	Env       *securityAssessEnvJS       `json:"env,omitempty"`
	Safety    []securityAssessSafetyJS   `json:"safety,omitempty"`
	// Probe is the request helper of a kind that probes (W5b): written into the
	// run folder, or why not.
	Probe *securityAssessProbeJS `json:"probe,omitempty"`
	// Objective is the red team exercise's objective in force; Retest is the
	// earlier run a retest replays with the findings it can and will replay.
	Objective *securityAssessObjectiveJS  `json:"objective,omitempty"`
	Retest    *securityAssessRetestPlanJS `json:"retest,omitempty"`
}

// securityAssessRelaxRowJS is one relaxation row of the plan: the table's words
// and the consent route the server decided, which the dialog shows as a tick
// or as the reason it is not offered.
type securityAssessRelaxRowJS struct {
	Key    string `json:"key"`
	Type   string `json:"type"`
	Title  string `json:"title"`
	Lifts  string `json:"lifts"`
	Why    string `json:"why"`
	Route  string `json:"route"`
	Row    string `json:"row"`
	Code   string `json:"code,omitempty"`
	Reason string `json:"reason"`
	// Ticked says the plan (or the held run it replays) has the row ticked.
	Ticked bool `json:"ticked"`
}

type securityAssessRelaxPlanJS struct {
	Tenancy    string                     `json:"tenancy"`
	Scope      string                     `json:"scope"`
	ScopeWords string                     `json:"scope_words"`
	Minutes    int                        `json:"minutes"`
	Reported   bool                       `json:"reported"`
	ReportRow  string                     `json:"report_row"`
	Enrolled   bool                       `json:"enrolled"`
	TierLive   string                     `json:"tier_live"`
	TierHosts  []string                   `json:"tier_hosts"`
	Rows       []securityAssessRelaxRowJS `json:"rows"`
	// Lines are the boundary lines the prompt gains with the ticked rows.
	Lines []string `json:"lines"`
}

// securityAssessResidual is what the plan dialog says about the forwarded
// model proxy (plan section 2.2).
const securityAssessResidual = "The sandbox's only route out is Observer's model proxy. That proxy also reaches the upstream addresses you configured in the proxy and routing settings, which can include a model server on this machine. If you route a local model server, its address is reachable from the box."

// securityAssessProbe returns the sandbox probe and whether one exists.
func (s *Server) securityAssessProbe(ctx context.Context) (SandboxAvailability, bool) {
	if s.opts.SandboxProber == nil {
		return SandboxAvailability{}, false
	}
	return s.opts.SandboxProber.ProbeSandbox(ctx), true
}

// securityAssessMaskCap is what is known of whether the sandbox row a run will
// use can hide the workspace's secret files and the launcher can report what it
// hid (decision D32): the probe's capability flag for the row the verdict chose,
// never the row's name, and the launcher's optional detailed call. An assessment
// asks for the mask only on MaskCan.
func (s *Server) securityAssessMaskCap(f secassess.Facts, backend string) secassess.MaskCapability {
	_, reports := s.opts.LaunchManager.(FreshLaunchDetailer)
	return secassess.MaskCapabilityOf(f.Backends, backend, reports)
}

// securityAssessFacts reduces the probe and the project to the pure rules'
// facts for one tool ("" judges no tool: the tool facts read as satisfied).
func (s *Server) securityAssessFacts(av SandboxAvailability, probed bool, root, tool string) secassess.Facts {
	tier := av.Egress
	capTier := tier
	if capTier == "" {
		capTier = "internet"
	}
	f := secassess.Facts{
		ProjectOnDisk: securityFixOnDisk(root), SandboxProbed: probed, Tier: tier,
		ToolSandboxable: true, ToolProxyRouted: true, ProxyPort: s.opts.ProxyPort,
	}
	// The in-box egress gateway's port is not a port the target may use: the
	// live tier has a gateway unless it is proxy_only (E5, plan section 13.9).
	if s.opts.ProxyPort != 0 && s.opts.SandboxGatewayPort != nil && (tier == "" || tier == "internet") {
		f.GatewayPort = s.opts.SandboxGatewayPort(s.opts.ProxyPort)
	}
	for _, b := range av.Backends {
		f.Backends = append(f.Backends, secassess.BackendFact{
			ID: b.ID, Label: b.Label, Available: b.Available, Beta: b.Beta, Local: b.Location == "local",
			Tiers: b.Egress, FullCapture: strings.HasPrefix(b.CaptureByTier[capTier], "full"),
			MasksSecrets: b.MasksWorkspaceSecrets,
		})
	}
	for _, src := range av.Sources {
		if src.ID == "live" && src.Available {
			f.SourceLiveAvailable = true
		}
	}
	if tool != "" {
		ta, ok := av.Tools[tool]
		f.ToolSandboxable, f.ToolSandboxReason = ok && ta.Available, ta.Reason
		cap, known := integration.For(tool)
		f.ToolProxyRouted = known && cap.Proxy != nil
	}
	return f
}

// securityAssessKindOf is a kind's wire row.
func securityAssessKindOf(k secassess.Kind) securityAssessKindJS {
	files := k.Files
	if files == nil {
		files = []string{}
	}
	return securityAssessKindJS{
		ID: string(k.ID), Title: k.Title, Summary: k.Summary, Mode: k.Mode, Launchable: k.Launchable,
		Reason: k.Reason, Pointer: k.Pointer, Sandbox: string(k.Sandbox), Target: string(k.Target), Files: files, Note: k.Note,
		Exercise: k.Exercise, FromRun: k.FromRun(),
	}
}

// securityAssessPlaceholderTarget stands in for the target while the caller
// has not chosen one, so the sandbox rules can still be judged.
const securityAssessPlaceholderTarget = "http://localhost:3000/"

// securityAssessAllowedTools is the launchable terminal tools a confined kind
// can use now: sandboxable and routed through the proxy.
func (s *Server) securityAssessAllowedTools(av SandboxAvailability, probed bool, root string) []string {
	out := []string{}
	for _, t := range launchableTools() {
		f := s.securityAssessFacts(av, probed, root, t)
		if f.ToolSandboxable && f.ToolProxyRouted {
			out = append(out, t)
		}
	}
	return out
}

// securityAssessNoToolReason is the refusal when the machine passes the
// sandbox rules but no agent can run a confined kind.
const securityAssessNoToolReason = "No agent on this machine can run this assessment: it must be launchable here, sandboxable and routed through Observer's proxy. Terminals > Settings and the Adapters page show what each agent supports."

// securityAssessNeedsATool turns a passing verdict into a refusal when no
// agent can run the kind (the per-agent rules are judged per launch; this is
// the plan-time summary over all agents).
func securityAssessNeedsATool(v *secassess.Verdict, allowed []string, probed bool) {
	if v.OK && probed && len(allowed) == 0 {
		v.OK, v.Rule, v.Code, v.Reason = false, "E8b", secassess.CodeToolNotProxyRouted, securityAssessNoToolReason
	}
}

// securityAssessRunView is a recorded run's wire row; root is the project's
// folder ("" when it is not known).
func securityAssessRunView(r secassesssvc.Run, root string) securityAssessRunJS {
	title := r.Kind
	if k, ok := secassess.KindByID(r.Kind); ok {
		title = k.Title
	}
	js := securityAssessRunJS{
		ID: r.ID, CreatedAt: r.CreatedAt, Kind: r.Kind, KindTitle: title, Tool: r.Tool,
		ProjectRootHash: r.ProjectRootHash, ProjectName: r.ProjectName, Handle: r.Handle, Seeded: r.Seeded,
		Sandboxed: r.Sandboxed, Backend: r.Backend, Tier: r.Tier, Target: r.Target,
		Phase: securityAssessPhase(r), Reported: r.Reported, Tenancy: r.Tenancy, RelaxMinutes: r.RelaxMinutes, Relaxed: r.Relaxed,
		Relax: securityAssessRelaxView(r.Relax), Files: securityAssessFilesJS{},
		securityAssessTimeJS: securityAssessTimeView(r, time.Now(), false),
	}
	if !r.EndedAt.IsZero() {
		t := r.EndedAt
		js.EndedAt = &t
	}
	if len(r.ScopePaths) > 0 || r.ScopeNote != "" {
		js.Scope = &securityAssessRunScopeJS{Paths: append([]string{}, r.ScopePaths...), Note: r.ScopeNote}
	}
	js.PreviousRun = r.PreviousRun
	js.Objective, js.RetestOf, js.RetestFindings = r.Objective, r.RetestOf, r.RetestFindings
	js.SecretMode, js.SecretModeWhy = r.SecretMode, r.SecretModeWhy
	if r.SecretMask != nil {
		m := securityAssessMaskView(*r.SecretMask)
		js.SecretMask = &m
	}
	if r.Validation != nil {
		js.CompareState = r.Validation.CompareState
	}
	if !r.IsStarted() {
		// A held or cancelled run has no terminal and no result files.
		js.State = js.Phase
		return js
	}
	v := secassesssvc.Describe(root, r)
	js.State = string(v.State)
	js.Files = securityAssessFilesJS{Report: v.Files.Report, SARIF: v.Files.SARIF, Commands: v.Files.Commands, Model: v.Files.Model}
	js.ReportBytes, js.Cloud, js.Import, js.ProjectGone = v.ReportBytes, v.Cloud, r.Import, v.ProjectGone
	js.Contract, js.Validation = r.Contract, securityAssessValidationView(r, v)
	js.BoundaryCrossed = v.Cloud != nil && v.Cloud.Crossed()
	return js
}

// securityAssessPhase is the run's phase in the wire vocabulary (a record
// from before the addendum has none and reads as started).
func securityAssessPhase(r secassesssvc.Run) string {
	switch r.Phase {
	case secassesssvc.PhaseHeld, secassesssvc.PhaseClaimed:
		return secassesssvc.PhaseHeld
	case secassesssvc.PhaseCancelled:
		return secassesssvc.PhaseCancelled
	}
	return secassesssvc.PhaseStarted
}

func securityAssessRelaxView(rs []secassesssvc.Relax) []securityAssessRelaxJS {
	if len(rs) == 0 {
		return nil
	}
	out := make([]securityAssessRelaxJS, 0, len(rs))
	for _, x := range rs {
		j := securityAssessRelaxJS{
			Key: x.Key, Type: x.Type, Route: x.Route, State: x.State, Scope: x.Scope, ApprovalID: x.ApprovalID,
			GrantID: x.GrantID, EndReason: x.EndReason, Note: x.Note, Hosts: x.Hosts,
		}
		if !x.ExpiresAt.IsZero() {
			t := x.ExpiresAt
			j.ExpiresAt = &t
		}
		out = append(out, j)
	}
	return out
}

// securityAssessRunViewFull is securityAssessRunView plus a held run's live
// answer from the grant cache.
func (s *Server) securityAssessRunViewFull(ctx context.Context, r secassesssvc.Run, root string) securityAssessRunJS {
	js := securityAssessRunView(r, root)
	side := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath)).Side()
	js.HasData = side.Has(r.ID)
	js.HasModel = side.HasFile(r.ID, secassesssvc.SideModel)
	if js.Phase == secassesssvc.PhaseHeld {
		js.Held = s.securityAssessHeld(ctx, r)
	}
	return js
}

// handleSecurityAssess serves GET /api/security/assessments.
func (s *Server) handleSecurityAssess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	av, probed := s.securityAssessProbe(ctx)
	out := securityAssessListJS{Kinds: []securityAssessKindJS{}, Runs: []securityAssessRunJS{}, ImportAvailable: s.securityAssessImportSelected(r), Launch: s.opts.LaunchManager != nil}
	for _, k := range secassess.Kinds() {
		js := securityAssessKindOf(k)
		js.Relaxable = len(secassess.RelaxationsFor(k.ID)) > 0
		if k.Launchable && k.Sandbox == secassess.SandboxRequired {
			// Judge the machine with a placeholder project and target: what
			// stops every launch of this kind here.
			facts := s.securityAssessFacts(av, probed, "", "")
			facts.ProjectOnDisk = true
			v := secassess.Eligible(k.ID, facts, secassess.Request{
				Kind: k.ID, Target: securityAssessPlaceholderTarget, Sandbox: true, Plan: true,
			})
			securityAssessNeedsATool(&v, s.securityAssessAllowedTools(av, probed, ""), probed)
			if !v.OK {
				js.Blocked, js.BlockedCode = v.Reason, v.Code
			}
		}
		out.Kinds = append(out.Kinds, js)
	}
	// A relaxation outlives nothing: the daemon's loop ends them each minute,
	// and this pass makes a listing current without waiting for it.
	s.securityAssessReconcile(ctx)
	index, err := securityProjectIndex(ctx, st)
	if err != nil {
		writeErrStatus(w, err, http.StatusInternalServerError)
		return
	}
	runStore := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	if err := runStore.Unreadable(); err != nil {
		out.RunsUnreadable, out.RunsError, out.RunsFile = true, codeRunRecordUnreadable, secassesssvc.Path(s.opts.DBPath)
	}
	for _, run := range runStore.Recent(securityAssessRunsShown) {
		root := ""
		if ref, ok := index[run.ProjectRootHash]; ok {
			root = ref.Root
		}
		out.Runs = append(out.Runs, s.securityAssessRunViewFull(ctx, run, root))
	}
	writeJSON(w, out)
}

// securityAssessImportSelected reports whether the SARIF import is selected
// and in this build (the same rule the upload route uses).
func (s *Server) securityAssessImportSelected(r *http.Request) bool {
	seam := s.opts.SARIFImport
	return seam != nil && seam.Import != nil && s.securitySARIFImportActive(r)
}

// handleSecurityAssessPlan serves GET /api/security/assessments/plan.
func (s *Server) handleSecurityAssessPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	k, ok := secassess.KindByID(q.Get("kind"))
	if !ok {
		http.Error(w, "unknown assessment kind", http.StatusBadRequest)
		return
	}
	st := store.New(s.db())
	index, err := securityProjectIndex(ctx, st)
	if err != nil {
		writeErrStatus(w, err, http.StatusInternalServerError)
		return
	}
	ref, known := index[q.Get("project")]
	if !known {
		http.Error(w, "unknown project", http.StatusNotFound)
		return
	}
	name := securityProjectName(ref)
	out := securityAssessPlanJS{
		ConfirmToken: setConfirmCookie(w, r), RunID: secassesssvc.NewRunID(), Kind: securityAssessKindOf(k),
		Project:    securityAssessProjectJS{Hash: q.Get("project"), Name: name, RootPath: ref.Root, OnDisk: securityFixOnDisk(ref.Root)},
		Candidates: []secassess.Candidate{}, Boundary: k.BoundaryLines(), Seeds: securityFixSeeds(),
		AllowedTools: nil,
	}
	if !k.Launchable {
		out.Reason, out.Code, out.Rule = k.Reason, secassess.CodeNotLaunchable, "E1"
		writeJSON(w, out)
		return
	}
	src, ok := s.securityAssessPlanSourceOf(w, q, k, &out)
	if !ok {
		return
	}
	av, probed := s.securityAssessProbe(ctx)
	facts := s.securityAssessFacts(av, probed, ref.Root, "")
	req := secassess.Request{Kind: k.ID, Sandbox: true, Plan: true}
	var relax securityAssessRelaxPlan
	var sel securityAssessSelection
	relaxable := len(secassess.RelaxationsFor(k.ID)) > 0
	if relaxable {
		relax = s.securityAssessRelaxFacts(ctx, k.ID, ref.Root, av)
		sel = securityAssessLenientSelection(relax.Rows, src.ticks, src.tier)
		facts = securityAssessFactsRelaxed(facts, relax)
		req.TierRelax = sel.Tier
	}
	assessCfg := s.securityAssessConfig().Security.Assessments
	ground := s.securityAssessGround(ctx, st, securityAssessGroundIn{
		Kind: k, Root: ref.Root, Hash: q.Get("project"), RunID: out.RunID, Choices: src.choices, Cfg: assessCfg, Tier: facts.Tier,
		TargetPort:      securityAssessTypedPort(src.typed),
		DefaultFindings: src.held == nil,
	})
	if k.Target == secassess.TargetRequired {
		req.Target = securityAssessPlanTarget(&out, ground, ref.Root, src.typed)
	}
	if k.Sandbox == secassess.SandboxRequired {
		out.AllowedTools = s.securityAssessAllowedTools(av, probed, ref.Root)
		out.Tier = av.Egress
		out.Residual = securityAssessResidual
	}
	v := secassess.Eligible(k.ID, facts, req)
	if k.Sandbox == secassess.SandboxRequired {
		securityAssessNeedsATool(&v, out.AllowedTools, probed)
	}
	out.OK, out.Rule, out.Code, out.Reason, out.Backend = v.OK, v.Rule, v.Code, v.Reason, v.Backend
	if k.Target == secassess.TargetRequired && v.Target.Host != "" {
		out.Target = v.Target.String()
	}
	// The environment-files mode meets the run's sandbox now that the verdict
	// has named one (a plan with no verdict has no sandbox: mask reads warn).
	maskBackend := v.Backend
	if maskBackend == "" && k.Sandbox == secassess.SandboxRequired {
		// The route sandboxes this kind whatever the plan says, and picks the
		// backend itself. A plan refused before rule E9 chose one (a target that
		// is not on loopback, say) names none, but the sandbox is not undecided:
		// the line about the environment files reads what the route would pick,
		// never "no sandbox is chosen for this run yet".
		maskBackend = secassess.AutoBackend(facts, req.TierRelax)
	}
	ground.resolveMask(s.securityAssessMaskCap(facts, maskBackend))
	// A start command that cannot be used, or an open secret under the Refuse
	// setting, refuses the plan with its own code and gives no task to read. A
	// scope place that was refused does not: the dialog shows it beside the
	// scope and the task is built from the places that were accepted.
	if code, reason := ground.refusal(false); v.OK && code != "" {
		out.OK, out.Rule, out.Code, out.Reason = false, "", code, reason
	}
	limits := securityAssessLimitsFor(k, assessCfg)
	out.Limits = securityAssessPlanLimits(k, limits, assessCfg, relaxable, relax)
	var inForce []secassess.InForce
	if relaxable {
		inForce = sel.promptRelax(relax.Policy.Scope, relax.Tier.Hosts)
		out.Relax = securityAssessRelaxPlanView(k.ID, relax, sel, inForce, s.securityAssessEnrolled(ctx))
	}
	if src.held != nil {
		out.Held = s.securityAssessHeld(ctx, *src.held)
	}
	// A typed target that the rules accepted gets a prompt; a kind without a
	// target always does.
	if out.OK && (k.Target == secassess.TargetNone || out.TargetTyped) {
		securityAssessPlanPrompt(&out, k, v, inForce, limits, assessCfg, ground)
	}
	securityAssessPlanViews(&out, k, assessCfg, ground)
	if k.Retest {
		redact, _ := securityAssessRedactorOf(s.securityAssessConfig())
		out.Retest = securityAssessRetestPlanView(ground.retest, redact)
	}
	writeJSON(w, out)
}

// securityAssessPlanSource is what a plan is built from: the typed target, the
// relaxation ticks and the depth choices, and the held run when the plan
// replays one.
type securityAssessPlanSource struct {
	typed   string
	ticks   []string
	tier    bool
	choices securityAssessChoices
	held    *secassesssvc.Run
}

// securityAssessPlanSourceOf reads the plan's ticks and choices from the query,
// or from the held run this plan replays: then the run id, target and
// relaxations are the held run's own, so the prompt the developer reads is the
// prompt the agent gets. It answers a held run that is not waiting for this
// assessment and project with a 409 itself and reports false.
func (s *Server) securityAssessPlanSourceOf(w http.ResponseWriter, q url.Values, k secassess.Kind, out *securityAssessPlanJS) (securityAssessPlanSource, bool) {
	src := securityAssessPlanSource{typed: strings.TrimSpace(q.Get("target"))}
	src.ticks, src.tier = securityAssessTicks(q)
	src.choices = securityAssessChoicesFromQuery(q)
	id := strings.TrimSpace(q.Get("run"))
	if id == "" {
		return src, true
	}
	hr, found := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath)).Get(id)
	if !found || hr.Phase != secassesssvc.PhaseHeld || hr.Kind != string(k.ID) || hr.ProjectRootHash != q.Get("project") {
		http.Error(w, "that held run is not waiting for this assessment and project", http.StatusConflict)
		return src, false
	}
	src.held = &hr
	out.RunID, src.typed = hr.ID, hr.Target
	src.ticks, src.tier = securityAssessHeldTicks(hr)
	src.choices = securityAssessHeldChoices(hr)
	return src, true
}

// securityAssessPlanTarget fills the plan's target candidates, which are read
// from every file that names a development server (the survey; a folder the
// survey could not open still gets the launch file's), and returns the target
// the rules judge: the typed one, else the first candidate, else the
// placeholder.
func securityAssessPlanTarget(out *securityAssessPlanJS, ground securityAssessGround, root, typed string) string {
	if ground.surveyed {
		out.Candidates = append(out.Candidates, secassess.PlanCandidates(ground.facts)...)
	} else if data, err := secassesssvc.ReadResult(root, ".claude/launch.json", secassess.MaxLaunchJSON); err == nil {
		out.Candidates = append(out.Candidates, secassess.LaunchCandidates(data)...)
	}
	out.TargetTyped = typed != ""
	if typed != "" {
		return typed
	}
	if len(out.Candidates) > 0 {
		return out.Candidates[0].URL
	}
	return securityAssessPlaceholderTarget
}

// securityAssessPlanLimits is the plan's limits view: the time box (a
// relaxable kind's policy may raise it) and, for a kind that probes, the
// request budget and pace in force.
func securityAssessPlanLimits(k secassess.Kind, limits securityAssessLimits, cfg config.SecurityAssessmentsConfig, relaxable bool, relax securityAssessRelaxPlan) *securityAssessLimitsJS {
	relaxMinutes := 0
	if relaxable {
		relaxMinutes = relax.Policy.MaxMinutes
	}
	view := securityAssessLimitsView(k, limits, relaxMinutes)
	if k.Probing {
		view.RequestBudget, view.PaceRPS = cfg.PentestRequestBudget, cfg.PentestPaceRPS
	}
	return &view
}

// securityAssessPlanPrompt builds the task the developer reads and records its
// digest. A prompt that cannot be built leaves both empty.
func securityAssessPlanPrompt(out *securityAssessPlanJS, k secassess.Kind, v secassess.Verdict, inForce []secassess.InForce, limits securityAssessLimits, cfg config.SecurityAssessmentsConfig, ground securityAssessGround) {
	var target *secassess.Target
	if k.Target == secassess.TargetRequired {
		t := v.Target
		target = &t
	}
	in := securityAssessPromptInput(k, out.RunID, out.Project.Name, target, inForce, limits, cfg, v.Backend)
	ground.fill(&in)
	if p, err := secassess.BuildPrompt(in); err == nil {
		out.Prompt, out.PromptSHA256 = p, secassess.PromptSHA256(p)
	}
}

// securityAssessPlanViews fills the plan's model limits and the views the
// ground (scope, grounding, earlier run, start, preflight, tools, environment
// files) and the kind (safety table) carry.
func securityAssessPlanViews(out *securityAssessPlanJS, k secassess.Kind, cfg config.SecurityAssessmentsConfig, ground securityAssessGround) {
	out.Model = securityAssessModelLimitsView(k, cfg)
	if out.Model != nil && k.Probing {
		out.Model.SecretMode, out.Model.SecretModeEffective, out.Model.SecretModeDowngrade = ground.secret.Configured, ground.secret.Effective, ground.secret.Why
		out.Model.RequestBudget, out.Model.PaceRPS = cfg.PentestRequestBudget, cfg.PentestPaceRPS
	}
	if out.Model != nil && k.Grounded {
		out.Model.Grounding = string(ground.mode)
	}
	out.Scope, out.Grounding, out.Previous = ground.scopeJS(), ground.groundingJS(), ground.previousJS()
	out.Start, out.Preflight, out.Tools = ground.startJS(), ground.preflightJS(), ground.toolsJS()
	out.Env, out.Safety = ground.envJS(), securityAssessSafetyView(k, secassess.SafetyFacts{Helper: ground.probe.Mode == secassess.HelperOn, Mask: ground.asksForMask()})
	out.Probe = ground.probeJS(out.RunID)
	if k.Exercise {
		out.Objective = &securityAssessObjectiveJS{Text: ground.objective, Max: secassess.MaxObjective}
	}
}

type securityAssessLaunchRequest struct {
	// Assessment is the kind id (the embedded launch body's "kind" is the
	// launch shape, which this route only accepts as terminal).
	Assessment      string `json:"assessment"`
	ProjectRootHash string `json:"project_root_hash"`
	RunID           string `json:"run_id"`
	Target          string `json:"target"`
	ConfirmTarget   string `json:"confirm_target"`
	// Relaxations are the rule ids the developer ticked and TierRelax the
	// tier row's tick (plan section 13.5). A body naming neither launches
	// exactly as it did before the addendum.
	Relaxations []string `json:"relaxations"`
	TierRelax   bool     `json:"tier_relax"`
	// PromptSHA256 is the digest of the prompt the developer read in the plan;
	// a launch that rebuilds a different prompt is refused (plan_changed). A
	// body without it (an older dialog) is accepted.
	PromptSHA256 string `json:"prompt_sha256"`
	// The choices made on the plan (depth plan W3.3, W3.4, W4.1): the scope of a
	// threat model and an earlier run to compare it with, and the start command
	// of a penetration test or red team ("none" declares none). A body naming
	// none of them gets the defaults the plan showed. A run held for the
	// organization keeps the choices it was held with.
	ScopePaths  []string `json:"scope_paths"`
	ScopeNote   string   `json:"scope_note"`
	PreviousRun string   `json:"previous_run"`
	Start       string   `json:"start"`
	// Prepare says the developer ticked the selected plan's preparation steps
	// (a migrate, a seed) to run first; the default is off.
	Prepare bool `json:"prepare"`
	// Objective is a red team run's objective; OfRun and FindingIDs are the
	// earlier run and the findings of a retest (depth plan W7.3, W7.2). A held run
	// keeps the ones it was held with.
	Objective  string   `json:"objective"`
	OfRun      string   `json:"of_run"`
	FindingIDs []string `json:"finding_ids"`
	terminalLaunchRequest
}

type securityAssessLaunchJS struct {
	terminalLaunchResponse
	Seeded bool   `json:"seeded"`
	Prompt string `json:"prompt,omitempty"`
	RunID  string `json:"run_id"`
	// SecretMask is what the workspace secret mask covered, present when the
	// launch asked the sandbox to hide environment and key files (decision
	// D32). A partial mask is a warning the dialog shows, not a refusal: the
	// box has started when this is known.
	SecretMask *securityAssessMaskJS `json:"secret_mask,omitempty"`
}

func writeSecurityAssessRefusal(w http.ResponseWriter, status int, rule, code, reason string) {
	writeJSONStatus(w, status, map[string]string{"error": reason, "code": code, "rule": rule})
}

// The refusals of a launch whose request helper could not be put into the run
// folder; the task says the files are there, so the run does not start without
// them. codeHelperExists is the folder already holding a different probe.py or
// probe.json (nothing there was changed); codeHelperNotWritten is any other
// cause. The sentences carry closed words only, never the error's text.
const (
	codeHelperNotWritten = "helper_not_written"
	codeHelperExists     = "helper_exists"
)

// securityAssessHelperRefusal is the status, code and sentence of the refusal
// for the error WriteProbeFiles (or the launch) gave.
func securityAssessHelperRefusal(err error) (status int, code, msg string) {
	switch {
	case errors.Is(err, secassesssvc.ErrProbeExists):
		return http.StatusConflict, codeHelperExists, "The run folder already holds a different probe.py or probe.json from an earlier attempt, so the run did not start and nothing there was changed. Look in .observer/assessments, or turn off \"" + secassess.LabelProbeHelper + "\" in " + secassess.WhereSettings + ", then try again."
	case errors.Is(err, secassesssvc.ErrProbeConfigTooLarge):
		return http.StatusConflict, codeRetestTooLarge, reasonRetestTooLarge
	case errors.Is(err, secassesssvc.ErrProbeRun):
		return http.StatusInternalServerError, codeHelperNotWritten, "The request helper could not be written into the run folder (the folder is not there, or this run has nowhere to put one), so the run did not start. Start the run again, or turn off \"" + secassess.LabelProbeHelper + "\" in " + secassess.WhereSettings + "."
	}
	return http.StatusInternalServerError, codeHelperNotWritten, "The request helper could not be written into the run folder (the write failed), so the run did not start. Check that the project folder can be written to, or turn off \"" + secassess.LabelProbeHelper + "\" in " + secassess.WhereSettings + ", then try again."
}

// codeHeldRunMismatch is the refusal of a launch that does not restate the
// held run it starts.
const codeHeldRunMismatch = "held_run_mismatch"

// codeHeldByAnotherRun is the refusal of a project-scoped relaxation another
// assessment run's approval already holds.
const codeHeldByAnotherRun = "relaxation_held_by_another_run"

// securityAssessLaunch is what one launch request has decided so far. The
// steps below each take the next decision, answer the refusal through w
// themselves and report false when they did.
type securityAssessLaunch struct {
	body securityAssessLaunchRequest
	kind secassess.Kind
	runs *secassesssvc.Store
	// prior is the run already recorded under the id; heldStart says it is a
	// run held for the organization's approval, which this launch starts.
	prior     secassesssvc.Run
	heldStart bool
	st        *store.Store
	ref       store.SecProjectRef
	facts     secassess.Facts
	relax     securityAssessRelaxPlan
	sel       securityAssessSelection
	verdict   secassess.Verdict
	grants    map[string]accessgrant.Held
	// limits are the time box, deadline action and audit switch in force; cfg is
	// the [security.assessments] block the launch read once.
	limits securityAssessLimits
	cfg    config.SecurityAssessmentsConfig
	// ground is what the launch learned about the project and the plan's choices.
	ground securityAssessGround
	// helper is what the request helper's write put in the run folder (the
	// hashes the run records); zero when the helper is not on.
	helper secassesssvc.ProbeFiles
	// Set by securityAssessLaunchStart.
	launch terminalLaunchRequest
	name   string
	prompt string
	seeded bool
	resp   terminalLaunchResponse
}

// handleSecurityAssessLaunch serves POST /api/security/assessments/launch.
func (s *Server) handleSecurityAssessLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	if s.opts.LaunchManager == nil {
		http.Error(w, "launch unavailable - this dashboard runs without the embedded-terminal launcher (run via `observer start`)", http.StatusServiceUnavailable)
		return
	}
	l, ok := s.securityAssessLaunchParse(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if !s.securityAssessLaunchLocate(ctx, w, l) || !s.securityAssessLaunchDecide(ctx, w, l) || !s.securityAssessLaunchStart(w, r, l) {
		return
	}
	s.securityAssessLaunchRecord(ctx, l)
	out := securityAssessLaunchJS{terminalLaunchResponse: l.resp, Seeded: l.seeded, RunID: l.body.RunID}
	if l.launch.maskWorkspaceSecrets {
		m := securityAssessMaskView(securityAssessMaskReportOf(l.resp.secretMask))
		out.SecretMask = &m
	}
	if !l.seeded {
		out.Prompt = l.prompt
	}
	writeJSON(w, out)
	s.kickWatchRootsRefresh()
}

// securityAssessLaunchParse reads the body and checks what needs no lookup: the
// tool, the kind, the run id and whether the id is already in use.
func (s *Server) securityAssessLaunchParse(w http.ResponseWriter, r *http.Request) (*securityAssessLaunch, bool) {
	var body securityAssessLaunchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, securityAssessBodyMax)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return nil, false
	}
	// A security assessment runs an agent in a terminal: never a GUI app, a
	// plain shell or a client-chosen folder.
	if k := strings.TrimSpace(body.Kind); k != "" && integration.LaunchKind(k) != integration.LaunchKindTerminal {
		http.Error(w, "an assessment starts a terminal agent", http.StatusBadRequest)
		return nil, false
	}
	if _, ok := launchSubcommand(body.Tool); !ok {
		http.Error(w, "tool "+body.Tool+" is not launchable in the embedded terminal", http.StatusBadRequest)
		return nil, false
	}
	kind, ok := secassess.KindByID(body.Assessment)
	if !ok {
		http.Error(w, "unknown assessment kind", http.StatusBadRequest)
		return nil, false
	}
	if !kind.Launchable {
		writeSecurityAssessRefusal(w, http.StatusConflict, "E1", secassess.CodeNotLaunchable, kind.Reason)
		return nil, false
	}
	if !secassess.ValidRunID(body.RunID) {
		http.Error(w, "bad run id: read the plan again", http.StatusBadRequest)
		return nil, false
	}
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	// A run id already recorded is refused, except a run held for the
	// organization's approval: that is the one this launch starts.
	prior, recorded := runs.Get(body.RunID)
	if recorded && prior.Phase != secassesssvc.PhaseHeld {
		http.Error(w, "that run was already started: read the plan again", http.StatusConflict)
		return nil, false
	}
	return &securityAssessLaunch{body: body, kind: kind, runs: runs, prior: prior, heldStart: recorded}, true
}

// securityAssessLaunchLocate finds the project and checks that a held run is
// being started for the assessment and project it was held for.
func (s *Server) securityAssessLaunchLocate(ctx context.Context, w http.ResponseWriter, l *securityAssessLaunch) bool {
	l.st = store.New(s.db())
	index, err := securityProjectIndex(ctx, l.st)
	if err != nil {
		writeErrStatus(w, err, http.StatusInternalServerError)
		return false
	}
	ref, known := index[l.body.ProjectRootHash]
	if !known {
		http.Error(w, "unknown project", http.StatusNotFound)
		return false
	}
	l.ref = ref
	if l.heldStart && (l.prior.Kind != string(l.kind.ID) || l.prior.ProjectRootHash != l.body.ProjectRootHash) {
		writeSecurityAssessRefusal(w, http.StatusConflict, "", codeHeldRunMismatch, "That run was held for a different assessment or project. Read the plan again.")
		return false
	}
	return true
}

// securityAssessRouteSandboxes says the launch route itself puts this kind's
// run in a sandbox: a kind that runs only in one (the penetration test, the red
// team) is sandboxed by the route, whatever the body says. The dialog sends no
// sandbox fields for such a task (web terminalTask.ts serverSandbox), so the
// route is the one that decides, and it refuses a launch it cannot confine
// (E7 to E10) rather than starting one bare. The held-launch card reads the
// same answer, so what a human is shown is what the route does.
func securityAssessRouteSandboxes(k secassess.Kind) bool {
	return k.Sandbox == secassess.SandboxRequired
}

// securityAssessEligibilityRequest is the request the launch hands the
// eligibility rules. For a kind the route sandboxes the body's sandbox flag is
// not read (true or false, the answer is the same: sandboxed), so E6 cannot
// refuse the launch of such a kind. The backend and the workspace source a body
// names are still checked, not replaced: E9 takes a named backend only when it
// is grounded and available, and E10 refuses any source but the live
// workspace; a body naming neither (what the dialog sends) gets Automatic and
// the live workspace.
func securityAssessEligibilityRequest(k secassess.Kind, body securityAssessLaunchRequest, tierRelax bool) secassess.Request {
	return secassess.Request{
		Kind: k.ID, Target: body.Target, ConfirmTarget: body.ConfirmTarget,
		Sandbox: body.Sandbox || securityAssessRouteSandboxes(k),
		Backend: body.Backend, WorkspaceSource: body.WorkspaceSource, TierRelax: tierRelax,
	}
}

// securityAssessBodySandboxed reads a held launch body for the assessment it
// names and says whether the route will sandbox that run (the launch card's
// sandbox line). A body that does not decode, or names no kind, is not.
func securityAssessBodySandboxed(body []byte) bool {
	var b struct {
		Assessment string `json:"assessment"`
	}
	if json.Unmarshal(body, &b) != nil {
		return false
	}
	k, ok := secassess.KindByID(b.Assessment)
	return ok && securityAssessRouteSandboxes(k)
}

// securityAssessLaunchDecide runs the decisions: the ticked relaxations, the
// eligibility rules, the held run's own terms, the organization's grants and
// the project row another run may hold.
func (s *Server) securityAssessLaunchDecide(ctx context.Context, w http.ResponseWriter, l *securityAssessLaunch) bool {
	body := l.body
	av, probed := s.securityAssessProbe(ctx)
	facts := s.securityAssessFacts(av, probed, l.ref.Root, body.Tool)
	l.relax = s.securityAssessRelaxFacts(ctx, l.kind.ID, l.ref.Root, av)
	sel, serr := securityAssessSelect(l.relax.Rows, body.Relaxations, body.TierRelax)
	if serr != nil {
		writeSecurityAssessRefusal(w, serr.Status, serr.Rule, serr.Code, serr.Reason)
		return false
	}
	l.sel = sel
	if l.heldStart {
		wantKeys, wantTier := securityAssessHeldTicks(l.prior)
		if !securityAssessSameTicks(sel, wantKeys, wantTier) {
			writeSecurityAssessRefusal(w, http.StatusConflict, "", codeHeldRunMismatch, "This launch does not name the same relaxations the run was held for. Read the plan again.")
			return false
		}
	}
	l.facts = securityAssessFactsRelaxed(facts, l.relax)
	l.verdict = secassess.Eligible(l.kind.ID, l.facts, securityAssessEligibilityRequest(l.kind, body, sel.Tier))
	if !l.verdict.OK {
		writeSecurityAssessRefusal(w, http.StatusConflict, l.verdict.Rule, l.verdict.Code, l.verdict.Reason)
		return false
	}
	if l.heldStart && l.prior.Target != "" && l.prior.Target != l.verdict.Target.String() {
		writeSecurityAssessRefusal(w, http.StatusConflict, "", codeHeldRunMismatch, "The target is not the one the run was held for. Read the plan again.")
		return false
	}
	// The plan's choices are read once and refused here, before anything is
	// asked of the organization: a scope place or start command that is not
	// accepted, and an open secret under the Refuse setting.
	l.cfg = s.securityAssessConfig().Security.Assessments
	choices := securityAssessChoices{
		ScopePaths: body.ScopePaths, ScopeNote: body.ScopeNote,
		PreviousRun: strings.TrimSpace(body.PreviousRun), Start: strings.TrimSpace(body.Start), Prepare: body.Prepare,
		Objective: body.Objective, RetestOf: strings.TrimSpace(body.OfRun), RetestFindings: body.FindingIDs,
	}
	if len(choices.ScopePaths) > securityAssessMaxScopeQuery {
		choices.ScopePaths = choices.ScopePaths[:securityAssessMaxScopeQuery]
	}
	if len(choices.RetestFindings) > securityAssessMaxRetestQuery {
		choices.RetestFindings = choices.RetestFindings[:securityAssessMaxRetestQuery]
	}
	if l.heldStart {
		choices = securityAssessHeldChoices(l.prior)
	}
	l.ground = s.securityAssessGround(ctx, l.st, securityAssessGroundIn{
		Kind: l.kind, Root: l.ref.Root, Hash: body.ProjectRootHash, RunID: body.RunID, Choices: choices, Cfg: l.cfg, Tier: l.facts.Tier, TargetPort: l.verdict.Target.PortNumber(),
	})
	l.ground.resolveMask(s.securityAssessMaskCap(l.facts, l.verdict.Backend))
	if code, reason := l.ground.refusal(true); code != "" {
		writeSecurityAssessRefusal(w, http.StatusConflict, "", code, reason)
		return false
	}
	// A rule only the organization can lift starts only under a grant in force.
	if org := sel.orgRules(); len(org) > 0 {
		grants, refusal := s.securityAssessOrgGrants(ctx, org, body.ProjectRootHash)
		if refusal != nil {
			refusal.write(w)
			return false
		}
		l.grants = grants
	}
	if refusal := s.securityAssessProjectRowHeld(ctx, l.st, sel, l.relax.Policy, body.ProjectRootHash); refusal != nil {
		refusal.write(w)
		return false
	}
	return true
}

// securityAssessLaunchStart builds the launch the verdict allows, claims a held
// run and starts the terminal.
func (s *Server) securityAssessLaunchStart(w http.ResponseWriter, r *http.Request, l *securityAssessLaunch) bool {
	launch := l.body.terminalLaunchRequest
	launch.Kind, launch.ProjectRoot = "", l.ref.Root
	if l.verdict.ForceSandbox {
		launch.Sandbox, launch.WorkspaceSource, launch.Backend = true, l.verdict.ForceSource, l.verdict.Backend
	}
	// The mask is the server's decision alone (no body field sets it): asked only
	// when the mode in force is mask, which the ground gives a run whose sandbox
	// row can hide files and whose launcher reports the outcome.
	launch.maskWorkspaceSecrets = launch.Sandbox && l.ground.asksForMask()
	// The org's terminal gate reads the sandbox flag the launch will carry,
	// so it runs after the server forced it.
	if s.opts.TerminalFeatureGate != nil {
		if allowed, reason := s.opts.TerminalFeatureGate(launch.Sandbox); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return false
		}
	}
	// A run that cannot be recorded is not started: it would run with no
	// deadline, no Stop and no closing check. Asked before anything is claimed.
	var recErr error
	if l.heldStart {
		recErr = l.runs.Unreadable()
	} else {
		recErr = l.runs.CanRecord()
	}
	if s.writeSecurityAssessRecordErr(w, recErr) {
		return false
	}
	l.name = securityProjectName(l.ref)
	l.limits = securityAssessLimitsFor(l.kind, l.cfg)
	var target *secassess.Target
	if l.kind.Target == secassess.TargetRequired {
		t := l.verdict.Target
		target = &t
	}
	in := securityAssessPromptInput(l.kind, l.body.RunID, l.name, target, l.sel.promptRelax(l.relax.Policy.Scope, l.relax.Tier.Hosts), l.limits, l.cfg, l.verdict.Backend)
	l.ground.fill(&in)
	prompt, err := secassess.BuildPrompt(in)
	if err != nil {
		writeErrStatus(w, err, http.StatusInternalServerError)
		return false
	}
	// The developer launches the prompt they read: when it differs from the
	// plan, nothing starts and the new prompt is handed back.
	if want := strings.TrimSpace(l.body.PromptSHA256); want != "" && want != secassess.PromptSHA256(prompt) {
		writePlanChanged(w, prompt)
		return false
	}
	l.prompt = prompt
	l.seeded = integration.TaskSeedFor(l.body.Tool).Seeds()
	arg := ""
	if l.seeded {
		arg = prompt
	}
	// One click starts one terminal: a held run is claimed in one conditional
	// update, and the claim goes back if the terminal does not start.
	if l.heldStart {
		if _, err := l.runs.ClaimHeld(l.body.RunID); err != nil {
			http.Error(w, "that run was already started or cancelled: read the plan again", http.StatusConflict)
			return false
		}
	}
	l.launch = launch
	undo, perr := s.securityAssessPrepare(r.Context(), l)
	if perr != nil {
		undo()
		if l.heldStart {
			_ = l.runs.ReleaseClaim(l.body.RunID)
		}
		status, code, msg := securityAssessHelperRefusal(perr)
		writeSecurityAssessRefusal(w, status, "", code, msg)
		return false
	}
	resp, started := s.startFreshTerminal(w, r, launch, arg)
	if !started {
		undo()
		if l.heldStart {
			_ = l.runs.ReleaseClaim(l.body.RunID)
		}
		return false
	}
	l.launch, l.resp = launch, resp
	return true
}

// securityAssessRunBackend is the sandbox backend a run is recorded under: the one
// the launcher resolved for the box it built, else the one the verdict chose (a
// launcher that does not report it), else none. A kind with no sandbox rule (a
// threat model, whose box the person asked for in the New terminal step) has no
// verdict backend, and an Automatic choice is resolved only by the launcher, so
// the run's row would otherwise say "in a sandbox" and not which.
func securityAssessRunBackend(l *securityAssessLaunch) string {
	if !l.launch.Sandbox {
		return ""
	}
	if l.resp.backend != "" {
		return l.resp.backend
	}
	return l.verdict.Backend
}

// securityAssessLaunchRecord applies the local approvals, records the run (or
// moves the held record to started) and writes the launch audit row.
func (s *Server) securityAssessLaunchRecord(ctx context.Context, l *securityAssessLaunch) {
	body, relax := l.body, l.relax
	now := time.Now().UTC()
	reported, _ := secassess.ReportRoute(secassess.ReportInput{Tenancy: relax.Tenancy, ReportToOrg: relax.Policy.ReportToOrg})
	recs := securityAssessRelaxRecords(l.sel, relax.Policy, l.grants)
	s.securityAssessApplyLocal(ctx, l.st, recs, body.RunID, reported, body.ProjectRootHash, relax, now)
	run := secassesssvc.Run{
		ID: body.RunID, Kind: string(l.kind.ID), Tool: body.Tool, ProjectRootHash: body.ProjectRootHash, ProjectName: l.name,
		Handle: l.resp.Token, Seeded: l.seeded, Sandboxed: l.launch.Sandbox, Backend: securityAssessRunBackend(l), ConfirmedAt: now,
		Relax: recs, Reported: reported, Tenancy: string(relax.Tenancy),
		TimeBoxMinutes: l.limits.Minutes, TimeBoxAction: l.limits.Action, Audit: securityAssessInitialAudit(l.kind, l.limits),
	}
	if len(recs) > 0 {
		run.RelaxMinutes = relax.Policy.MaxMinutes
	}
	securityAssessLaunchModelFields(&run, l.kind, l.cfg)
	l.ground.record(&run)
	if l.launch.maskWorkspaceSecrets {
		m := securityAssessMaskReportOf(l.resp.secretMask)
		run.SecretMask = &m
	}
	run.HelperSHA, run.ConfigSHA = l.helper.Helper, l.helper.Config
	if l.launch.Sandbox {
		run.Tier = l.facts.Tier
		if run.Tier == "" {
			run.Tier = "internet"
		}
	}
	if l.kind.Target == secassess.TargetRequired {
		run.Target = l.verdict.Target.String()
	}
	var err error
	if l.heldStart {
		run.Phase = secassesssvc.PhaseStarted
		_, _, err = l.runs.Mutate(body.RunID, func(cur *secassesssvc.Run) error {
			run.CreatedAt, run.Held = cur.CreatedAt, cur.Held
			*cur = run
			return nil
		})
	} else {
		_, err = l.runs.Record(run, time.Now())
	}
	if err != nil && s.opts.Logger != nil {
		s.opts.Logger.Warn("security assessments: run not recorded", "error", err)
	}
	s.securityAssessAudit(ctx, reported, "launch", body.ProjectRootHash, "", securityAssessLaunchDetail(run, relax))
}

// securityAssessRunRoot resolves a recorded run and its project's folder.
func (s *Server) securityAssessRunRoot(ctx context.Context, id string) (secassesssvc.Run, string, bool, error) {
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	// An unreadable record is its own answer, not "unknown run".
	if err := runs.Unreadable(); err != nil {
		return secassesssvc.Run{}, "", false, err
	}
	run, ok := runs.Get(id)
	if !ok {
		return secassesssvc.Run{}, "", false, nil
	}
	index, err := securityProjectIndex(ctx, store.New(s.db()))
	if err != nil {
		return run, "", true, err
	}
	return run, index[run.ProjectRootHash].Root, true, nil
}

// handleSecurityAssessReport serves GET /api/security/assessments/report?run=:
// the run's report.md as plain text, read through the confined reader.
func (s *Server) handleSecurityAssessReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	run, root, found, err := s.securityAssessRunRoot(r.Context(), r.URL.Query().Get("run"))
	if err != nil {
		s.writeSecurityAssessRunErr(w, err)
		return
	}
	if !found {
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	}
	data, err := secassesssvc.ReadResult(root, secassess.ResultPaths(run.ID).Report, secassesssvc.MaxReportBytes)
	switch {
	case errors.Is(err, secassesssvc.ErrAbsent):
		http.Error(w, "the report is not there yet", http.StatusNotFound)
		return
	case errors.Is(err, secassesssvc.ErrTooLarge):
		http.Error(w, "the report is over its size cap", http.StatusRequestEntityTooLarge)
		return
	case errors.Is(err, secassesssvc.ErrNotRegular):
		http.Error(w, "the report is not a plain file", http.StatusUnprocessableEntity)
		return
	case err != nil:
		http.Error(w, "the report could not be read", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	// Recognised secrets are hidden on the way out (setting display_redaction);
	// the file in the project is as the agent wrote it. The header says how many
	// places were hidden, and is absent when hiding is off.
	if redact, _ := securityAssessRedactorOf(s.securityAssessConfig()); redact != nil {
		text := string(data)
		out := redact(text)
		hidden := strings.Count(out, redactedMarker) - strings.Count(text, redactedMarker)
		if hidden < 0 {
			hidden = 0
		}
		w.Header().Set(redactedHeader, strconv.Itoa(hidden))
		data = []byte(out)
	}
	_, _ = w.Write(data) //nolint:gosec // G705: the agent's report served as text/plain with nosniff and no-store, never rendered as HTML
}

// securityAssessSeam adapts the SARIF import seam to the service's ImportFunc:
// the tool is always "other" (an assessment's rule ids carry the tag), the
// seam's report round-trips through JSON into counts, and the seam's own
// input refusal is mapped to the service's sentinel.
func securityAssessSeam(seam *dashapi.SARIFImport) secassesssvc.ImportFunc {
	if seam == nil || seam.Import == nil {
		return nil
	}
	return func(ctx context.Context, root string, data []byte) (secassesssvc.Counts, error) {
		rep, err := seam.Import(ctx, root, "other", data)
		if err != nil {
			if errors.Is(err, dashapi.ErrSARIFImportInput) {
				return secassesssvc.Counts{}, errors.Join(secassesssvc.ErrInputRefused, err)
			}
			return secassesssvc.Counts{}, err
		}
		raw, err := json.Marshal(rep)
		if err != nil {
			return secassesssvc.Counts{}, err
		}
		var c struct {
			Findings    int            `json:"findings"`
			New         int            `json:"new"`
			WithLineage int            `json:"with_lineage"`
			Refused     map[string]int `json:"refused"`
			Truncated   bool           `json:"truncated"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return secassesssvc.Counts{}, err
		}
		return secassesssvc.Counts{Findings: c.Findings, New: c.New, WithLineage: c.WithLineage, Refused: c.Refused, Truncated: c.Truncated}, nil
	}
}

// handleSecurityAssessImport serves POST /api/security/assessments/import
// {run}: the developer's click that imports a run's findings file.
func (s *Server) handleSecurityAssessImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	var body struct {
		Run string `json:"run"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, securityAssessBodyMax)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	run, root, found, err := s.securityAssessRunRoot(ctx, body.Run)
	if err != nil {
		s.writeSecurityAssessRunErr(w, err)
		return
	}
	if !found {
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	}
	rec, err := secassesssvc.RunImport(ctx, secassesssvc.ImportInput{
		ProjectRoot: root, Run: run, Selected: s.securityAssessImportSelected(r), Seam: securityAssessSeam(s.opts.SARIFImport), Now: time.Now(),
		Side: secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath)).Side(), Derive: securityAssessDeriveSettings(s.securityAssessConfig().Security.Assessments),
	})
	if err != nil {
		switch {
		case errors.Is(err, secassesssvc.ErrNoFindingsFile):
			http.Error(w, "the run has no findings file to import yet", http.StatusConflict)
		case errors.Is(err, secassesssvc.ErrNotValidated):
			writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "check the model first: the import takes the findings Observer derives from a checked model, and this run's model has not been checked, or has changed since", "code": codeNotValidated})
		default:
			writeErrStatus(w, err, http.StatusInternalServerError)
		}
		return
	}
	if err := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath)).SetImport(run.ID, rec); err != nil && s.opts.Logger != nil {
		s.opts.Logger.Warn("security assessments: import outcome not recorded", "error", err)
	}
	run.Import = &rec
	s.securityAssessAudit(ctx, run.Reported, "import", run.ProjectRootHash, "", securityAssessImportDetail(run.ID, rec))
	writeJSON(w, map[string]any{"run": s.securityAssessRunViewFull(ctx, run, root)})
}
