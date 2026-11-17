//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_assess_org.go is the managed-node half of the relaxations addendum
// (plan section 13.6): asking the organization for a rule's exemption, the
// held run that waits for it, reading the node's verified grant cache for the
// answer, and cancelling. Every statement about a grant is the access-grant
// package's own (Validate, AlreadyGranted) reached through the Requests seam;
// no grant is created, extended or read here by any other route.

// securityAssessRequestBody is POST /api/security/assessments/request.
type securityAssessRequestBody struct {
	Assessment      string   `json:"assessment"`
	ProjectRootHash string   `json:"project_root_hash"`
	RunID           string   `json:"run_id"`
	Target          string   `json:"target"`
	Relaxations     []string `json:"relaxations"`
	// Start is the start command chosen on the plan ("none" declares none, ""
	// takes the plan's default); the held run keeps the command it resolves to,
	// so the run that starts later is the run the organization approved.
	Start string `json:"start"`
	// Prepare says the developer ticked the selected plan's preparation steps (the
	// default is off); the held run keeps it too.
	Prepare bool `json:"prepare"`
	// Objective is a red team run's own objective, kept on the held run like the
	// start command (a retest has no relaxation to hold: nothing_to_request). OfRun
	// and FindingIDs are carried for the same reason, so a kind that could be held
	// never loses its choices.
	Objective  string   `json:"objective"`
	OfRun      string   `json:"of_run"`
	FindingIDs []string `json:"finding_ids"`
}

// securityAssessAsk is one rule's exemption request, prepared and validated
// exactly the way POST /api/requests prepares one.
type securityAssessAsk struct {
	Prepared orgcontract.AccessRequestCreate
	Norm     accessgrant.Normalized
	Problems []accessgrant.Problem
}

// securityAssessAskFor prepares the exemption request for one rule in one
// project on the tool lane: rule-wide, exempt, this machine, for seconds.
func securityAssessAskFor(ctx context.Context, svc dashapi.RequestService, message, rule, projectHash string, seconds int64) (securityAssessAsk, error) {
	prepared, err := svc.PrepareAccessRequest(ctx, orgcontract.AccessRequestCreate{
		RequestType: accessgrant.TypeGuardExemption, Message: message, RequestedDurationS: seconds,
		Payload: &orgcontract.AccessRequestPayload{
			RuleID: rule, Lane: accessgrant.LaneTool, Breadth: accessgrant.BreadthRule,
			Effect: orgcontract.AccessGrantEffectExempt, ProjectRootHash: projectHash,
		},
	}, false)
	if err != nil {
		return securityAssessAsk{}, err
	}
	payload := orgcontract.AccessRequestPayload{}
	if prepared.Payload != nil {
		payload = *prepared.Payload
	}
	norm, problems := accessgrant.Validate(accessgrant.Request{
		Type: prepared.RequestType, Payload: payload, DurationS: prepared.RequestedDurationS, Uses: prepared.RequestedUses,
		SubjectKind: prepared.SubjectKind, Machine: prepared.MachineIdentity, Justification: prepared.Message,
	}, accessgrant.DefaultSettings())
	return securityAssessAsk{Prepared: prepared, Norm: norm, Problems: problems}, nil
}

// securityAssessCovered reports the grant in force that already gives the
// exemption on this project for at least window.
func securityAssessCovered(ctx context.Context, svc dashapi.RequestService, rule, projectHash string, window time.Duration) (accessgrant.Held, bool) {
	if svc == nil {
		return accessgrant.Held{}, false
	}
	ask, err := securityAssessAskFor(ctx, svc, "check", rule, projectHash, int64(window/time.Second))
	if err != nil || len(ask.Problems) > 0 {
		return accessgrant.Held{}, false
	}
	return svc.AlreadyGranted(ctx, ask.Norm)
}

// securityAssessJustification is the request's message: the kind, the run and
// the project, in words the approver can read.
func securityAssessJustification(kindTitle, runID, project, rule string, minutes int) string {
	return fmt.Sprintf("Security assessment %q (run %s) in the project %q needs guard rule %s lifted for this project on the tool lane while it runs, for up to %d minutes. It was started by the developer on this machine and its terminal runs in a sandbox with Observer's other rules in force.", kindTitle, runID, project, rule, minutes)
}

// securityAssessRefusal is a refusal the caller writes as is.
type securityAssessRefusal struct {
	Status int
	Rule   string
	Code   string
	Reason string
}

func (s *securityAssessRefusal) write(w http.ResponseWriter) {
	writeSecurityAssessRefusal(w, s.Status, s.Rule, s.Code, s.Reason)
}

// codeRelaxNotGranted is the refusal of a launch whose org-approved rule has
// no grant in force.
const codeRelaxNotGranted = "relaxation_not_granted"

// securityAssessOrgGrants resolves the grant in force for every ticked
// org-approved row, or says which row has none. The map is by rule id.
func (s *Server) securityAssessOrgGrants(ctx context.Context, rows []secassess.PlanRow, projectHash string) (map[string]accessgrant.Held, *securityAssessRefusal) {
	out := map[string]accessgrant.Held{}
	for _, row := range rows {
		h, ok := securityAssessCovered(ctx, s.opts.Requests, row.Key, projectHash, secassess.MinGrantWindow)
		if !ok {
			return nil, &securityAssessRefusal{
				Status: http.StatusConflict, Rule: row.Row, Code: codeRelaxNotGranted,
				Reason: "Your organization has not approved " + row.Key + " for this project yet (or the grant ends too soon). Ask your organization first, then start the run once it is approved.",
			}
		}
		out[row.Key] = h
	}
	return out, nil
}

// securityAssessMinutes is the window an org request asks for.
func securityAssessMinutes(p secassess.Policy) int { return p.MaxMinutes }

// handleSecurityAssessRequest serves POST /api/security/assessments/request:
// files one exemption request per org-approved rule the developer ticked and
// records a held run that waits for the grants. It starts nothing.
func (s *Server) handleSecurityAssessRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	svc := s.opts.Requests
	if svc == nil {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "requests go to an organization; this node is not enrolled", "code": "not_enrolled"})
		return
	}
	var body securityAssessRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, securityAssessBodyMax)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	kind, ok := secassess.KindByID(body.Assessment)
	if !ok {
		http.Error(w, "unknown assessment kind", http.StatusBadRequest)
		return
	}
	if !kind.Launchable {
		writeSecurityAssessRefusal(w, http.StatusConflict, "E1", secassess.CodeNotLaunchable, kind.Reason)
		return
	}
	if !secassess.ValidRunID(body.RunID) {
		http.Error(w, "bad run id: read the plan again", http.StatusBadRequest)
		return
	}
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	if runs.Exists(body.RunID) {
		http.Error(w, "that run was already recorded: read the plan again", http.StatusConflict)
		return
	}
	ctx := r.Context()
	index, err := securityProjectIndex(ctx, store.New(s.db()))
	if err != nil {
		writeErrStatus(w, err, http.StatusInternalServerError)
		return
	}
	ref, known := index[body.ProjectRootHash]
	if !known {
		http.Error(w, "unknown project", http.StatusNotFound)
		return
	}
	av, probed := s.securityAssessProbe(ctx)
	facts := s.securityAssessFacts(av, probed, ref.Root, "")
	req := secassess.Request{Kind: kind.ID, Sandbox: true, Plan: true}
	if kind.Target == secassess.TargetRequired {
		req.Target = strings.TrimSpace(body.Target)
		if req.Target == "" {
			http.Error(w, "choose the target first", http.StatusBadRequest)
			return
		}
	}
	verdict := secassess.Eligible(kind.ID, facts, req)
	if kind.Sandbox == secassess.SandboxRequired {
		securityAssessNeedsATool(&verdict, s.securityAssessAllowedTools(av, probed, ref.Root), probed)
	}
	if !verdict.OK {
		writeSecurityAssessRefusal(w, http.StatusConflict, verdict.Rule, verdict.Code, verdict.Reason)
		return
	}
	plan := s.securityAssessRelaxFacts(ctx, kind.ID, ref.Root, av)
	sel, serr := securityAssessSelect(plan.Rows, body.Relaxations, false)
	if serr != nil {
		writeSecurityAssessRefusal(w, serr.Status, serr.Rule, serr.Code, serr.Reason)
		return
	}
	org := sel.orgRules()
	if len(org) == 0 {
		writeSecurityAssessRefusal(w, http.StatusBadRequest, "", "nothing_to_request", "Nothing ticked needs your organization's approval: start the run instead.")
		return
	}
	// The start command and the environment-files setting are decided now, so a
	// held run neither waits on a command that cannot be used nor files requests
	// for a run the setting would refuse.
	ground := s.securityAssessGround(ctx, store.New(s.db()), securityAssessGroundIn{
		Kind: kind, Root: ref.Root, Hash: body.ProjectRootHash, RunID: body.RunID,
		Choices: securityAssessChoices{
			Start: strings.TrimSpace(body.Start), Prepare: body.Prepare,
			Objective: body.Objective, RetestOf: strings.TrimSpace(body.OfRun), RetestFindings: body.FindingIDs,
		},
		TargetPort: verdict.Target.PortNumber(),
		Cfg:        s.securityAssessConfig().Security.Assessments, Tier: facts.Tier,
	})
	if code, reason := ground.refusal(true); code != "" {
		writeSecurityAssessRefusal(w, http.StatusConflict, "", code, reason)
		return
	}
	// Nothing is filed with the organization for a run that cannot be recorded.
	if s.writeSecurityAssessRecordErr(w, runs.CanRecord()) {
		return
	}
	name := securityProjectName(ref)
	held, refusal := s.securityAssessFileRequests(ctx, svc, kind, body.RunID, name, body.ProjectRootHash, org, plan.Policy)
	if refusal != nil {
		refusal.write(w)
		return
	}
	reported, _ := secassess.ReportRoute(secassess.ReportInput{Tenancy: plan.Tenancy, ReportToOrg: plan.Policy.ReportToOrg})
	run := secassesssvc.Run{
		ID: body.RunID, Kind: string(kind.ID), ProjectRootHash: body.ProjectRootHash, ProjectName: name,
		Phase: secassesssvc.PhaseHeld, Held: held, Relax: securityAssessRelaxRecords(sel, plan.Policy, nil),
		RelaxMinutes: securityAssessMinutes(plan.Policy), Reported: reported, Tenancy: string(plan.Tenancy),
	}
	if kind.Target == secassess.TargetRequired {
		run.Target = verdict.Target.String()
	}
	if kind.Probing {
		run.Start, run.Prepare = ground.start.Choice, ground.prepare
		if run.Start == securityAssessNone {
			run.Start = ""
		}
	}
	if kind.Exercise {
		run.Objective = ground.objective
	}
	if kind.Retest && ground.retest.usable() {
		run.RetestOf, run.RetestFindings = ground.retest.basis.Of, ground.retest.basis.IDs()
	}
	rec, err := runs.Record(run, time.Now())
	if err != nil {
		securityAssessUndoRequests(ctx, svc, held)
		s.writeSecurityAssessRunErr(w, err)
		return
	}
	s.securityAssessAudit(ctx, reported, "held", body.ProjectRootHash, "", securityAssessHeldDetail(rec))
	status := http.StatusCreated
	if anyQueued(held) {
		status = http.StatusAccepted
	}
	writeJSONStatus(w, status, map[string]any{"run": s.securityAssessRunViewFull(ctx, rec, ref.Root)})
}

func anyQueued(h *secassesssvc.Held) bool {
	for _, q := range h.QueuedIDs {
		if q != 0 {
			return true
		}
	}
	return false
}

// securityAssessFileRequests files the requests for the ticked org rows. A
// rule a grant already covers files nothing. A failure after an earlier
// request went out takes that request back, so no half-filed set is left.
func (s *Server) securityAssessFileRequests(ctx context.Context, svc dashapi.RequestService, kind secassess.Kind, runID, project, projectHash string, org []secassess.PlanRow, pol secassess.Policy) (*secassesssvc.Held, *securityAssessRefusal) {
	held := &secassesssvc.Held{At: time.Now().UTC()}
	for _, row := range org {
		held.Rules = append(held.Rules, row.Key)
		held.RequestIDs = append(held.RequestIDs, 0)
		held.QueuedIDs = append(held.QueuedIDs, 0)
	}
	fail := func(ref *securityAssessRefusal) (*secassesssvc.Held, *securityAssessRefusal) {
		securityAssessUndoRequests(ctx, svc, held)
		return nil, ref
	}
	for i, row := range org {
		if _, ok := securityAssessCovered(ctx, svc, row.Key, projectHash, secassess.MinGrantWindow); ok {
			held.Covered = append(held.Covered, row.Key)
			continue
		}
		ask, err := securityAssessAskFor(ctx, svc, securityAssessJustification(kind.Title, runID, project, row.Key, securityAssessMinutes(pol)), row.Key, projectHash, int64(securityAssessMinutes(pol))*60)
		switch {
		case errors.Is(err, orgclient.ErrNotEnrolled):
			return fail(&securityAssessRefusal{Status: http.StatusConflict, Code: "not_enrolled", Reason: "requests go to an organization; this node is not enrolled"})
		case err != nil:
			return fail(&securityAssessRefusal{Status: http.StatusBadRequest, Code: "bad_request", Reason: err.Error()})
		}
		if covered := securityAssessProblemsCovered(ask.Problems); covered {
			held.Covered = append(held.Covered, row.Key)
			continue
		}
		if len(ask.Problems) > 0 {
			return fail(&securityAssessRefusal{Status: http.StatusBadRequest, Rule: row.Row, Code: "bad_request", Reason: accessgrant.Error(ask.Problems)})
		}
		got, queued, err := svc.SendOrQueueAccessRequest(ctx, ask.Prepared)
		var refused *orgclient.RequestRefusedError
		switch {
		case errors.As(err, &refused):
			return fail(&securityAssessRefusal{Status: http.StatusBadRequest, Rule: row.Row, Code: "refused", Reason: refused.Error()})
		case errors.Is(err, orgclient.ErrOrgRequestCapReached):
			return fail(&securityAssessRefusal{Status: http.StatusTooManyRequests, Code: "too_many_open", Reason: "you already have the maximum number of open requests to this organization"})
		case errors.Is(err, store.ErrOutboxFull):
			return fail(&securityAssessRefusal{Status: http.StatusTooManyRequests, Code: "outbox_full", Reason: "the organization is unreachable and the queue of unsent requests is full"})
		case err != nil:
			return fail(&securityAssessRefusal{Status: http.StatusBadGateway, Code: "send_failed", Reason: err.Error()})
		}
		held.RequestIDs[i], held.QueuedIDs[i] = got.ID, queued
	}
	return held, nil
}

// securityAssessProblemsCovered says the request's only problem is that a
// grant already covers it.
func securityAssessProblemsCovered(ps []accessgrant.Problem) bool {
	for _, p := range ps {
		if p.Code == accessgrant.CodeAlreadyGranted {
			return true
		}
	}
	return false
}

// securityAssessUndoRequests takes back every request a held run filed:
// withdraws the sent ones and cancels the queued ones. Best effort.
func securityAssessUndoRequests(ctx context.Context, svc dashapi.RequestService, h *secassesssvc.Held) {
	if h == nil || svc == nil {
		return
	}
	for _, id := range h.RequestIDs {
		if id != 0 {
			_ = svc.WithdrawOrgRequest(ctx, id)
		}
	}
	for _, id := range h.QueuedIDs {
		if id != 0 {
			_, _ = svc.CancelQueuedAccessRequest(ctx, id)
		}
	}
}

// securityAssessHeldDetail is the content-free line of the `held` audit row.
func securityAssessHeldDetail(r secassesssvc.Run) string {
	var b strings.Builder
	b.WriteString("run " + r.ID + " kind " + r.Kind)
	if r.Held != nil {
		for i, rule := range r.Held.Rules {
			b.WriteString("; " + rule + " org_request")
			if i < len(r.Held.RequestIDs) && r.Held.RequestIDs[i] != 0 {
				fmt.Fprintf(&b, " request %d", r.Held.RequestIDs[i])
			}
			if i < len(r.Held.QueuedIDs) && r.Held.QueuedIDs[i] != 0 {
				b.WriteString(" queued")
			}
		}
		for _, c := range r.Held.Covered {
			b.WriteString("; " + c + " already covered")
		}
	}
	return b.String()
}

// securityAssessRelaxRecords turns a selection into the run's relaxation
// records. grants are the org grants in force (by rule id) when the run starts;
// nil for a held run that has not started.
func securityAssessRelaxRecords(sel securityAssessSelection, pol secassess.Policy, grants map[string]accessgrant.Held) []secassesssvc.Relax {
	out := make([]secassesssvc.Relax, 0, len(sel.Rows))
	for _, r := range sel.Rows {
		x := secassesssvc.Relax{Key: r.Key, Type: string(r.Type), Route: string(r.Route)}
		switch {
		case r.Type == secassess.RelaxTier:
			x.State = string(secassess.RelaxTierOn)
		case r.Route == secassess.RouteOrgRequest:
			x.Scope = secassess.ScopeOrg
			if g, ok := grants[r.Key]; ok {
				x.State, x.GrantID = string(secassess.RelaxOrgGrant), g.ID
			}
		default:
			x.Scope = pol.Scope
		}
		out = append(out, x)
	}
	return out
}

// handleSecurityAssessCancel serves POST /api/security/assessments/cancel
// {run}: withdraws a held run's requests and marks it cancelled.
func (s *Server) handleSecurityAssessCancel(w http.ResponseWriter, r *http.Request) {
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
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	var cancelled secassesssvc.Run
	run, found, err := runs.Mutate(body.Run, func(x *secassesssvc.Run) error {
		if x.Phase != secassesssvc.PhaseHeld {
			return secassesssvc.ErrNotHeld
		}
		x.Phase, x.EndedAt = secassesssvc.PhaseCancelled, time.Now().UTC()
		cancelled = *x
		return nil
	})
	// The error before the found flag: an unreadable record reports found=false
	// with an error, and that is the record's own 409, not an unknown run.
	switch {
	case errors.Is(err, secassesssvc.ErrNotHeld):
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "the run is not waiting for your organization", "code": "not_held"})
		return
	case err != nil:
		s.writeSecurityAssessRunErr(w, err)
		return
	case !found:
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	}
	ctx := r.Context()
	securityAssessUndoRequests(ctx, s.opts.Requests, cancelled.Held)
	s.securityAssessAudit(ctx, run.Reported, "cancel", run.ProjectRootHash, "", "run "+run.ID+" kind "+run.Kind+"; requests withdrawn")
	root := ""
	if index, err := securityProjectIndex(ctx, store.New(s.db())); err == nil {
		root = index[run.ProjectRootHash].Root
	}
	writeJSON(w, map[string]any{"run": s.securityAssessRunViewFull(ctx, run, root)})
}

// The held rule states.
const (
	heldWaiting  = "waiting"
	heldApproved = "approved"
	heldNarrower = "narrower"
	heldDeclined = "declined"
	heldLapsed   = "lapsed"
	heldQueued   = "queued"
)

type securityAssessHeldRuleJS struct {
	Rule string `json:"rule"`
	// State is waiting, approved, narrower, declined, lapsed or queued.
	State     string `json:"state"`
	GrantID   int64  `json:"grant_id,omitempty"`
	RequestID int64  `json:"request_id,omitempty"`
	Why       string `json:"why,omitempty"`
}

type securityAssessHeldJS struct {
	At time.Time `json:"at"`
	// Ready: every rule has a grant in force that covers the run.
	Ready bool                       `json:"ready"`
	Rules []securityAssessHeldRuleJS `json:"rules"`
}

// securityAssessMyRequests reads the node's own requests, cached for a short
// while so a polling list does not call the organization on every poll.
var securityAssessMyRequests struct {
	mu   sync.Mutex
	at   time.Time
	list []orgclient.OrgRequest
}

const securityAssessRequestsTTL = 30 * time.Second

func securityAssessOwnRequests(ctx context.Context, svc dashapi.RequestService) []orgclient.OrgRequest {
	c := &securityAssessMyRequests
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) < securityAssessRequestsTTL {
		return c.list
	}
	list, err := svc.ListMyOrgRequests(ctx)
	if err != nil {
		return c.list
	}
	c.at, c.list = time.Now(), list
	return list
}

// securityAssessHeld derives a held run's state live from the node's verified
// grant cache (and, for a declined answer, the org's own list of the member's
// requests).
func (s *Server) securityAssessHeld(ctx context.Context, run secassesssvc.Run) *securityAssessHeldJS {
	if run.Held == nil {
		return nil
	}
	svc := s.opts.Requests
	out := &securityAssessHeldJS{At: run.Held.At, Ready: len(run.Held.Rules) > 0, Rules: []securityAssessHeldRuleJS{}}
	var facts []secassess.GrantFact
	factsRead := false
	now := time.Now()
	for i, rule := range run.Held.Rules {
		row := securityAssessHeldRuleJS{Rule: rule, State: heldWaiting}
		if i < len(run.Held.RequestIDs) {
			row.RequestID = run.Held.RequestIDs[i]
		}
		queued := i < len(run.Held.QueuedIDs) && run.Held.QueuedIDs[i] != 0
		if h, ok := securityAssessCovered(ctx, svc, rule, run.ProjectRootHash, secassess.MinGrantWindow); ok {
			row.State, row.GrantID = heldApproved, h.ID
			out.Rules = append(out.Rules, row)
			continue
		}
		out.Ready = false
		if svc != nil && !factsRead {
			facts, factsRead = securityAssessGrantFacts(ctx, svc), true
		}
		if n, ok := secassess.FindNarrower(rule, run.ProjectRootHash, now.UnixNano(), int64(secassess.MinGrantWindow), facts); ok {
			row.State, row.GrantID, row.Why = heldNarrower, n.ID, n.Why
			out.Rules = append(out.Rules, row)
			continue
		}
		switch {
		case queued && row.RequestID == 0:
			row.State = heldQueued
		case row.RequestID != 0 && svc != nil:
			for _, q := range securityAssessOwnRequests(ctx, svc) {
				if q.ID != row.RequestID {
					continue
				}
				switch q.Status {
				case "declined", "withdrawn":
					row.State = heldDeclined
					row.Why = strings.TrimSpace(q.ResolutionNote)
				case "lapsed":
					row.State = heldLapsed
				}
			}
		}
		out.Rules = append(out.Rules, row)
	}
	return out
}

// securityAssessGrantFacts reads the honoured grants of the node's verified
// cache as the pure narrowing explanation reads them.
func securityAssessGrantFacts(ctx context.Context, svc dashapi.RequestService) []secassess.GrantFact {
	view, ok, err := svc.AccessGrantsView(ctx)
	if err != nil || !ok || view.Unverified {
		return nil
	}
	out := make([]secassess.GrantFact, 0, len(view.Grants))
	for _, g := range view.Grants {
		out = append(out, secassess.GrantFact{
			ID: g.Grant.ID, Type: g.Grant.Type, Effect: g.Grant.Effect, RuleID: g.Grant.RuleID, Lane: g.Grant.Lane,
			CommandClass: g.Grant.CommandClass, OperandHash: g.Grant.OperandHash, ProjectRootHash: g.Grant.ProjectRootHash,
			MaxUses: g.Grant.MaxUses, ExpiresAtNs: g.Grant.ExpiresAtNs, Honoured: g.Honoured,
		})
	}
	return out
}
