package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	policyfamadmission "github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/policyfam/planebadmission"
	"github.com/marmutapp/superbased-observer/internal/promptjudgeipc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// planeb_admission_hookask.go is the HOOK-PROCESS half of the hook lane of
// the organization's prompt judge (P-228 phase 2, lane adm-2). A prompt-gate
// hook of ANY tool asks the daemon, which judges through the one node lane
// (planeb_admission_hookserve.go). Which hooks ask is decided by the
// integration registry: only an invocation whose resolved binding is the
// prompt-gate capability (integration.HookCapPromptGate) asks, never a branch
// on a tool name.
//
// When it asks: only while the daemon's signed guard posture says the judge
// is active here (PromptJudgeActive), so an individual node never dials. A
// posture that is missing, unverifiable or stale (the daemon is down) is
// replaced by the same answer derived from durable state (the grant, the
// config's accepted families and the signature-verified cached
// planeb.admission body), so stopping the daemon does not switch a strict
// judge off.
//
// Latency budget: the ask waits at most min(12 s, the host's hook timeout
// minus 3 s); a host with no known timeout gets 12 s (the node lane's 10 s
// relay default plus the hop). The hook's own watchdog is capped at the host
// timeout minus 2 s (hookGateBudget), so the ask always ends first.
//
// Failure: a daemon that is down, slow or wrong follows the policy's strict
// flag as the posture signs it (PromptJudgeFailClosed: strict and enforced):
// the prompt is refused with a reason, else it goes through. Either way one
// spool record (guardposture.KindPromptJudge) reaches the daemon's drain and
// guard_events, the docs/guard.md "Hook failure semantics" path.

// orgPromptJudge is the hook's org prompt judge: hook.OrgPromptJudge over
// the daemon's owner-only ask channel.
type orgPromptJudge struct {
	configPath string
	cfg        config.Config
}

// newOrgPromptJudge is the judge for a prompt gate whose local guard is not
// evaluating (hook.HandlePromptSubmitOrgJudge): the org judge runs whatever
// the local guard switches say (adm-2 fixes-1, H3).
func newOrgPromptJudge(configPath string, cfg config.Config) *orgPromptJudge {
	return &orgPromptJudge{configPath: configPath, cfg: cfg}
}

// JudgeOrgPrompt implements hook.OrgPromptJudge.
func (j *orgPromptJudge) JudgeOrgPrompt(q hook.OrgPromptQuery) hook.OrgPromptJudgement {
	return hookOrgPromptJudge(currentHookPlan(), q, productionPromptJudgeDeps(j.configPath, j.cfg, os.Stderr))
}

// judgeOnlyUndecodableRefused is the FU-161 rule on the judge-only path
// (adm-2 fixes-2, N3): a prompt payload the dialect cannot decode (invalid
// JSON, or valid JSON of the wrong shape) was not judged, so it refuses
// wherever this invocation's failure plan already fails closed (a strict
// enforced org judge, M2, or guard enforcement), exactly as on the guarded
// path. Where the plan is open (every individual node) nothing changes and
// nothing new is recorded. A payload cut at the read bound is not this case:
// the judge was asked about it as Partial.
func judgeOnlyUndecodableRefused(dialect string, body []byte, truncated bool) bool {
	return !truncated && hookPlanFailsClosed() && hook.PromptPayloadUndecodable(dialect, body) &&
		hookFailClosed(guardposture.KindUnparseable, body)
}

// orgJudgedEvaluator is the hook's guard with the OrgPromptJudge capability.
// Embedding *guard.Guard keeps every evaluator interface the prompt and
// Cursor paths need.
type orgJudgedEvaluator struct {
	*guard.Guard
	*orgPromptJudge
}

// withOrgPromptJudge wraps the hook's guard with the org prompt judge.
func withOrgPromptJudge(g *guard.Guard, configPath string, cfg config.Config) *orgJudgedEvaluator {
	return &orgJudgedEvaluator{Guard: g, orgPromptJudge: newOrgPromptJudge(configPath, cfg)}
}

// promptJudgeDeps is the hook judge's I/O, injected for tests.
type promptJudgeDeps struct {
	// posture reports whether the judge is active here and whether a
	// failure to get its answer must refuse.
	posture func() (active, failClosed bool)
	// ask asks the daemon.
	ask func(ctx context.Context, req promptjudgeipc.Request) (promptjudgeipc.Answer, error)
	// spool records a judge the hook could not reach.
	spool func(plan hookFailurePlan, sessionID, outcome string)
}

// promptJudgeRefusedPrefix leads every refusal the developer reads.
const promptJudgeRefusedPrefix = "Prompt refused by your organization's coding-agent admission policy: "

// promptJudgeUnreachableReason is the refusal when a strict, enforced policy's
// judge could not answer.
const promptJudgeUnreachableReason = "Your organization's prompt judge could not answer, and its strict policy refuses a prompt it cannot judge. Try again shortly; `observer guard status` shows the judge's state."

// hookOrgPromptJudge is the hook judge's decision, one row per outcome.
func hookOrgPromptJudge(plan hookFailurePlan, q hook.OrgPromptQuery, d promptJudgeDeps) hook.OrgPromptJudgement {
	if plan.Cap != integration.HookCapPromptGate {
		// Capability-driven: only a prompt-gate binding asks.
		return hook.OrgPromptJudgement{}
	}
	active, failClosed := d.posture()
	if !active {
		return hook.OrgPromptJudgement{}
	}
	budget := promptJudgeAskBudget(plan, time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	ans, err := d.ask(ctx, promptjudgeipc.Request{Tool: q.Tool, SessionID: q.SessionID, Prompt: q.Prompt, Oversize: q.Partial, Budget: budget})
	switch {
	case err != nil && failClosed:
		d.spool(plan, q.SessionID, guardposture.OutcomeFailClosed)
		return hook.OrgPromptJudgement{Block: true, Reason: promptJudgeUnreachableReason}
	case err != nil:
		d.spool(plan, q.SessionID, guardposture.OutcomeFailOpen)
		return hook.OrgPromptJudgement{}
	case ans.Block():
		return hook.OrgPromptJudgement{Block: true, Reason: promptJudgeRefusedPrefix + ans.Reason}
	default:
		// allow, flag (the daemon audited it) or inactive (the policy
		// changed since the posture was signed).
		return hook.OrgPromptJudgement{}
	}
}

// promptJudgeReplyMargin is what the ask leaves on the hook's watchdog for
// the reply and the spool record.
const promptJudgeReplyMargin = time.Second

// promptJudgeAskBudget is the ask's wait (adm-2 fixes-1, M2): what is left on
// THIS invocation's watchdog (plan.Deadline, which already counts the time
// spent reading the payload and settling the plan) minus a reply margin, at
// most promptjudgeipc.MaxBudget, so the ask always ends before the watchdog
// fires. With no watchdog armed (disabled) it falls back to the host's hook
// timeout minus 3 s.
func promptJudgeAskBudget(plan hookFailurePlan, now time.Time) time.Duration {
	b := promptjudgeipc.MaxBudget
	if !plan.Deadline.IsZero() {
		left := plan.Deadline.Sub(now)
		c := left - promptJudgeReplyMargin
		if c <= 0 {
			c = left / 2
		}
		if c <= 0 {
			// Exhausted: the ask fails at once and the watchdog answers.
			c = time.Millisecond
		}
		if c < b {
			b = c
		}
		return b
	}
	if plan.HostTimeout <= 0 {
		return b
	}
	if c := plan.HostTimeout - 3*time.Second; c < b {
		b = c
	}
	if b <= 0 {
		b = plan.HostTimeout / 3
	}
	return b
}

// productionPromptJudgeDeps wires the hook judge to the real posture, the
// owner-only ask channel and the hook failure spool. cfg is the hook's
// already-loaded config.
func productionPromptJudgeDeps(configPath string, cfg config.Config, stderr io.Writer) promptJudgeDeps {
	return promptJudgeDeps{
		posture: func() (bool, bool) { return hookPromptJudgePosture(configPath, cfg) },
		ask: func(ctx context.Context, req promptjudgeipc.Request) (promptjudgeipc.Answer, error) {
			ep, err := promptjudgeipc.Endpoint(cfg.Observer.DBPath)
			if err != nil {
				return promptjudgeipc.Answer{}, err
			}
			return promptjudgeipc.Ask(ctx, ep, req)
		},
		spool: func(plan hookFailurePlan, sessionID, outcome string) {
			appendHookFailure(plan, guardposture.KindPromptJudge, sessionID, outcome, stderr)
		},
	}
}

// hookPromptJudgePosture reads the judge's state from the daemon's signed,
// fresh guard posture, and derives it from durable state when the posture
// cannot be trusted (missing, tampered or stale). The derivation starts with
// a cheap local check (no database), so a node with no planeb.admission
// body cached (every individual node) never opens the database here (adm-2
// fixes-1, L1).
func hookPromptJudgePosture(configPath string, cfg config.Config) (active, failClosed bool) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return false, false
	}
	ld := guardposture.Load(guardposture.PosturePath(resolved), guardposture.KeyPath(resolved))
	if ld.State == guardposture.StateValid && ld.Posture.Stale(time.Now(), fileModTime(resolved)) == "" {
		return ld.Posture.PromptJudgeActive, ld.Posture.PromptJudgeFailClosed
	}
	if !planeBJudgeMayApply(cfg) {
		return false, false
	}
	return hookPromptJudgeFallbackFn(cfg)
}

// hookPromptJudgeFallbackFn is the database derivation's seam (tests count
// its calls).
var hookPromptJudgeFallbackFn = hookPromptJudgeFallback

// planeBJudgeMayApply is the fallback's cheap local check: planeb.admission
// is an accepted family and a cached body for it exists for some enrolment.
// It reads only the config already in hand and one directory listing.
func planeBJudgeMayApply(cfg config.Config) bool {
	if !containsString(policyfam.FamilyPlaneBAdmission, cfg.OrgClient.Policy.AcceptedFamilies()) {
		return false
	}
	matches, err := filepath.Glob(filepath.Join(policyResourceCacheDir(cfg), "*", "*", policyfam.FamilyPlaneBAdmission+".json"))
	return err == nil && len(matches) > 0
}

// hookPromptJudgeFallback derives the judge's state with no daemon: the
// grant, the accepted and preauthorized families, and the signature-verified
// cached planeb.admission body (the same facts `observer guard status`
// reads). Any read failure answers inactive.
func hookPromptJudgeFallback(cfg config.Config) (active, failClosed bool) {
	if _, statErr := os.Stat(cfg.Observer.DBPath); statErr != nil {
		return false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return false, false
	}
	defer func() { _ = database.Close() }()
	return promptJudgeStateFromFacts(loadPlaneBStatusFacts(ctx, cfg, store.New(database), time.Now()))
}

// promptJudgeStateFromFacts is the fallback's rule, the same gate the daemon's
// lane applies (planeBNodeLane.gate / hookPosture).
func promptJudgeStateFromFacts(f planeBStatusFacts) (active, failClosed bool) {
	active = f.Managed && f.HoldsEnforce && f.Accepted && f.HavePolicy && f.Spec.NodeLane &&
		f.Spec.Admission.Mode != policyfamadmission.ModeOff
	return active, active && f.Spec.Admission.Strict && planebadmission.Enforces(f.Spec) && f.Preauthorized
}
