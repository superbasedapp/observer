//go:build !sbo_omit_security

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/gitalias"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secipc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrules"
)

// hook_security.go wires the security pillar's host providers into the
// hook context seam (roadmap F0-3; security pillar plan sections 4.7 item
// 2 and 4.8): the signed posture sidecar reader (Sidecar), the dirty
// marker raise (Dirty) and the quick-scan request over the owner-only
// local IPC (QuickScan). Every provider first reads the module's state
// from the signed guard posture: while the module is not active they read
// and write nothing.

// Provider limits: a provider that overruns degrades its fact to unknown
// (Fill records an Issue); the measured costs are far below them (JSP-2:
// a 2 KiB posture reads, verifies and decodes in 0.26 ms p99).
const (
	hookSecurityReadLimit  = 250 * time.Millisecond
	hookSecurityDirtyLimit = 100 * time.Millisecond
)

// hookSecurity is one hook invocation's security state: the layout, the
// module signal and the signed active pack set, read once.
type hookSecurity struct {
	once   sync.Once
	config string
	layout secposture.Layout
	module secposture.ModuleSignal
	// packs is the node's active pack set as the signed guard posture
	// carries it (guardposture.Posture.SecurityPacks), used whenever the
	// project's own posture file cannot be (lane SEC-GATEFIX).
	packs []string
	// daemonStopped: the signed guard posture says the module is active
	// but is past its freshness window, so the daemon is not refreshing it
	// (`observer stop`, a crash, a suspended machine). The commit gate's
	// verdict then says so (policy.Security.DaemonStopped; lane sec-gate2).
	daemonStopped bool
	// floorHeld: the signed guard posture says this managed node holds a
	// commit gate floor (guardposture.Posture.CommitGateFloorHeld, audit
	// SEC-P4 F2). Whenever a project's own posture file cannot answer for
	// the floor, the floor reads as in force (fail closed), never as none.
	floorHeld bool

	// noScan records the projects whose current, verified posture file
	// says the daemon's quick-scan service is not serving
	// (File.QuickScanAvailable false): the hook does not ask it there.
	mu     sync.Mutex
	noScan map[string]bool
	// budget records, per project, the quick-scan budget its current,
	// verified posture file signs ([security.scanning] quick_scan_budget_s
	// raised by an org floor, lane LEFT-SEC); a project with none asks
	// with the built-in IndividualQuickScan.
	budget map[string]time.Duration
}

// quickScanBudget is the budget the last reading for root signed.
func (s *hookSecurity) quickScanBudget(root string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.budget[root]; ok {
		return b
	}
	return secposture.IndividualQuickScan
}

// noteQuickScan records what a reading says about the quick-scan service
// for root: only a current, verified file is believed.
func (s *hookSecurity) noteQuickScan(root string, r secposture.Reading) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.File == nil || r.State.Posture == policy.SecurityPostureUnknown {
		delete(s.noScan, root)
		delete(s.budget, root)
		return
	}
	if s.noScan == nil {
		s.noScan = map[string]bool{}
	}
	s.noScan[root] = !r.File.QuickScanAvailable
	if s.budget == nil {
		s.budget = map[string]time.Duration{}
	}
	s.budget[root] = secposture.EffectiveQuickScanBudget(r)
}

// quickScanOff reports whether the last reading for root said the service
// is not serving.
func (s *hookSecurity) quickScanOff(root string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.noScan[root]
}

// errQuickScanOff is the quick-scan provider's answer while the posture
// says the service is not serving: Fill records it and the verdict stays
// unknown, never clean.
var errQuickScanOff = errors.New("security: quick-scan service not available")

// errQuickScanNoTime is the quick-scan provider's answer when the hook
// already spent the host's timeout less the margins: the verdict stays
// unknown, never clean (LEFT2 audit E4).
var errQuickScanNoTime = errors.New("security: no time left in the host's hook timeout for the quick scan")

// hookQuickScanBudget clamps budget below plan's host timeout less the time
// the hook spent since plan.Started (zero when no start is recorded).
func hookQuickScanBudget(budget time.Duration, plan hookFailurePlan, now time.Time) (time.Duration, bool) {
	var elapsed time.Duration
	if !plan.Started.IsZero() {
		elapsed = now.Sub(plan.Started)
	}
	return secposture.ClampQuickScanBudgetAfter(budget, plan.HostTimeout, elapsed)
}

var (
	hookSecMu  sync.Mutex
	hookSecCur *hookSecurity
)

// hookSecurityPostureLoad reads and verifies the signed guard posture for
// currentHookSecurity (a seam for tests that count the reads).
var hookSecurityPostureLoad = guardposture.Load

// currentHookSecurity returns the invocation's security state for
// configPath, reading the guard posture once.
func currentHookSecurity(configPath string) *hookSecurity {
	hookSecMu.Lock()
	defer hookSecMu.Unlock()
	if hookSecCur == nil || hookSecCur.config != configPath {
		hookSecCur = &hookSecurity{config: configPath}
	}
	s := hookSecCur
	s.once.Do(func() {
		resolved, err := config.ResolveGlobalPath(configPath)
		if err != nil {
			s.module = secposture.ModuleNoDaemon
			return
		}
		s.layout = secposture.LayoutFor(resolved)
		ld := hookSecurityPostureLoad(guardposture.PosturePath(resolved), guardposture.KeyPath(resolved))
		s.module = secposture.ModuleSignalFrom(ld.State, ld.Posture)
		if s.module == secposture.ModuleActive {
			s.packs = append([]string(nil), ld.Posture.SecurityPacks...)
			s.daemonStopped = hookDaemonStopped(ld.Posture, time.Now())
			s.floorHeld = ld.Posture.Managed && ld.Posture.CommitGateFloorHeld
		}
	})
	return s
}

// hookDaemonStopped reports a verified guard posture the daemon stopped
// refreshing: written longer ago than guardposture.MaxAge (the daemon
// re-signs it every guardposture.RefreshInterval while it runs).
func hookDaemonStopped(p *guardposture.Posture, now time.Time) bool {
	return p != nil && !p.WrittenAt.IsZero() && now.Sub(p.WrittenAt) > guardposture.MaxAge
}

// unknownFacts are the facts of an unknown state under the signed pack set:
// the commit gate and the content rows still fire (lane SEC-GATEFIX).
func (s *hookSecurity) unknownFacts(reason secposture.Reason) hookctx.Security {
	sec := secposture.FactsUnder(secposture.Reading{State: secposture.State{Posture: policy.SecurityPostureUnknown, Reason: reason}}, s.packs)
	if s.floorHeld {
		sec.CommitGateFloor = policy.CommitGateFloorQuickScan
	}
	return sec
}

// withHeldFloor puts the held commit gate floor on facts read from a
// reading with no verified file (missing, unverifiable, over the cap): on a
// managed node holding a floor the gate keeps the floor's cell (audit
// SEC-P4 F2). A verified file is authoritative for its project and is left
// as read.
func (s *hookSecurity) withHeldFloor(sec policy.Security, r secposture.Reading) policy.Security {
	if r.File == nil && s.floorHeld {
		sec.CommitGateFloor = policy.CommitGateFloorQuickScan
	}
	return sec
}

// hookFloorReadLimit bounds the direct floor read after the posture read
// overran (floorAfterOverrun).
const hookFloorReadLimit = hookSecurityReadLimit

// hookSecurityPostureRead is the Sidecar provider's project posture read (a
// seam for tests that make it overrun).
var hookSecurityPostureRead = secposture.Load

// floorAfterOverrun is the commit gate floor for root when the Sidecar read
// failed or overran (audit SEC-P4 F2): the floor is read straight from the
// project's signed posture file, in a bounded read of its own; a verified
// file decides (its floor, or none), and with no verified file in time a
// managed node holding a floor reads it as in force.
func (s *hookSecurity) floorAfterOverrun(root string) string {
	type floorRead struct {
		floor string
		ok    bool
	}
	if root != "" {
		ch := make(chan floorRead, 1)
		go func() {
			r := secposture.Load(s.layout, root, s.module, time.Now(), secposture.Versions{})
			if r.File == nil {
				ch <- floorRead{}
				return
			}
			ch <- floorRead{floor: r.File.CommitGateFloor, ok: true}
		}()
		select {
		case f := <-ch:
			if f.ok {
				return f.floor
			}
		case <-time.After(hookFloorReadLimit):
		}
	}
	if s.floorHeld {
		return policy.CommitGateFloorQuickScan
	}
	return ""
}

// errModuleOff is the dirty provider's "nothing to do" (the module is not
// active, so no marker is written); Fill records it as an Issue and leaves
// DirtyRaised false, which is the truth.
var errModuleOff = errors.New("security module not active")

// errNoProjectRoot is the dirty provider's answer for an event with no
// resolved project root: no marker is named after the working directory.
var errNoProjectRoot = errors.New("security: no project root")

// securityHostProviders returns the host-path providers for configPath.
func securityHostProviders(configPath string) hookctx.HostProviders {
	return hookctx.HostProviders{
		Sidecar: func(_ context.Context, req hookctx.Request) (hookctx.Security, error) {
			s := currentHookSecurity(configPath)
			if req.ProjectRoot == "" {
				// No project to name (the invocation's first Fill, or an
				// event with no resolved root): read nothing.
				return s.unknownFacts(secposture.ReasonNoProjectRoot), nil
			}
			r := hookSecurityPostureRead(s.layout, req.ProjectRoot, s.module, time.Now(), secposture.Versions{})
			_ = secposture.Accept(s.layout, req.ProjectRoot, r)
			s.noteQuickScan(req.ProjectRoot, r)
			return hookDropStalePushDefault(s.withHeldFloor(secposture.FactsUnder(r, s.packs), r), r, req.ProjectRoot), nil
		},
		Dirty: func(_ context.Context, projectRoot string) error {
			if projectRoot == "" {
				return errNoProjectRoot
			}
			s := currentHookSecurity(configPath)
			if s.module != secposture.ModuleActive {
				return errModuleOff
			}
			return secposture.RaiseDirty(s.layout, secposture.ProjectRootHash(projectRoot))
		},
		QuickScan: func(ctx context.Context, req hookctx.QuickScanRequest) (hookctx.QuickScanResult, error) {
			s := currentHookSecurity(configPath)
			if s.module != secposture.ModuleActive {
				return hookctx.QuickScanResult{}, errModuleOff
			}
			if s.quickScanOff(req.ProjectRoot) {
				return hookctx.QuickScanResult{}, errQuickScanOff
			}
			// req.DirtySeen is the counter the enrich step read once,
			// before the line's first Fill raised it (lane sec-gate2): zero
			// covers nothing new, and the provider never re-reads it, so a
			// later scan on the same line cannot cover its own raise.
			ep, err := secipc.Endpoint(s.layout.Dir)
			if err != nil {
				return hookctx.QuickScanResult{}, err
			}
			// The scan must end inside the vendor's own hook timeout (lane
			// LEFT2-SEC item R-039): clamped below what is left of it after
			// the hook's own time (LEFT2 audit E4), with a margin.
			budget, _ := hookQuickScanBudget(s.quickScanBudget(req.ProjectRoot), currentHookPlan(), time.Now())
			if budget <= 0 {
				return hookctx.QuickScanResult{}, errQuickScanNoTime
			}
			return secipc.Ask(ctx, ep, req, budget)
		},
		Install: securityInstallChecker(configPath),
		// The quick scan's own limit is the largest budget a posture may
		// sign plus a margin (lane LEFT-SEC); each ask is bounded by its
		// project's budget, 2 s by default, so the default wait is as before.
		Limits: hookctx.Limits{Security: hookSecurityReadLimit, Dirty: hookSecurityDirtyLimit, QuickScan: secipc.MaxBudget + time.Second, Install: hookInstallLimit},
	}
}

// hookHeadWrite is when a checkout of the repository at root last wrote
// its HEAD (a seam for tests).
var hookHeadWrite = git.LatestHeadWrite

// hookDropStalePushDefault drops the signed default push remote when a
// checkout of the project switched branch at or after the posture was
// signed (or its HEADs cannot be read): the signed remote may be the
// previous branch's, so a plain push reads as an unknown target until the
// daemon re-signs (lane SEC-GATE5 milestone 2, SECP-18). Metadata reads
// only, and only while a default is signed (a held commit exists).
//
// A HEAD write in the future (clock skew, DrvFs, a network file system)
// is clamped the way the daemon clamps it (clampFutureHeadWrite, merge
// finding F7): the daemon resolved the default after that write and
// counts it resolved, so the hook keeps the default rather than dropping
// it on every event while the clock disagrees. A switch the skewed clock
// stamps later still makes the daemon re-resolve within one HEAD watch
// tick; until then a plain push reads that default (a named residual of
// SECP-18). A HEAD write with no sub-second part (a whole-second file
// system) compares at one-second granularity, so a switch in the second
// the posture was signed drops the default (git.HeadWriteBefore, lane
// SEC-P4 decision 6).
func hookDropStalePushDefault(sec policy.Security, r secposture.Reading, root string) policy.Security {
	if sec.DefaultPushRemote == "" {
		return sec
	}
	if r.File == nil {
		sec.DefaultPushRemote = ""
		return sec
	}
	if latest, ok := hookHeadWrite(root); !ok || !git.HeadWriteBefore(latest, clampFutureHeadWrite(latest, r.File.IssuedAt, time.Now())) {
		sec.DefaultPushRemote = ""
	}
	return sec
}

// securityDaemonProviders are the daemon-path providers of a relayed hook
// (sandbox plan section 5.2, M1; lane sbx-p2): the relay child runs on the
// host as a child of the daemon, so the posture it reads, the dirty marker
// it raises and the quick scan it asks for are the host's own state, which
// no box can reach (the observer directory is a tmpfs in every box). The
// same functions as the host path, read in the daemon's context; the
// daemon path has no "sidecar from the box" by construction.
func securityDaemonProviders(configPath string) hookctx.DaemonProviders {
	h := securityHostProviders(configPath)
	return hookctx.DaemonProviders{Memory: h.Sidecar, Dirty: h.Dirty, QuickScan: h.QuickScan, Install: h.Install, Limits: h.Limits}
}

// securityToolGateEnrich returns the tool gate's Enrich step: for every
// write-capable event (a shell command, an MCP call, a file write) the
// hook context is filled for the event's project, which reads the posture
// into Event.Security and then raises the dirty marker, before guard
// evaluates the call. A read-only event carries no Security facts, and
// while the signed guard posture does not say the module is active the
// step fills nothing and leaves Event.Security nil (its contract in
// internal/policy/event.go). The project root is the event's own root, or
// the project the working directory belongs to (hookProjectRoot), never
// the working directory as given: an event with neither reads as unknown
// and raises no marker.
//
// Security Phase C adds two facts (lane SEC-C2): a file write's in-hook
// secret scan (secrules.PreWriteSecurity, the hits S-721 reads), and, at a
// commit or a push, the quick-scan request to the daemon, asked only while
// the posture says the project is dirty; its verdict is what S-793 reads.
// aliases is the git alias table guard reads (policy.Config.GitAliases),
// so the request classifier reaches the same writes as the gate rows (lane
// SEC-GATEFIX); nil reads only aliases defined on the line itself.
func securityToolGateEnrich(configPath, tool, event string, aliases func(dir string) (map[string]string, bool)) func(*policy.Event) {
	return withProjectLookupRoot(securityFactsEnrich(configPath, tool, event, aliases))
}

// securityFactsEnrich is securityToolGateEnrich's security half: the hook
// context facts of a write-capable event (the doc comment above).
func securityFactsEnrich(configPath, tool, event string, aliases func(dir string) (map[string]string, bool)) func(*policy.Event) {
	return func(pe *policy.Event) {
		if !policy.IsWriteCapable(pe) {
			return
		}
		hs := currentHookSecurity(configPath)
		if hs.module != secposture.ModuleActive {
			return
		}
		ctx := context.Background()
		hc := invocationHookContext(ctx, configPath)
		root := hookProjectRoot(pe)
		// The classifier runs only here, while the module is active, and
		// only for the event kinds that can commit (lazily: a file write
		// never reaches it).
		plan := securityQuickScanPlanFor(pe, root, aliases)
		// The AI change record trailer (lane sec-f2a): an agent's commit in
		// a repository whose trailer a person consented to is held as a
		// candidate (one stat otherwise); its marker is written only on the
		// gate's allow path (provenanceAgentCommitAllowed, audit finding F3;
		// security_provenance_writers.go).
		provenanceNoteAgentCommit(hs.layout.Dir, root, pe, tool, plan.commits(), aliases)
		// The dirty counter is read ONCE, before the first Fill raises it,
		// and every request of the line carries that value (lane
		// sec-gate2, decision log P-021): a clean answer then covers only
		// activity from before this event, never the event's own raise. A
		// counter that cannot be read covers nothing (zero).
		plan.captureDirty(hs.layout, root)
		req := hookctx.Request{
			Tool: tool, Event: event, ProjectRoot: root, SessionID: pe.SessionID, WriteCapable: true,
			QuickScan: plan.first(),
		}
		hc.Fill(ctx, req)
		if hc.Security != nil && hc.Security.Posture == policy.SecurityPostureUnknown && len(hc.Security.Packs) == 0 {
			// The Sidecar provider failed or overran (Fill recorded an
			// Issue and left an unknown state with no packs): the event
			// still carries the signed pack set, so the commit gate asks
			// and the content rows fire (lane SEC-GATEFIX, P-014 item 2).
			// Set before the install check, which reads the pack set too
			// (plans decision log P-021).
			hc.Security.Packs = hs.unknownFacts(secposture.ReasonUnverified).Packs
			// The floor survives the failed read too (audit SEC-P4 F2): read
			// straight from the signed posture file, failing closed on a
			// managed node holding a floor.
			if hc.Security.CommitGateFloor == "" {
				hc.Security.CommitGateFloor = hs.floorAfterOverrun(root)
			}
		}
		securityDepsEnrich(ctx, hc, pe, root)
		if hc.Security == nil {
			return
		}
		sec := *hc.Security
		sec.DaemonStopped = hs.daemonStopped
		content, hasContent := securityMCPContentFacts(pe, hs)
		if plan.elsewhere() || hasContent {
			// A gating write runs in another repository, or somewhere the
			// line does not let the hook place (P-021, P-041; lane
			// SEC-GATE5 milestone 1): that repository's own posture is
			// read, and the stricter of the two states decides. A GitHub
			// content tool's own arguments are one more state (lane SEC-P4
			// decision 2).
			sec = securityMergeElsewhere(sec, hs, plan, content...)
		}
		// Every repository the line can write into is marked dirty after
		// its posture was read (lane SEC-P4 decision 3).
		securityRaiseWrittenRepos(hs, pe, root, plan)
		if plan.otherCheckout && sec.Posture == policy.SecurityPostureClean {
			// The posture is the project's (F0-14 keys a linked worktree on
			// its main repository), scanned from and cleared by the main
			// checkout; a commit in another checkout records that
			// checkout's own index, which no clean record speaks for. It
			// reads at least dirty, so the gate reads the (opaque, unknown)
			// quick scan and asks, never a clean inherited from elsewhere.
			sec.Posture = policy.SecurityPostureDirty
		}
		if sec.Posture != policy.SecurityPostureAbsent {
			sec.Hits, sec.ScanIncomplete = secrules.PreWriteSecurity(pe)
			sec.QuickScan = policy.QuickScanNone
			if plan.asked(sec) {
				sec.QuickScan = plan.verdict(ctx, hc, req, hc.QuickScan)
			}
		}
		pe.Security = &sec
	}
}

// maxQuickScanWrites bounds the gating writes one event's quick scan
// covers; a line with more answers unknown (the gate asks).
const maxQuickScanWrites = 4

// securityQuickScanPlan is the quick scan an event needs: one request per
// gating write (a commit, a push), scanned one by one and combined, or
// opaque when the scan cannot answer for what the line records.
type securityQuickScanPlan struct {
	reqs []*hookctx.QuickScanRequest
	// opaque: the line changes directory before a write (`cd other &&
	// git commit`) or holds more than maxQuickScanWrites writes, so no
	// scan of the project root can call it clean (unknown, never a
	// vacuous clean).
	opaque bool
	// otherCheckout: a write runs in a linked worktree of the project
	// other than root's own checkout (securityInOtherCheckout). The plan is
	// opaque and the enrich step reads a clean posture as dirty for it, so
	// the gate never lets such a commit through on the main checkout's
	// clean (F0-14 merge, audit finding 1).
	otherCheckout bool
	// otherRepos are the project roots (hookRootOf spelling) of other
	// repositories a gating write runs in (`cd /other && git commit`,
	// `git -C /other commit`, GIT_DIR, a subshell), at most
	// maxOtherRepos; unplaced is set when a write could not be placed, or
	// more repositories than that were named. Either makes the plan opaque
	// and the enrich step reads each repository's own posture, with an
	// unplaced write reading unknown (lane SEC-GATE5 milestone 1).
	otherRepos []string
	unplaced   bool
}

// maxOtherRepos bounds the other repositories one event's posture reads
// cover; a line naming more reads unknown. It also bounds the other
// repositories one event raises the dirty counter of.
const maxOtherRepos = 4

// maxRaiseDirs bounds the directories of one line whose repository the
// dirty raise looks up.
const maxRaiseDirs = 16

// commits reports whether the plan's own-repository writes include a
// commit (an opaque plan reports none: no trailer for a line the hook
// cannot place).
func (p securityQuickScanPlan) commits() bool {
	for _, r := range p.reqs {
		if r.Form.Form == policy.GitWriteCommit {
			return true
		}
	}
	return false
}

// elsewhere reports a write outside the event's own repository.
func (p securityQuickScanPlan) elsewhere() bool { return p.unplaced || len(p.otherRepos) > 0 }

// captureDirty stamps every request with the project's dirty counter as
// it is now (zero when it cannot be read: a clean answer then covers
// nothing).
func (p securityQuickScanPlan) captureDirty(layout secposture.Layout, root string) {
	if len(p.reqs) == 0 {
		return
	}
	seen, err := secposture.ReadDirty(layout, secposture.ProjectRootHash(root))
	if err != nil {
		seen = 0
	}
	for _, r := range p.reqs {
		r.DirtySeen = seen
	}
}

// first is the request the first Fill carries (nil when none is needed or
// the plan is opaque: an opaque plan asks nothing of the daemon).
func (p securityQuickScanPlan) first() *hookctx.QuickScanRequest {
	if p.opaque || len(p.reqs) == 0 {
		return nil
	}
	return p.reqs[0]
}

// asked reports whether the commit gate reads a quick-scan verdict for this
// event in state sec (a gating write, in a dirty project).
func (p securityQuickScanPlan) asked(sec hookctx.Security) bool {
	return (p.opaque || len(p.reqs) > 0) && securityNeedsQuickScan(sec)
}

// verdict combines the plan's answers: clean only when every write was
// scanned clean, blocking when one was blocking, else unknown. firstRes is
// the first Fill's answer; every further write is asked through the same
// hook context (a Fill that raises no second dirty marker), stopping at
// the first answer that is not clean. A failed or skipped answer is
// unknown, never clean.
func (p securityQuickScanPlan) verdict(ctx context.Context, hc *hookctx.Context, req hookctx.Request, firstRes *hookctx.QuickScanResult) policy.QuickScanVerdict {
	if p.opaque {
		return policy.QuickScanUnknown
	}
	v := policy.QuickScanUnknown
	if firstRes != nil {
		v = firstRes.Verdict
	}
	seen := p.reqs[0].DirtySeen
	for _, next := range p.reqs[1:] {
		if v != policy.QuickScanClean {
			break
		}
		r := *next
		r.DirtySeen = seen
		more := req
		more.WriteCapable = false
		more.QuickScan = &r
		hc.Fill(ctx, more)
		v = policy.QuickScanUnknown
		if hc.QuickScan != nil {
			v = hc.QuickScan.Verdict
		}
	}
	return v
}

// securityQuickScanPlanFor returns the quick-scan plan for an event: one
// request per gating commit or push the classifier finds, reading the
// alias table guard reads (policy.ClassifyGitWritesCtx, so `git ci && git
// p` is two writes, not one), or an opaque plan when the line changes
// directory before a write to a place outside the project root, or holds
// too many writes. An event with no project root or no gating write needs
// none.
func securityQuickScanPlanFor(pe *policy.Event, root string, aliases func(string) (map[string]string, bool)) securityQuickScanPlan {
	if root == "" || (pe.Kind != policy.KindShellExec && pe.Kind != policy.KindMCPCall) {
		return securityQuickScanPlan{}
	}
	mctx := &policy.MatchContext{Event: pe, Cfg: &policy.Config{GitAliases: aliases}}
	var gating []policy.GitWrite
	for _, c := range policy.ClassifyGitWritesCtx(mctx) {
		if policy.GitWriteGates(c.Write) {
			gating = append(gating, c.Write)
		}
	}
	if len(gating) == 0 {
		return securityQuickScanPlan{}
	}
	others, unplaced, placedOtherCheckout := securityWriteRepos(pe, root, aliases)
	other := placedOtherCheckout || securityInOtherCheckout(pe, root)
	if other || unplaced || len(others) > 0 || len(gating) > maxQuickScanWrites || securityLeavesRoot(pe, root) {
		return securityQuickScanPlan{opaque: true, otherCheckout: other, otherRepos: others, unplaced: unplaced}
	}
	// A relayed commit in a sandbox copy is scanned in the copy's tree, and
	// a tree only inside a box answers unknown (lane sec-box,
	// security_box.go).
	scanRoot, ok := securityQuickScanRoot(root)
	if !ok {
		return securityQuickScanPlan{opaque: true}
	}
	plan := securityQuickScanPlan{}
	for _, w := range gating {
		plan.reqs = append(plan.reqs, &hookctx.QuickScanRequest{ProjectRoot: scanRoot, Form: w, OnlyWhen: securityNeedsQuickScan})
	}
	return plan
}

// dirChangeCommands are the command units that change the shell's
// directory for the rest of the line (bash, zsh, cmd, PowerShell
// spellings; the parser canonicalizes PowerShell aliases).
var dirChangeCommands = map[string]bool{
	"cd": true, "pushd": true, "popd": true, "chdir": true,
	"set-location": true, "push-location": true, "pop-location": true,
}

// securityLeavesRoot reports whether a shell line changes directory to
// somewhere outside root's working tree before (or around) its writes: a
// `cd` whose target is not inside root, or one it cannot resolve (a
// variable, `-`, no operand, popd). The quick scan reads root's index, so
// such a line is never answered clean (lane SEC-GATEFIX milestone 2e).
func securityLeavesRoot(pe *policy.Event, root string) bool {
	if pe.Kind != policy.KindShellExec {
		return false
	}
	dirs, unresolved := securityLineDirs(pe, root)
	if unresolved {
		return true
	}
	for _, dir := range dirs {
		// Checkouts, not project roots: a linked worktree shares its main
		// checkout's project root (F0-14) but not its index.
		if hookCheckoutOf(dir) != hookCheckoutOf(root) {
			return true
		}
	}
	return false
}

// securityLineDirs returns the directories a shell line changes to, in
// order, each resolved against the one before (the first against the
// event's working directory, else root), and whether a change could not be
// resolved (a variable, `-`, no operand, popd); the walk stops there.
//
// A line with a second shell reading (policy.Event.AltDialect, as the
// engine and policy.GitWriteLocations read it) is walked under both, and
// the directories of both are returned (merge finding F1 of lane
// SEC-GATE5).
//
// A target on a UNC path (`\\host\share`, `//host/share`) or under a
// network or automount root (/net, /misc, /afs, /Network), outside the
// event's own directory, is unresolved and never returned, so nothing on
// the hook path stats it: it reads unknown, as a `-C` or GIT_DIR there
// does (policy.IsNetworkPlace; SEC-GATE5 follow-up to merge finding F9).
func securityLineDirs(pe *policy.Event, root string) (dirs []string, unresolved bool) {
	dirs, unresolved, _ = securityLineWalk(pe, root)
	return dirs, unresolved
}

// securityLineWalk is securityLineDirs that also reports whether a change
// went to a network place (which is also unresolved).
func securityLineWalk(pe *policy.Event, root string) (dirs []string, unresolved, network bool) {
	base := pe.Cwd
	if base == "" {
		base = root
	}
	if len(pe.Args) > 0 {
		return securityWalkDirs(policy.ParseArgv(pe.Args, pe.Dialect), base, pe.Dialect)
	}
	dirs, unresolved, network = securityWalkDirs(policy.ParseCommand(pe.Target, pe.Dialect), base, pe.Dialect)
	if alt := pe.AltDialect; alt != "" && securityDialectOf(alt) != securityDialectOf(pe.Dialect) {
		more, altUnresolved, altNetwork := securityWalkDirs(policy.ParseCommand(pe.Target, alt), base, alt)
		dirs = append(dirs, more...)
		unresolved = unresolved || altUnresolved
		network = network || altNetwork
	}
	return dirs, unresolved, network
}

// securityLineWrittenDirs is securityLineWalk's directories narrowed to
// the ones a unit may write into (audit SEC-P4 F6): a directory counts when
// a unit after the change into it, before the next change, is not a
// read-only command (securityReadOnlyUnit). Both shell readings are
// walked, as securityLineWalk walks them.
func securityLineWrittenDirs(pe *policy.Event, root string) []string {
	base := pe.Cwd
	if base == "" {
		base = root
	}
	if len(pe.Args) > 0 {
		return securityWrittenDirsOf(policy.ParseArgv(pe.Args, pe.Dialect), base, pe.Dialect)
	}
	dirs := securityWrittenDirsOf(policy.ParseCommand(pe.Target, pe.Dialect), base, pe.Dialect)
	if alt := pe.AltDialect; alt != "" && securityDialectOf(alt) != securityDialectOf(pe.Dialect) {
		dirs = append(dirs, securityWrittenDirsOf(policy.ParseCommand(pe.Target, alt), base, alt)...)
	}
	return dirs
}

// securityWrittenDirsOf walks one reading like securityWalkDirs and keeps
// each directory changed to only when a later unit in it may write.
func securityWrittenDirsOf(cmds []policy.Command, base string, dialect policy.Dialect) []string {
	var out []string
	cur, written := "", false
	flush := func() {
		if cur != "" && written {
			out = append(out, cur)
		}
	}
	anchor := base
	for _, c := range cmds {
		if !dirChangeCommands[c.Base] {
			if cur != "" && !securityReadOnlyUnit(c) {
				written = true
			}
			continue
		}
		flush()
		cur, written = "", false
		args := c.Args()
		if len(args) != 1 || args[0] == "-" || strings.ContainsAny(args[0], "$%`~") {
			return out
		}
		res := resolveShellDir(hostShellPathRules(), dialect, args[0], base)
		if res.Reason != "" {
			return out // HOOK-MSYS-1: an unmapped or network place is unknown
		}
		dir := res.Dir
		if policy.IsNetworkPlace(args[0], dir, anchor) {
			return out
		}
		cur, base = dir, dir
	}
	flush()
	return out
}

// securityReadOnlyBases are the commands that only read: a unit of one of
// them with no output redirection writes nothing where it runs. Anything
// else (git included, an interpreter, a nested shell, tee, find with its
// -delete and -exec) may write. A data table, over-approximating writes.
var securityReadOnlyBases = map[string]bool{
	"ls": true, "dir": true, "pwd": true, "cat": true, "head": true, "tail": true,
	"less": true, "more": true, "wc": true, "grep": true, "egrep": true, "fgrep": true,
	"rg": true, "echo": true, "printf": true, "true": true, "false": true, "test": true,
	"[": true, "stat": true, "file": true, "which": true, "type": true, "tree": true,
	"du": true, "df": true, "whoami": true, "date": true,
	"get-childitem": true, "get-content": true, "get-location": true, "get-item": true,
	"select-string": true, "write-output": true, "write-host": true, "test-path": true,
}

// securityReadOnlyUnit reports a unit that cannot write where it runs: a
// read-only command with no output redirection and nothing it wraps left
// unanalysed.
func securityReadOnlyUnit(c policy.Command) bool {
	return securityReadOnlyBases[strings.ToLower(c.Base)] && len(c.RedirectTargets) == 0 && c.Unanalyzed == "" && c.Payload == ""
}

// securityDialectOf spells the default dialect ("" is POSIX) for comparing
// two readings.
func securityDialectOf(d policy.Dialect) policy.Dialect {
	if d == "" {
		return policy.DialectPosix
	}
	return d
}

// securityWalkDirs walks one reading's directory changes from base (see
// securityLineDirs). A network target stops the walk, unresolved, before
// anything stats it.
func securityWalkDirs(cmds []policy.Command, base string, dialect policy.Dialect) (dirs []string, unresolved, network bool) {
	anchor := base
	for _, c := range cmds {
		if !dirChangeCommands[c.Base] {
			continue
		}
		args := c.Args()
		if len(args) != 1 || args[0] == "-" || strings.ContainsAny(args[0], "$%`~") {
			return dirs, true, false
		}
		// HOOK-MSYS-1: the operand resolves as the line's own shell does
		// (Git Bash's /c/x is C:\x on Windows); a place it cannot map
		// stops the walk, unresolved.
		res := resolveShellDir(hostShellPathRules(), dialect, args[0], base)
		if res.Reason != "" {
			return dirs, true, res.Reason == shellDirNetworkRoot
		}
		dir := res.Dir
		if policy.IsNetworkPlace(args[0], dir, anchor) {
			return dirs, true, true
		}
		dirs = append(dirs, dir)
		base = dir
	}
	return dirs, false, false
}

// hookCheckoutOf is hookRootOf for the checkout: the top level whose index
// a commit in dir records (a linked worktree's own, git.FindCheckoutRoot).
func hookCheckoutOf(dir string) string {
	if root, ok := git.FindCheckoutRoot(dir); ok {
		return root
	}
	return hookAbs(dir)
}

// securityInOtherCheckout reports whether the event's write runs in a
// linked worktree of root's project rather than root's own checkout: the
// event's working directory, the checkout a relayed run was launched in
// (hookctx's RunCheckoutRoot, the host's launch fact, so a relayed event
// with no or a box-only working directory is still placed), or a directory
// a shell line changes to, belongs to root's project but to another
// checkout. The
// two share one project root (F0-14), but the quick scan reads root's
// index and the posture's clean record is the main checkout's, neither of
// which is what a commit in the worktree records, so the answer is
// unknown, never a vacuous or inherited clean (as before F0-14, when the
// worktree's posture key had no file and the gate always asked). A
// directory outside the project (a relayed event's box path, another
// repository) is not this case. A plain repository has one checkout, so
// this never holds there.
func securityInOtherCheckout(pe *policy.Event, root string) bool {
	if root == "" {
		return false
	}
	locs := []string{pe.Cwd, hookctx.Process().RunCheckoutRoot()}
	if pe.Kind == policy.KindShellExec {
		dirs, _ := securityLineDirs(pe, root)
		locs = append(locs, dirs...)
	}
	project, checkout := hookRootOf(root), hookCheckoutOf(root)
	for _, dir := range locs {
		if dir == "" || hookRootOf(dir) != project {
			continue
		}
		if hookCheckoutOf(dir) != checkout {
			return true
		}
	}
	return false
}

// securityWriteRepos places every gating write of an event
// (policy.GitWriteLocations: the cwd frames, `-C`, `--git-dir`,
// `--work-tree`, GIT_DIR, GIT_WORK_TREE) and returns the other
// repositories they run in (hookRootOf spelling, deduplicated, at most
// maxOtherRepos), whether one could not be placed, and whether one runs in
// another checkout of root's own project (the otherCheckout case). A
// relayed event is anchored on the run's checkout, never on a directory the
// box reported, and gets no home directory to expand.
func securityWriteRepos(pe *policy.Event, root string, aliases func(string) (map[string]string, bool)) (others []string, unplaced, otherCheckout bool) {
	if root == "" || (pe.Kind != policy.KindShellExec && pe.Kind != policy.KindMCPCall) {
		return nil, false, false
	}
	ev := *pe
	home := ""
	if run := hookctx.Process().RunCheckoutRoot(); run != "" {
		ev.Cwd, ev.ProjectRoot = run, run
	} else if r := hookctx.Process().RunProjectRoot(); r != "" {
		ev.Cwd, ev.ProjectRoot = r, r
	} else {
		home = hookGitHome()
		if ev.Cwd == "" {
			ev.Cwd = root
		}
	}
	// A directory change to a network place: the line's writes are
	// unplaced, and no directory of it is stat-ed (SEC-GATE5 follow-up).
	if ev.Kind == policy.KindShellExec {
		if _, _, network := securityLineWalk(&ev, root); network {
			return nil, true, false
		}
	}
	anchor := ev.Cwd
	project, checkout := hookRootOf(root), hookCheckoutOf(root)
	seen := map[string]bool{}
	// A gating write the placer did not place (fewer locations than gating
	// writes, or one with no place) reads unknown, never as the event's
	// own repository (merge finding F3).
	gating := 0
	for _, c := range policy.ClassifyGitWritesCtx(&policy.MatchContext{Event: &ev, Cfg: &policy.Config{GitAliases: aliases}}) {
		if policy.GitWriteGates(c.Write) {
			gating++
		}
	}
	locs := policy.GitWriteLocations(&policy.MatchContext{Event: &ev, Cfg: &policy.Config{GitAliases: aliases, Home: home}})
	if securityWritesUnplaced(gating, locs) {
		unplaced = true
	}
	for _, loc := range locs {
		for _, d := range loc.Dirs {
			if policy.IsNetworkPlace(d, d, anchor) {
				unplaced = true
				continue
			}
			dir := filepath.FromSlash(policy.GitDirWorkTree(d))
			proj := hookRootOf(dir)
			if hookSamePath(proj, project) {
				if !hookSamePath(hookCheckoutOf(dir), checkout) {
					otherCheckout = true
				}
				continue
			}
			key := filepath.Clean(proj)
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(others) == maxOtherRepos {
				unplaced = true
				continue
			}
			others = append(others, proj)
		}
	}
	return others, unplaced, otherCheckout
}

// securityWritesUnplaced reports that the placer left a gating write
// without a place: it located fewer writes than the classifier gates, or
// one location is unknown or names no directory. Such a line reads
// unknown, never as the event's own repository (merge finding F3 of lane
// SEC-GATE5).
func securityWritesUnplaced(gating int, locs []policy.GitWriteLocation) bool {
	if len(locs) < gating {
		return true
	}
	for _, loc := range locs {
		if loc.Unknown || len(loc.Dirs) == 0 {
			return true
		}
	}
	return false
}

// hookGitHome is the home directory a `~` in a gating write's location
// expands against (a payload path's home; "" when it cannot be read, so
// such a location is unplaced).
func hookGitHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// hookSamePath compares two root spellings, case-insensitively where the
// file system is.
func hookSamePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// securityPostureRank orders the commit-gate states for merging two
// repositories' postures: the higher rank decides. blocking ranks above
// unknown because enforce denies it where it only asks on unknown.
func securityPostureRank(p policy.SecurityPosture) int {
	switch p {
	case policy.SecurityPostureAbsent:
		return 0
	case policy.SecurityPostureClean:
		return 1
	case policy.SecurityPostureDirty:
		return 2
	case policy.SecurityPostureBlocking:
		return 4
	}
	return 3 // unknown, or a state outside the vocabulary
}

// securityMergeElsewhere merges the postures of the other repositories a
// line's writes run in into sec (the event's own project): each one's own
// signed file is read and accepted as the Sidecar provider reads the
// event's, an unplaced write reads unknown, and the higher-ranked state
// decides. Two blocking states add up, and a history-only hold is kept
// only when every blocking finding on both sides is one. Since the push
// gate cannot tell which repository's remotes a push on such a line goes
// to, no remote is credited (DefaultPushRemote and BlockingHistoryOnlyOn
// are cleared): never looser than either repository alone (PR14).
//
// extra are further states to merge (a content tool's scanned arguments,
// securityMCPContentFacts). The dirty counters of the repositories read
// here are raised after the read by securityRaiseWrittenRepos, never here
// (a raise first would turn a blocking file into dirty, which enforce only
// asks on).
func securityMergeElsewhere(sec policy.Security, hs *hookSecurity, plan securityQuickScanPlan, extra ...policy.Security) policy.Security {
	if sec.Posture == policy.SecurityPostureAbsent {
		// The module or every pillar child is off: nothing gates here,
		// and the other repository is on the same node.
		return sec
	}
	others := append([]policy.Security(nil), extra...)
	if plan.unplaced {
		others = append(others, hs.unknownFacts(secposture.ReasonMissing))
	}
	now := time.Now()
	for _, repo := range plan.otherRepos {
		r := secposture.Load(hs.layout, repo, hs.module, now, secposture.Versions{})
		_ = secposture.Accept(hs.layout, repo, r)
		f := secposture.FactsUnder(r, hs.packs)
		if f.Posture == policy.SecurityPostureClean {
			// The line may change files there before it commits, and the
			// hook raised only the event's own project's counter: a clean
			// record of that repository does not cover this line (the
			// otherCheckout rule), so it reads dirty and the opaque quick
			// scan answers unknown.
			f.Posture = policy.SecurityPostureDirty
		}
		others = append(others, f)
	}
	out := sec
	out.DefaultPushRemote = ""
	out.BlockingHistoryOnlyOn = nil
	for _, o := range others {
		switch ro, rs := securityPostureRank(o.Posture), securityPostureRank(out.Posture); {
		case ro > rs:
			out.Posture = o.Posture
			out.Blocking, out.Overflow, out.BlockingHistoryOnly = o.Blocking, o.Overflow, o.BlockingHistoryOnly
			out.HeldCommits = append([]policy.HeldCommit(nil), o.HeldCommits...)
		case ro == rs && o.Posture == policy.SecurityPostureBlocking:
			out.Blocking += o.Blocking
			out.Overflow = out.Overflow || o.Overflow
			out.BlockingHistoryOnly += o.BlockingHistoryOnly
			out.HeldCommits = append(out.HeldCommits, o.HeldCommits...)
		}
		if len(out.Packs) == 0 {
			out.Packs = o.Packs
		}
		// The strictest commit gate floor of the repositories the line
		// reaches decides (lane SEC-P4 decision 9): a floored repository's
		// commit from an unfloored session still takes the floor's cells.
		if o.CommitGateFloor == policy.CommitGateFloorQuickScan {
			out.CommitGateFloor = o.CommitGateFloor
		}
	}
	return out
}

// securityMCPContentFacts scans a GitHub content tool's file contents
// (policy.MCPCommitContents: push_files, create_or_update_file,
// create_commit) with the hook's secret detector, as a file write's edits
// are (lane SEC-P4 decision 2). A high-confidence hit reads blocking (the
// S-721 threshold), an unreadable or over-cap argument or a scan that did
// not finish reads unknown, and a clean scan adds nothing (the event's own
// placement still decides). ok is false when the event is not such a tool.
func securityMCPContentFacts(pe *policy.Event, hs *hookSecurity) ([]policy.Security, bool) {
	texts, applies, readable := policy.MCPCommitContents(pe)
	if !applies {
		return nil, false
	}
	if !readable {
		return []policy.Security{hs.unknownFacts(secposture.ReasonUnverified)}, true
	}
	scan := policy.Event{Kind: policy.KindFileAccess, Target: pe.Target, ProjectRoot: pe.ProjectRoot}
	for _, t := range texts {
		scan.Edits = append(scan.Edits, policy.ProposedEdit{Kind: policy.EditWhole, New: t})
	}
	hits, incomplete := secrules.PreWriteSecurity(&scan)
	blocking := 0
	for _, h := range hits {
		if h.Category == policy.FindingSecret && h.Confidence == policy.FindingConfidenceHigh {
			blocking++
		}
	}
	switch {
	case blocking > 0:
		f := hs.unknownFacts(secposture.ReasonUnverified)
		f.Posture, f.Blocking = policy.SecurityPostureBlocking, blocking
		return []policy.Security{f}, true
	case incomplete:
		return []policy.Security{hs.unknownFacts(secposture.ReasonUnverified)}, true
	}
	return nil, false
}

// securityRaiseWrittenRepos raises the dirty counter of every repository
// other than root's that the event can write into (lane SEC-P4 decision 3,
// SECP-18): the repositories a gating write was placed in (whose posture
// securityMergeElsewhere read first), every directory a shell line changes
// to where a later unit may write (`cd /o && echo x > f`; a `cd /o && ls`
// raises nothing, audit SEC-P4 F6: securityLineWrittenDirs), and a file
// tool's path outside root. At most maxOtherRepos repositories; a network place
// is never stat-ed (P-053), and a relayed event's box-side directories are
// not host paths, so only its placed writes count. The event's own root is
// raised by hookctx's Fill.
func securityRaiseWrittenRepos(hs *hookSecurity, pe *policy.Event, root string, plan securityQuickScanPlan) {
	if root == "" || hs.module != secposture.ModuleActive {
		return
	}
	repos := append([]string(nil), plan.otherRepos...)
	if hookctx.Process().RunProjectRoot() == "" {
		var dirs []string
		switch {
		case pe.Kind == policy.KindShellExec:
			dirs = securityLineWrittenDirs(pe, root)
		case pe.Kind == policy.KindFileAccess && filepath.IsAbs(pe.Target):
			if !policy.IsNetworkPlace(pe.Target, pe.Target, root) {
				dirs = append(dirs, filepath.Dir(pe.Target))
			}
		}
		if len(dirs) > maxRaiseDirs {
			// Bound the root lookups (each stats up the tree); the
			// repositories past it keep their counters, as a line naming
			// more than maxOtherRepos already reads unknown.
			dirs = dirs[:maxRaiseDirs]
		}
		project := hookRootOf(root)
		for _, d := range dirs {
			if proj := hookRootOf(d); proj != "" && !hookSamePath(proj, project) {
				repos = append(repos, proj)
			}
		}
	}
	seen := map[string]bool{}
	for _, repo := range repos {
		key := filepath.Clean(repo)
		if seen[key] || hookSamePath(repo, root) {
			continue
		}
		if len(seen) == maxOtherRepos {
			return
		}
		seen[key] = true
		_ = secposture.RaiseDirty(hs.layout, secposture.ProjectRootHash(repo))
	}
}

// securityNeedsQuickScan: only a dirty project's commit gate reads the
// quick scan (S-793); a clean, blocking, unknown or absent state decides
// without it, so no daemon round trip is spent there.
func securityNeedsQuickScan(s hookctx.Security) bool {
	return s.Posture == policy.SecurityPostureDirty
}

// securityHookPackRules composes the pillar's rule pack in the hook
// process. The hook has no component state: while the signed guard posture
// says the module is active, every pillar pack is composed, and each
// composed rule fires only while its child is in Event.Security.Packs (the
// active pack set signed into the project's posture; secrules.Compose
// enforces it); while it is not, nothing is composed.
func securityHookPackRules(configPath string) []policy.Rule {
	if currentHookSecurity(configPath).module != secposture.ModuleActive {
		return nil
	}
	return securityPackRules(func(id string) bool { return id == "security" || strings.HasPrefix(id, "security.") }, nil)
}

// hookSecurityAliases is the alias lookup the enrich step's request
// classifier reads: the same table buildHookGuard gives guard, so the
// quick scan covers the writes the commit-gate rows see (nil when the
// config did not load). The lookup reads the file only when called.
func hookSecurityAliases(cfg config.Config, cfgErr error) func(string) (map[string]string, bool) {
	if cfgErr != nil {
		return nil
	}
	if fn := fileGitAliasLookup(gitalias.Path(cfg.Observer.DBPath), nil); fn != nil {
		return fn
	}
	return nil
}
