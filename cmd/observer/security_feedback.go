//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secciwf"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secdiffobs"
	"github.com/marmutapp/superbased-observer/internal/secfeedback"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secipc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_feedback.go is security Phase H's feedback to the agent after a
// write (security pillar plan sections 4.7, 5.11 (c), 6.1 and 6.2 step 2;
// spike JSP-6; lane sec-h): the daemon's answer to the post-tool feedback
// request, and the hook's one seam, securityPostFeedback, that every
// post-tool handler calls with the reply it is about to write. Both halves
// act only while component security.feedback is SELECTED (securityOptIn:
// a [components] block names it): the daemon reads the selection from its
// component snapshot, the hook from the signed active pack set the daemon
// derives from that same selection. Not selected, the seam returns the
// reply it was given byte for byte, and asks nothing.

// securityFeedbackComponent is the catalog id of the feedback child.
const securityFeedbackComponent = "security.feedback"

// hookFeedbackAskLimit bounds the hook's feedback round trip: the daemon's
// own 50 ms answer budget plus the transport (internal/hookbudget Feedback).
const hookFeedbackAskLimit = secipc.FeedbackBudget + 50*time.Millisecond

// securityFeedbackAnswerer returns the daemon's feedback answerer for the
// quick-scan endpoint, or nil while the component is not selected or
// [security.feedback].after_write is off (the endpoint then answers the
// request empty). The store opens on the first request and stays open for
// the daemon's lifetime (closed when ctx ends), so later requests answer
// within the budget. What it offers is leased, not recorded: the endpoint
// records it only through the offer's Ack, once the hook acknowledged the
// reply that carried it (lane sec-polish, audit finding F3).
func securityFeedbackAnswerer(ctx context.Context, configPath string, snap componentstate.Snapshot) secipc.FeedbackAnswerer {
	if !securitySelected(snap, securityFeedbackComponent) {
		return nil
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil || !cfg.Security.Feedback.AfterWrite {
		return nil
	}
	for _, bind := range feedbackConfigBinders {
		bind(configPath)
	}
	var (
		mu     sync.Mutex
		st     *store.Store
		offers feedbackOffers
	)
	// The pending offers survive a daemon restart (lane SEC-H2, audit
	// finding F3): written beside the node's posture files, owner-only.
	if resolved, rerr := config.ResolveGlobalPath(configPath); rerr == nil {
		path := filepath.Join(secposture.LayoutFor(resolved).Dir, feedbackPendingFile)
		offers.load = func() []secfeedback.PendingOffer {
			b, err := readFeedbackPending(path)
			if err != nil {
				return nil
			}
			return secfeedback.DecodePending(b)
		}
		offers.persist = func(p []secfeedback.PendingOffer) { writeFeedbackPending(path, p) }
	}
	open := func() (*store.Store, error) {
		mu.Lock()
		defer mu.Unlock()
		if st != nil {
			return st, nil
		}
		database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
		if err != nil {
			return nil, err
		}
		go func() {
			<-ctx.Done()
			_ = database.Close()
		}()
		st = store.New(database)
		return st, nil
	}
	return func(ctx context.Context, req secipc.FeedbackRequest) (secipc.FeedbackOffer, error) {
		s, err := open()
		if err != nil {
			return secipc.FeedbackOffer{}, err
		}
		if req.AckOffer != "" {
			offers.ackToken(ctx, s, req.AckOffer, time.Now())
			return secipc.FeedbackOffer{}, nil
		}
		return offers.offer(ctx, s, req, time.Now())
	}
}

// feedbackPendingFile names the pending offers' file in the security
// directory; feedbackPendingMaxBytes caps its read.
const (
	feedbackPendingFile     = "feedback-pending.json"
	feedbackPendingMaxBytes = 256 << 10
)

// readFeedbackPending reads the pending offers' file, capped (a larger
// file reads as none).
func readFeedbackPending(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, feedbackPendingMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > feedbackPendingMaxBytes {
		return nil, errors.New("feedback pending file too large")
	}
	return b, nil
}

// writeFeedbackPending replaces the pending offers' file (owner-only, a
// temporary file renamed over it). A failed write is dropped: the offers
// then live in memory only, and a restart offers their lines again.
func writeFeedbackPending(path string, offers []secfeedback.PendingOffer) {
	b, err := secfeedback.EncodePending(offers)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
	}
}

// feedbackOffers is the daemon's one owner of the feedback leases: the
// findings it put into a reply that no hook has acknowledged yet. One
// offer at a time, so two post hooks of one session never get the same
// line.
type feedbackOffers struct {
	mu     sync.Mutex
	leases secfeedback.Leases
	// pending are the offers whose answer was written to a hook that will
	// acknowledge it, by token (lane SEC-H2): held out of other replies
	// for secfeedback.PendingFor, acknowledged on the connection or late
	// on a fresh one, idempotently. load and persist (nil: memory only)
	// carry them across a daemon restart; loaded is set once load ran.
	pending map[string]secfeedback.PendingOffer
	load    func() []secfeedback.PendingOffer
	persist func([]secfeedback.PendingOffer)
	loaded  bool
}

// restore loads the pending offers once and holds their findings until
// each offer's window ends. Called with o.mu held.
func (o *feedbackOffers) restore(now time.Time) {
	if o.loaded {
		return
	}
	o.loaded = true
	if o.pending == nil {
		o.pending = map[string]secfeedback.PendingOffer{}
	}
	if o.load == nil {
		return
	}
	for _, p := range secfeedback.LivePending(o.load(), now) {
		o.pending[p.Token] = p
		o.leases.HoldUntil(p.IDs(), p.Until)
	}
}

// savePending prunes and writes the pending offers. Called with o.mu held.
func (o *feedbackOffers) savePending(now time.Time) {
	list := make([]secfeedback.PendingOffer, 0, len(o.pending))
	for _, p := range o.pending {
		list = append(list, p)
	}
	live := secfeedback.LivePending(list, now)
	o.pending = make(map[string]secfeedback.PendingOffer, len(live))
	for _, p := range live {
		o.pending[p.Token] = p
	}
	if o.persist != nil {
		o.persist(live)
	}
}

// recordFeedback records groups' findings as sent (the store re-reads
// open and unsent, so recording twice changes nothing). A failed write
// returns false: the lines are offered again, never lost.
func recordFeedback(ctx context.Context, s *store.Store, session string, groups map[string][]string) bool {
	for hash, group := range groups {
		if len(group) == 0 {
			continue
		}
		if _, err := s.TakeSecFeedback(ctx, store.SecFeedbackQuery{
			ProjectRootHash: hash, SessionID: session, IDs: group, Limit: len(group),
		}, time.Now()); err != nil {
			return false
		}
	}
	return true
}

// ackToken records the pending offer token names (a late acknowledgement,
// lane SEC-H2). An unknown or lapsed token records nothing.
func (o *feedbackOffers) ackToken(ctx context.Context, s *store.Store, token string, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.restore(now)
	p, ok := o.pending[token]
	if !ok || !now.Before(p.Until) {
		return
	}
	if !recordFeedback(ctx, s, p.Session, p.Groups) {
		return
	}
	o.leases.Settle(p.IDs())
	delete(o.pending, token)
	o.savePending(now)
}

// newFeedbackToken is a fresh offer token (128 random bits, hex).
func newFeedbackToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// offer leases the session's feedback findings under each spelling of the
// project root the hook may give (the commit scanner's WSL spelling of a
// stored Windows root too), leaving out what is already leased, and
// returns them with an Ack that records exactly those findings (a finding
// closed or excepted since is not recorded, and is not offered again).
// Unacknowledged, they lapse after secfeedback.LeaseFor and the next post
// hook gets them.
func (o *feedbackOffers) offer(ctx context.Context, s *store.Store, req secipc.FeedbackRequest, now time.Time) (secipc.FeedbackOffer, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.restore(now)
	roots := []string{req.ProjectRoot}
	if n := commitScanRoot(req.ProjectRoot); n != "" && n != req.ProjectRoot {
		roots = append(roots, n)
	}
	held := o.leases.Held(now)
	var (
		hits   []policy.SecurityHit
		ids    []string
		byRoot = map[string][]string{}
		asked  = map[string]bool{}
	)
	for _, root := range roots {
		if len(hits) >= secipc.MaxFeedbackFindings {
			break
		}
		hash := secposture.ProjectRootHash(root)
		if asked[hash] {
			continue
		}
		asked[hash] = true
		fs, err := s.TakeSecFeedback(ctx, store.SecFeedbackQuery{
			ProjectRootHash: hash, SessionID: req.SessionID, Lease: true,
			Exclude: slices.Concat(held, ids), Limit: secipc.MaxFeedbackFindings - len(hits),
		}, now)
		if err != nil {
			return secipc.FeedbackOffer{}, err
		}
		for _, f := range fs {
			if slices.Contains(ids, f.ID) {
				continue
			}
			ids = append(ids, f.ID)
			byRoot[hash] = append(byRoot[hash], f.ID)
			hits = append(hits, feedbackHit(f))
		}
	}
	if len(ids) == 0 {
		return secipc.FeedbackOffer{}, nil
	}
	o.leases.Hold(ids, now)
	token := newFeedbackToken()
	ack := func(ctx context.Context) {
		// A failed write leaves the lease to lapse: the line is offered
		// again, never lost.
		if !recordFeedback(ctx, s, req.SessionID, byRoot) {
			return
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		o.leases.Settle(ids)
		if _, ok := o.pending[token]; ok {
			delete(o.pending, token)
			o.savePending(time.Now())
		}
	}
	// Pending: the answer reached a hook that will acknowledge it, so the
	// lines stay out of other replies for the pending window and the
	// token is kept on disk (lane SEC-H2, audit finding F3).
	pending := func(context.Context) {
		if token == "" {
			return
		}
		at := time.Now()
		o.mu.Lock()
		defer o.mu.Unlock()
		until := at.Add(secfeedback.PendingFor)
		o.leases.HoldUntil(ids, until)
		o.pending[token] = secfeedback.PendingOffer{Token: token, Session: req.SessionID, Groups: byRoot, Until: until}
		o.savePending(at)
	}
	return secipc.FeedbackOffer{Hits: hits, Ack: ack, Token: token, Pending: pending}, nil
}

// feedbackHit is a finding's rule data as a hit (no message, evidence or
// fix-hint text crosses the endpoint). The rule id crosses only when
// feedbackRuleNamed knows it from Observer's compiled tables (audit finding
// F5); otherwise it is left empty and the line names the category.
func feedbackHit(f secfinding.Finding) policy.SecurityHit {
	path := f.Location.RelPath
	if len(path) > policy.SecurityHitPathMax {
		path = path[:policy.SecurityHitPathMax]
	}
	rule := ""
	if feedbackRuleNamed(f.Rule.Pack, f.Rule.ID) {
		rule = f.Rule.ID
	}
	return policy.SecurityHit{
		Category: f.Category, Severity: f.Severity, Confidence: f.Confidence, Baseline: f.Baseline,
		RuleID: rule, Path: path, Line: f.Location.StartLine,
	}
}

// feedbackRuleTables is the boundary check of audit finding F5 (lane
// sec-polish): per native rule pack, whether a rule id is one that
// Observer's own compiled tables produce. A pack with no row (an engine's
// SARIF, a custom driver, an advisory database) or an id its row does not
// know is never named in a feedback line: the line names the category.
// The rows of a tag-gated module are added by that module's own file
// (security_feedback_trust.go, security_feedback_deps.go,
// security_feedback_custom.go), so a build without the module neither
// links its tables nor names its rules. Written only at package init.
var feedbackRuleTables = map[string]func(id string) bool{
	// secret.<type> for a detector type the secret table names.
	"security.secrets": feedbackSecretRule,
	// ci.<id> of the workflow rule table, code.<id> of the diff
	// observation table, both lower-cased.
	"security.code": feedbackCodeRule,
}

// feedbackConfigBinders run once the daemon's feedback answerer is built,
// with its config path: a module row whose table lives in a file the
// daemon reads (the verified code rule pack, security_feedback_codepack.go)
// learns where to read it. Written only at package init.
var feedbackConfigBinders []func(configPath string)

// feedbackRuleNamed reports whether the rule id of a finding from pack may
// be named in a feedback line.
func feedbackRuleNamed(pack, id string) bool {
	known := feedbackRuleTables[pack]
	return known != nil && id != "" && known(id)
}

// feedbackSecretRule knows secret.<type> for every type the secret
// detector table puts into words (an unknown type falls back to the
// table's default words).
func feedbackSecretRule(id string) bool {
	t, ok := strings.CutPrefix(id, secdetect.SecretRulePrefix)
	return ok && t != "" && secdetect.TypeWords(t) != secdetect.TypeWords("")
}

// feedbackCodeRule knows the security.code ids the workflow rules and the
// diff observations produce.
func feedbackCodeRule(id string) bool {
	if rest, ok := strings.CutPrefix(id, "ci."); ok {
		return slices.ContainsFunc(secciwf.Rules, func(r secciwf.Rule) bool { return strings.ToLower(r.ID) == rest })
	}
	if rest, ok := strings.CutPrefix(id, "code."); ok {
		return slices.ContainsFunc(secdiffobs.Rules, func(r secdiffobs.Rule) bool { return strings.ToLower(r.ID) == rest })
	}
	return false
}

// feedbackPostBinding returns the post-phase context_inject binding of
// tool's native event whose dialect has a reply writer.
func feedbackPostBinding(tool, event string) (integration.HookBinding, bool) {
	c, ok := integration.For(tool)
	if !ok {
		return integration.HookBinding{}, false
	}
	for _, b := range c.Hook.Bindings {
		if b.NativeEvent == event && b.Cap == integration.HookCapContextInject && b.Phase == integration.HookPhasePost &&
			secfeedback.Supported(b.Dialect) {
			return b, true
		}
	}
	return integration.HookBinding{}, false
}

// feedbackGateDialects are the tool-gate extractors a post payload is read
// with, in order: the row's own tool-gate dialects (the post payload names
// the tool, its input, the session and the root as the pre-tool one does;
// a row can carry several transports, such as Cline CLI's plugin gate and
// its file hook), then the generic {tool_name, tool_input} extractor (the
// plugin shim's envelope).
func feedbackGateDialects(tool string) []string {
	var out []string
	if c, ok := integration.For(tool); ok {
		for _, b := range c.Hook.Bindings {
			if b.Cap == integration.HookCapToolGate && hook.IsToolGateDialect(b.Dialect) && !slices.Contains(out, b.Dialect) {
				out = append(out, b.Dialect)
			}
		}
	}
	if !slices.Contains(out, hook.ToolGateDialectClaudeJSON) {
		out = append(out, hook.ToolGateDialectClaudeJSON)
	}
	return out
}

// feedbackGateEvents reads a post payload with the first of
// feedbackGateDialects that extracts an event from it.
func feedbackGateEvents(tool, event string, body []byte) ([]policy.Event, bool) {
	for _, d := range feedbackGateDialects(tool) {
		if evs, ok := hook.ToolGateEvents(tool, d, event, body); ok && len(evs) > 0 {
			return evs, true
		}
	}
	return nil, false
}

// hookFeedbackSelected reports whether security.feedback is selected: first
// in the invocation's component snapshot (the same component state the
// registration writers use, already resolved by the adapter gate, so an
// unselected install, every install with no [components] block, decides
// here without reading the posture or checking its MAC), then in the signed
// guard posture, which must say the security module is active with
// security.feedback in its pack set: the daemon signs only selected
// children into that set (securityActivePacks).
func hookFeedbackSelected(configPath string) bool {
	if !securitySelected(hookInvocationComponents(configPath), securityFeedbackComponent) {
		return false
	}
	s := currentHookSecurity(configPath)
	return s.module == secposture.ModuleActive && slices.Contains(s.packs, securityFeedbackComponent)
}

// feedbackOptInRoute reports whether runHookInvocation serves (tool, event)
// with handlePostFeedbackHook ahead of the tool's own receiver: a post-phase
// context_inject binding Observer registers only for a component
// (RegisterWhen set: Gemini CLI AfterTool, Qwen Code and Qoder PostToolUse,
// the Cline PostToolUse file hook, the plugin shim's tool.execute.after)
// while that component is selected. The bindings Observer registers anyway
// (Claude Code, Codex, Cursor) carry no RegisterWhen and keep their own
// receivers, which call securityPostFeedback. Not selected, the invocation
// goes where it always went, so its reply is unchanged.
func feedbackOptInRoute(tool, event, configPath string) bool {
	b, ok := feedbackPostBinding(tool, event)
	return ok && b.RegisterWhen != "" && hookFeedbackSelected(configPath)
}

// securityPostFeedback is the ONE post-tool feedback seam for a handler
// that has its reply in hand: it writes reply (the host's own bytes) to w,
// with the feedback lines merged in, and acknowledges the daemon's lease
// only once that write succeeded (lane sec-polish, audit finding F3). While
// security.feedback is not selected, or tool's event has no post context
// binding, or there is nothing to say, reply is written unchanged and
// nothing is asked. Any failure gives the agent no context; nothing here
// ever blocks.
func securityPostFeedback(ctx context.Context, w io.Writer, tool, event string, body, reply []byte, configPath string) {
	_, _ = securityPostFeedbackWriter(ctx, w, tool, event, body, configPath).Write(reply)
}

// securityFeedbackLines asks the daemon for the session's feedback
// findings; when the daemon does not answer at all (not running, endpoint
// missing), it scans the written content in the hook with the secret rows
// (internal/secdetect at the hook's 16 KiB cap), the only facts the hook
// can establish alone. A daemon that answers, even with nothing or with a
// refusal, is the answer: the fallback never second-guesses it. The
// daemon's answer comes with its lease (nil for the fallback or no lines):
// the caller acknowledges it once the reply carrying the lines is written,
// or closes it.
func securityFeedbackLines(ctx context.Context, tool, event string, body []byte, configPath string) ([]string, *secipc.FeedbackLease) {
	p, ok := decodeObservePayload(body)
	if !ok {
		return nil, nil
	}
	sessionID, cwd := p.SessionID, p.Cwd
	// A payload whose session and root sit where the host's tool-gate
	// dialect reads them (the Cline file hook's taskId /
	// sessionContext.sessionId and workspaceRoots).
	for _, d := range feedbackGateDialects(tool) {
		if sessionID != "" && cwd != "" {
			break
		}
		sid, dir, root, ok := hook.ToolGatePayloadContext(d, body)
		if !ok {
			continue
		}
		if sessionID == "" {
			sessionID = sid
		}
		if cwd == "" {
			cwd = dir
		}
		if cwd == "" {
			cwd = root
		}
	}
	// hookProjectRoot reads the relay run's project first (hookctx), so a
	// relayed event asks for the run's project, never a box's directory.
	root := hookProjectRoot(&policy.Event{Cwd: cwd})
	if root == "" || sessionID == "" {
		return nil, nil
	}
	var lease *secipc.FeedbackLease
	s := currentHookSecurity(configPath)
	ep, err := secipc.Endpoint(s.layout.Dir)
	if err == nil {
		actx, cancel := context.WithTimeout(ctx, hookFeedbackAskLimit)
		lease, err = secipc.AskFeedbackLease(actx, ep, secipc.FeedbackRequest{ProjectRoot: root, SessionID: sessionID}, hookFeedbackAskLimit)
		cancel()
	}
	if err != nil {
		if errors.Is(err, secipc.ErrFeedbackDeclined) {
			return nil, nil
		}
		return secfeedback.Lines(feedbackFindings(securityFeedbackFallback(tool, event, body, root, configPath))), nil
	}
	lines := secfeedback.Lines(feedbackFindings(lease.Hits()))
	if len(lines) == 0 {
		lease.Close()
		return nil, nil
	}
	return lines, lease
}

// securityFeedbackFallback is the in-hook fallback: the secret rows over
// the payload's written content, high confidence only, while
// [security.feedback].after_write is on.
func securityFeedbackFallback(tool, event string, body []byte, root, configPath string) []policy.SecurityHit {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil || !cfg.Security.Feedback.AfterWrite {
		return nil
	}
	for _, bind := range feedbackConfigBinders {
		bind(configPath)
	}
	events, ok := feedbackGateEvents(tool, event, body)
	if !ok {
		return nil
	}
	var out []policy.SecurityHit
	for i := range events {
		pe := events[i]
		if pe.ProjectRoot == "" {
			pe.ProjectRoot = root
		}
		hits, _ := secrules.PreWriteSecurity(&pe)
		for _, h := range hits {
			if h.Confidence != policy.FindingConfidenceHigh {
				continue
			}
			if !feedbackRuleNamed("security.secrets", h.RuleID) {
				h.RuleID = ""
			}
			out = append(out, h)
		}
	}
	return out
}

// feedbackFindings maps hits onto the line builder's input. A rule id the
// daemon sent was checked there (feedbackHit blanks any other); the
// in-hook fallback's hits come from the secret rows, checked the same way.
func feedbackFindings(hits []policy.SecurityHit) []secfeedback.Finding {
	out := make([]secfeedback.Finding, 0, len(hits))
	for _, h := range hits {
		out = append(out, secfeedback.Finding{
			RuleID: h.RuleID, RuleNamed: h.RuleID != "", Category: h.Category, Severity: h.Severity, Confidence: h.Confidence, Path: h.Path, Line: h.Line,
		})
	}
	return out
}

// securityPostFeedbackWriter returns w unchanged unless the seam has
// something to add for this event; then a writer that merges the lines
// into the host receiver's first JSON reply. The lines are fetched here,
// before the receiver writes, so the reply is never held open on the
// daemon; the daemon's lease is acknowledged only after that first write
// carried the lines and succeeded (a refused write, a reply the lines
// could not be merged into, or a receiver that never writes leaves it
// unacknowledged, and the daemon offers the lines again).
func securityPostFeedbackWriter(ctx context.Context, w io.Writer, tool, event string, body []byte, configPath string) io.Writer {
	b, ok := feedbackPostBinding(tool, event)
	if !ok || !hookFeedbackSelected(configPath) {
		return w
	}
	lines, lease := securityFeedbackLines(ctx, tool, event, body, configPath)
	if len(lines) == 0 {
		return w
	}
	return &feedbackReplyWriter{w: w, dialect: b.Dialect, event: event, lines: lines, lease: lease}
}

// feedbackReplyWriter merges the feedback lines into the first write and
// settles the daemon's lease on it.
type feedbackReplyWriter struct {
	w       io.Writer
	dialect string
	event   string
	lines   []string
	lease   *secipc.FeedbackLease
	done    bool
}

func (f *feedbackReplyWriter) Write(p []byte) (int, error) {
	if f.done {
		return f.w.Write(p)
	}
	f.done = true
	out, changed := secfeedback.Write(f.dialect, f.event, p, f.lines)
	if !changed {
		f.lease.Close()
		return f.w.Write(p)
	}
	if n, err := f.w.Write(out); err != nil || n != len(out) {
		f.lease.Close()
		if err == nil {
			err = io.ErrShortWrite
		}
		return 0, err
	}
	f.lease.Ack()
	return len(p), nil
}

// handlePostFeedbackHook serves a post-tool event that has a feedback
// binding but no receiver of its own (Gemini CLI AfterTool, Qwen Code and
// Qoder PostToolUse, the Cline PostToolUse file hook, the plugin shim's
// tool.execute.after): events Observer registers only while
// security.feedback is selected. The reply is the dialect's allow with the
// feedback merged in; with nothing to add (or the component deselected
// while a registration lingers) it is exactly the binding fallback's
// approve, so a leftover entry answers as it always did. Returns false when
// (tool, event) has no feedback binding.
func handlePostFeedbackHook(ctx context.Context, tool, event, label, configPath string, stdin io.Reader, stdout, stderr io.Writer) bool {
	b, ok := feedbackPostBinding(tool, event)
	if !ok {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(stdin, defaultHookBodyLimit))
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	noteHookPayload(body)
	var approve bytes.Buffer
	hook.HandleApprove(label, bytes.NewReader(body), &approve, stderr)
	if !hookFeedbackSelected(configPath) {
		_, _ = stdout.Write(approve.Bytes())
		return true
	}
	lines, lease := securityFeedbackLines(ctx, tool, event, body, configPath)
	if len(lines) == 0 {
		_, _ = stdout.Write(approve.Bytes())
		return true
	}
	// The dialect's allow with the lines merged in; the lease is
	// acknowledged only after that reply was written whole.
	out, changed := secfeedback.Write(b.Dialect, event, feedbackAllowReply(b.Dialect), lines)
	if !changed {
		lease.Close()
		_, _ = stdout.Write(approve.Bytes())
		return true
	}
	if n, err := stdout.Write(out); err != nil || n != len(out) {
		lease.Close()
		return true
	}
	lease.Ack()
	return true
}

// feedbackAllowReplies is the allow each feedback dialect's no-receiver
// host is answered with when there is feedback to carry: the reply shape
// its post-tool hook documents (an empty object; Claude-shaped hosts keep
// the approve). Keyed on the dialect, never on a tool.
var feedbackAllowReplies = map[string][]byte{
	secfeedback.DialectClaude: []byte(`{"decision":"approve"}` + "\n"),
	secfeedback.DialectGemini: []byte("{}\n"),
	secfeedback.DialectCline:  nil,
	secfeedback.DialectPlugin: []byte(`{"decision":"allow"}` + "\n"),
}

func feedbackAllowReply(dialect string) []byte {
	return append([]byte(nil), feedbackAllowReplies[dialect]...)
}
