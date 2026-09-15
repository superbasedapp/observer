// Package handoffsvc is the single boundary seam of the session-handoff
// feature (CLAUDE.md rule #2; plan §4): it composes the store substrate,
// the source adapter's transcript reader, the pure internal/handoff core,
// scrubbing, and delivery into one Build() entry that the CLI (and the P2
// dashboard/MCP surfaces) call. Callers receive a plain Result; handoff.*
// types do not spread past this package's signature.
package handoffsvc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/handoff"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TranscriptReader is the optional adapter capability (defined at the
// consumer, Go-style): re-read a session's normalized message stream from
// the source tool's own files. sourceHints are real paths the store
// observed; implementations DERIVE the path from session metadata when no
// hint resolves (Phase 0 D-P0.1).
type TranscriptReader interface {
	ReadTranscript(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error)
}

// FullTranscriptReader is the optional un-excerpted read capability: the
// same normalized stream as ReadTranscript but with tool_result bodies and
// message text emitted WHOLE (the source excerpt caps lifted). It backs
// the `full_cache` carry mode (the actual read content inlined into the
// handover) and the get_session_message MCP pull. Adapters that can serve
// full bodies implement it; the boundary dispatches on its presence
// (capability shape, CLAUDE.md rule #3) and falls back honestly to the
// capped reader otherwise. Nothing is persisted — bodies are re-read from
// the source tool's own files on demand.
type FullTranscriptReader interface {
	ReadTranscriptFull(ctx context.Context, sess models.Session, sourceHints []string) ([]models.TranscriptMessage, error)
}

// Substrate is the store surface Build needs (implemented by
// *store.Store; narrowed for tests). The final three methods back the
// best-effort target-session linker (LinkTargetSessions, link.go).
type Substrate interface {
	LoadHandoffSubstrate(ctx context.Context, sessionID string) (store.HandoffSubstrate, error)
	LoadSessionShape(ctx context.Context, sessionID string) (store.PredictShape, error)
	InsertHandoff(ctx context.Context, r store.HandoffRecord) (int64, error)
	ListUnlinkedHandoffs(ctx context.Context, since time.Time) ([]store.HandoffRecord, error)
	CandidateTargetSessions(ctx context.Context, tool, projectRoot string, after time.Time, limit int) ([]store.CandidateSession, error)
	LinkTargetSession(ctx context.Context, handoffID int64, targetSessionID string) error
}

// Deps carries the boundary dependencies, all injected.
type Deps struct {
	Store    Substrate
	Cfg      config.HandoffConfig
	Adapters []adapter.Adapter
	// Price prices input tokens on a model (backed by cost.ComputeBreakdown
	// rates at the CLI boundary; nil prices $0).
	Price handoff.PriceFunc
	// Scrub redacts the rendered payload (structure-safe for markdown text;
	// nil = no scrubbing — tests only).
	Scrub func(string) string
	// Stay, when non-nil, resolves the stay-option comparison for the
	// source session (plan §9: predict band + cachewarm value-at-risk,
	// composed at the cmd boundary). ok=false omits the row honestly.
	Stay func(ctx context.Context, sessionID string) (handoff.StayEstimate, bool)
	// ResolveTargetModel maps (sourceModel, targetTool) → a
	// target-appropriate model when the caller didn't pin one
	// (--target-model unset). It returns "" to fall back to the source
	// model — the honest default when the source tier or the target's
	// provider representative is unknown, or when source and target share
	// a provider shape (the source model is already correct). Injected at
	// the cmd boundary over the routing tier table; internal/handoffsvc and
	// pure internal/handoff never import internal/routing.
	ResolveTargetModel func(sourceModel, targetTool string) string
	// Now overrides time.Now for tests.
	Now func() time.Time
}

// ErrSessionNotFound reports an unknown source session id. Boundary
// callers (dashboard, MCP) map it to their own not-found shape.
var ErrSessionNotFound = errors.New("session not found")

// Request is one handoff invocation.
type Request struct {
	SessionID   string
	TargetTool  string
	TargetModel string
	Fork        handoff.ForkPoint
	Carry       handoff.CarryMode
	// Delivery selects the delivery lane (plan §10). Zero value =
	// integration.InjectFile (the universal floor; back-compatible with
	// callers that don't set it). Non-file lanes are validated against the
	// TARGET tool's integration.HandoffCapability — dispatch on capability
	// shape, never tool name (CLAUDE.md rule #3).
	Delivery integration.InjectKind
	// OutPath overrides the inject_file destination.
	OutPath string
	// DryRun computes the estimate + doc without writing anything —
	// no file, no handoffs row.
	DryRun bool
	// IncludeBoundaries adds the fork-picker rows (handoff.Boundaries
	// over the readable transcript, previews scrubbed) to the Result.
	IncludeBoundaries bool
}

// Result is the plain outcome callers render.
type Result struct {
	Doc     string
	DocPath string
	ShortID string
	// ProjectRoot is the source session's project root RESOLVED to a path
	// reachable from the daemon's OS (Build translates a foreign-OS path
	// like `C:\proj` to `/mnt/c/proj`). It is the directory the doc was
	// written into and the working directory a `--continue-from` launcher
	// starts the continued tool in. "" when the session had no project root.
	ProjectRoot string
	CarryUsed   handoff.CarryMode
	Fork        handoff.ForkResolution
	Estimate    handoff.EstimateResult
	TargetModel string
	// TargetTool echoes the requested target (for the armed-hook message).
	TargetTool string
	// Delivery is the lane the handoff was delivered on.
	Delivery integration.InjectKind
	// HookExpiresAt is set when Delivery == integration.InjectHook: the
	// armed handoff waits for the next target session until this time
	// (one-shot). Zero for every other lane.
	HookExpiresAt time.Time
	// DegradeReason explains a carry downgrade (e.g. no readable
	// transcript → metadata), "" when none. Honest-copy rule: it names
	// the exact missing capability.
	DegradeReason string
	HandoffID     int64
	// GitignoreHint is set when the doc landed inside a git repo whose
	// .gitignore lacks a HANDOFF pattern.
	GitignoreHint bool
	// Boundaries is the fork-picker view of the transcript (previews
	// scrubbed); nil unless Request.IncludeBoundaries was set and a
	// transcript was readable.
	Boundaries []handoff.Boundary
	// ContextWarning flags a likely context-window mismatch: the full carry
	// exceeds [handoff].context_warn_tokens, so the target tool's (often
	// unknown) default model may be too small to rehydrate it in one shot.
	// "" when there is no grounded concern. Advisory, never blocking.
	ContextWarning string
}

// Build runs one handoff end to end. Reversible by construction: it only
// reads the source tool's files, and writes one markdown file + one
// node-local handoffs row (neither on a dry run).
func Build(ctx context.Context, deps Deps, req Request) (Result, error) {
	var res Result
	if !deps.Cfg.Enabled {
		return res, fmt.Errorf("handoff is disabled ([handoff] enabled = false in config)")
	}
	now := time.Now
	if deps.Now != nil {
		now = deps.Now
	}

	sub, err := deps.Store.LoadHandoffSubstrate(ctx, req.SessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return res, fmt.Errorf("%w: %q", ErrSessionNotFound, req.SessionID)
	}
	if err != nil {
		return res, fmt.Errorf("handoffsvc.Build: %w", err)
	}

	// Cross-OS project-root resolution (docs/session-handoff.md; the same
	// boundary translation every adapter applies to a captured cwd before
	// git.Resolve). The source tool correctly records its OWN project root
	// in its OWN OS convention — e.g. a Windows-run Claude Code session
	// stores `C:\proj`. This handoff runs in the daemon's OS (WSL), so the
	// raw foreign path is unreachable here: writeDoc's stat-gate would fall
	// back to the daemon's cwd (wrong folder) and a launched continuation
	// would inherit it. Translate ONCE at the boundary (never-fail,
	// idempotent for a path already in this OS's convention) so the doc,
	// the gitignore hint, the rendered "Project:" line, the stored
	// handoff row, AND the launcher cwd all agree on the reachable path
	// (`C:\proj` -> `/mnt/c/proj`).
	sub.ProjectRoot = crossmount.TranslateForeignPath(sub.ProjectRoot)
	res.ProjectRoot = sub.ProjectRoot

	carry := req.Carry
	if carry == "" {
		carry = handoff.CarryMode(deps.Cfg.DefaultCarry)
	}
	if !handoff.ValidCarry(carry) {
		return res, fmt.Errorf("unknown carry mode %q (metadata|distilled|distilled_tail|full)", carry)
	}

	delivery := req.Delivery
	if delivery == "" {
		delivery = integration.InjectFile
	}
	if err := validateDeliveryLane(delivery, req.TargetTool); err != nil {
		return res, err
	}

	// full_cache carries the actual read content un-excerpted (inlined into
	// the handover), so it needs the FullTranscriptReader path; every other
	// carry reads capped excerpts.
	var transcript []models.TranscriptMessage
	carry, transcript, res.DegradeReason = resolveCarry(ctx, deps, sub, carry)
	if req.IncludeBoundaries {
		res.Boundaries = handoff.Boundaries(transcript)
		if deps.Scrub != nil {
			for i := range res.Boundaries {
				res.Boundaries[i].Preview = deps.Scrub(res.Boundaries[i].Preview)
			}
		}
	}

	forkRes, err := handoff.ResolveFork(transcript, req.Fork)
	if err != nil {
		return res, err
	}

	ex := handoff.Extract{
		SessionID:   sub.Session.ID,
		Tool:        sub.Session.Tool,
		Model:       sub.Session.Model,
		ProjectRoot: sub.ProjectRoot,
		GitBranch:   sub.Session.GitBranch,
		StartedAt:   sub.Session.StartedAt,
		EndedAt:     sub.Session.EndedAt,
		Transcript:  transcript,
		Files:       sub.Files,
		Commands:    sub.Commands,
		Errors:      sub.Errors,
	}
	if err := ex.Validate(); err != nil {
		return res, err
	}
	if shape, err := deps.Store.LoadSessionShape(ctx, req.SessionID); err == nil {
		ex.ContextTokens = shape.PrefixTokens
		if ex.Model == "" {
			ex.Model = shape.Model
		}
	}

	shortID := newShortID()
	maxDocBytes := deps.Cfg.MaxDocTokens * 4 // tokens ≈ bytes/4 (TokenEstimate)
	if carry == handoff.CarryFullCache {
		// full_cache inlines the un-excerpted read bodies by design, so the
		// tail-shrink doc budget must not fight it (its tail is the whole
		// conversation — shrinking TailMessages can't reduce it anyway).
		// Give it the full-cache byte budget; the safety truncation below
		// is the real bound.
		maxDocBytes = fullCacheBudget(deps.Cfg.MaxCacheBytes)
	}
	opts := handoff.Options{
		TargetTool:   req.TargetTool,
		Carry:        carry,
		TailMessages: deps.Cfg.TailMessages,
		MaxDocBytes:  maxDocBytes,
		Now:          now().UTC(),
		ShortID:      shortID,
	}
	doc := handoff.Distill(ex, forkRes, opts)
	rendered := handoff.RenderMarkdown(doc)
	if deps.Scrub != nil {
		rendered = deps.Scrub(rendered)
	}
	// full_cache safety cap: the only mode that inlines full read bodies.
	// Truncate a pathologically large doc with an honest note so it never
	// writes an unusable multi-hundred-MB prompt (docs/session-handoff.md).
	if carry == handoff.CarryFullCache {
		if capped, note := capCacheDoc(rendered, deps.Cfg.MaxCacheBytes); note != "" {
			rendered = capped
			if res.DegradeReason == "" {
				res.DegradeReason = note
			} else {
				res.DegradeReason += "; " + note
			}
		}
	}

	targetModel := resolveTargetModel(req, deps, ex.Model)
	estimate := buildEstimate(ex, forkRes, opts, targetModel, deps.Price, sourceHasFullReader(deps.Adapters, sub.Session.Tool))
	if deps.Stay != nil {
		if st, ok := deps.Stay(ctx, req.SessionID); ok {
			estimate.Stay = &st
		}
	}

	res.Doc = rendered
	res.ShortID = shortID
	res.CarryUsed = carry
	res.Fork = forkRes
	res.Estimate = estimate
	res.ContextWarning = handoff.ContextFitWarning(estimate, int64(deps.Cfg.ContextWarnTokens))
	res.TargetModel = targetModel
	res.TargetTool = req.TargetTool
	res.Delivery = delivery
	if res.DegradeReason == "" && doc.DegradeNote != "" {
		res.DegradeReason = doc.DegradeNote
	}
	if req.DryRun {
		return res, nil
	}

	if err := persistHandoff(ctx, deps, req, sub, carry, delivery, forkRes, transcript, rendered, estimate, shortID, now().UTC(), &res); err != nil {
		return res, err
	}
	return res, nil
}

// resolveCarry reads the source transcript for the requested carry mode and
// downgrades the mode when the source can't satisfy it, returning the effective
// carry, the transcript (nil when unavailable), and an honest degrade reason
// ("" when the mode was satisfied). Extracted from Build to keep that
// function's cyclomatic complexity in check.
func resolveCarry(ctx context.Context, deps Deps, sub store.HandoffSubstrate, carry handoff.CarryMode) (handoff.CarryMode, []models.TranscriptMessage, string) {
	preferFull := carry == handoff.CarryFullCache
	transcript, usedFull, degrade := readTranscript(ctx, deps, sub, preferFull)
	var degradeReason string
	if transcript == nil && carry != handoff.CarryMetadata {
		carry = handoff.CarryMetadata
		degradeReason = degrade
	}
	// full_cache requested but the source has no un-excerpted reader: fall
	// back to full (capped excerpts) with an honest note — the bodies
	// aren't available whole, but the whole conversation flow still crosses.
	if carry == handoff.CarryFullCache && !usedFull {
		carry = handoff.CarryFull
		degradeReason = fmt.Sprintf("%s has no un-excerpted (full-body) reader — full_cache degraded to full (excerpts)", sub.Session.Tool)
	}
	return carry, transcript, degradeReason
}

// persistHandoff writes the rendered doc to disk and records the handoff row.
// It mutates res with the on-disk path, gitignore hint, hook-expiry window, and
// the inserted handoff id. Extracted from Build to keep that function's
// cyclomatic complexity in check.
func persistHandoff(ctx context.Context, deps Deps, req Request, sub store.HandoffSubstrate, carry handoff.CarryMode, delivery integration.InjectKind, forkRes handoff.ForkResolution, transcript []models.TranscriptMessage, rendered string, estimate handoff.EstimateResult, shortID string, nowUTC time.Time, res *Result) error {
	path, err := writeDoc(sub.ProjectRoot, deps.Cfg.FileName, shortID, req.OutPath, rendered)
	if err != nil {
		return err
	}
	res.DocPath = path
	res.GitignoreHint = needsGitignoreHint(sub.ProjectRoot, path)

	// inject_hook arms the doc for the NEXT target session in this project:
	// the doc still lives only on disk (delivery_ref), the row records the
	// arming window. TTL bounds the wait so a stale handoff never fires
	// days later; first delivery marks it delivered (one-shot).
	var hookExpires time.Time
	if delivery == integration.InjectHook {
		ttl := deps.Cfg.HookTTLMinutes
		if ttl <= 0 {
			ttl = 240
		}
		hookExpires = nowUTC.Add(time.Duration(ttl) * time.Minute)
		res.HookExpiresAt = hookExpires
	}

	rec := store.HandoffRecord{
		SourceSessionID:  sub.Session.ID,
		SourceTool:       sub.Session.Tool,
		TargetTool:       orUnspecified(req.TargetTool),
		CarryMode:        string(carry),
		ForkKind:         forkKindLabel(req.Fork),
		ForkMessageIndex: forkRes.ResolvedIndex,
		ForkMessageTime:  forkRes.ForkTime,
		ForkAnchorHash:   anchorHash(transcript, forkRes),
		RequestedIndex:   forkRes.RequestedIndex,
		DocTokenEstimate: handoff.TokenEstimate(rendered),
		EstimateJSON:     estimateJSON(estimate),
		Delivery:         string(delivery),
		DeliveryRef:      path,
		ProjectRoot:      sub.ProjectRoot,
		HookExpiresAt:    hookExpires,
		ShortID:          shortID,
	}
	id, err := deps.Store.InsertHandoff(ctx, rec)
	if err != nil {
		return err
	}
	res.HandoffID = id
	return nil
}

// validateDeliveryLane checks the requested delivery lane against the
// TARGET tool's grounded handoff capability (CLAUDE.md rule #3: dispatch on
// capability shape, never `if tool == "claude-code"`). The universal file
// lane is always allowed. Any other lane must appear in the target's
// HandoffCapability.Inject set; an unsupported lane errors honestly, naming
// the tool and the lanes it does support.
func validateDeliveryLane(delivery integration.InjectKind, targetTool string) error {
	if delivery == integration.InjectFile {
		return nil
	}
	if targetTool == "" {
		return fmt.Errorf("the %s delivery lane needs an explicit target tool (--to)", delivery)
	}
	cap, ok := integration.For(targetTool)
	if !ok {
		return fmt.Errorf("the %s delivery lane is not available: unknown target tool %q", delivery, targetTool)
	}
	for _, k := range cap.Handoff.Lanes() {
		if k == delivery {
			return nil
		}
	}
	return fmt.Errorf("target tool %q does not support the %q handoff delivery lane (grounded lanes: %v)",
		targetTool, delivery, cap.Handoff.Lanes())
}

// readTranscript dispatches on the capability shape (CLAUDE.md rule #3):
// the registry row must claim a readable transcript AND the adapter must
// implement the reader. Failures degrade with an honest reason, never an
// error — metadata carry is always available.
func readTranscript(ctx context.Context, deps Deps, sub store.HandoffSubstrate, preferFull bool) (msgs []models.TranscriptMessage, usedFull bool, note string) {
	return readSessionTranscript(ctx, deps.Adapters, sub.Session, sub.SourceFiles, preferFull)
}

// readSessionTranscript is the SHARED reader dispatch used for both the
// source session (Build) and candidate TARGET sessions (the linker,
// link.go) — one implementation so the two paths can never diverge. It
// dispatches on capability shape (the registry row must claim a readable
// transcript AND the adapter must implement the reader). Failures return a
// nil slice with an honest reason, never an error.
//
// preferFull requests the un-excerpted read (the full_cache carry): when
// the adapter implements FullTranscriptReader the full bodies come
// through and usedFull is true; otherwise it falls back to the capped
// reader and usedFull stays false, so the caller can note the honest
// degrade (excerpts, not full bodies).
func readSessionTranscript(ctx context.Context, adapters []adapter.Adapter, sess models.Session, sourceHints []string, preferFull bool) (msgs []models.TranscriptMessage, usedFull bool, note string) {
	cap, _ := integration.For(sess.Tool)
	if cap.Handoff.Transcript == integration.TranscriptActionsOnly {
		return nil, false, fmt.Sprintf("%s has no readable transcript capability — metadata carry", sess.Tool)
	}
	var reader TranscriptReader
	var fullReader FullTranscriptReader
	for _, a := range adapters {
		if a.Name() != sess.Tool {
			continue
		}
		if r, ok := a.(TranscriptReader); ok {
			reader = r
		}
		if fr, ok := a.(FullTranscriptReader); ok {
			fullReader = fr
		}
		break
	}
	if preferFull && fullReader != nil {
		full, err := fullReader.ReadTranscriptFull(ctx, sess, sourceHints)
		if err != nil {
			return nil, false, fmt.Sprintf("transcript unreadable (%v) — metadata carry", err)
		}
		if len(full) == 0 {
			return nil, false, "transcript on disk holds no messages — metadata carry"
		}
		return full, true, ""
	}
	if reader == nil {
		return nil, false, fmt.Sprintf("%s transcript reader not implemented yet (classified %s) — metadata carry", sess.Tool, cap.Handoff.Transcript)
	}
	capped, err := reader.ReadTranscript(ctx, sess, sourceHints)
	if err != nil {
		return nil, false, fmt.Sprintf("transcript unreadable (%v) — metadata carry", err)
	}
	if len(capped) == 0 {
		return nil, false, "transcript on disk holds no messages — metadata carry"
	}
	return capped, false, ""
}

// resolveTargetModel picks the model the carry table is priced at. An
// explicit --target-model always wins. Otherwise the injected cross-family
// resolver maps the source model's tier to the target provider's
// representative (P2 routing-tier default); it returns "" for a same-shape
// or ungrounded target, and the honest fallback is the source model (a
// same-capability continuation).
func resolveTargetModel(req Request, deps Deps, sourceModel string) string {
	if req.TargetModel != "" {
		return req.TargetModel
	}
	if deps.ResolveTargetModel != nil {
		if m := deps.ResolveTargetModel(sourceModel, req.TargetTool); m != "" {
			return m
		}
	}
	return sourceModel
}

// buildEstimate renders the carry variants to weigh them (plan §9: the
// boundary measures, the pure layer prices).
func buildEstimate(ex handoff.Extract, res handoff.ForkResolution, opts handoff.Options, targetModel string, price handoff.PriceFunc, hasFullReader bool) handoff.EstimateResult {
	render := func(carry handoff.CarryMode) int64 {
		o := opts
		o.Carry = carry
		return handoff.TokenEstimate(handoff.RenderMarkdown(handoff.Distill(ex, res, o)))
	}
	metaTok := render(handoff.CarryMetadata)
	distTok := render(handoff.CarryDistilled)
	tailTok := render(handoff.CarryDistilledTail) - distTok
	if tailTok < 0 {
		tailTok = 0
	}
	return handoff.Estimate(handoff.EstimateInput{
		TargetModel:         targetModel,
		MetadataTokens:      metaTok,
		DistilledTokens:     distTok,
		TailTokens:          tailTok,
		ContextTokens:       ex.ContextTokens,
		ForkShare:           handoff.ForkShare(ex.Transcript, res),
		SourceHasFullReader: hasFullReader,
		Price:               price,
	})
}

// sourceHasFullReader reports whether the source tool's adapter implements the
// un-excerpted FullTranscriptReader that the full_cache carry needs. It is the
// same capability probe readSessionTranscript uses to pick the reader, hoisted
// so the estimate can price full_cache honestly (= full when absent).
func sourceHasFullReader(adapters []adapter.Adapter, tool string) bool {
	for _, a := range adapters {
		if a.Name() != tool {
			continue
		}
		_, ok := a.(FullTranscriptReader)
		return ok
	}
	return false
}

// fullCacheBudget resolves the doc-byte budget for the full_cache carry:
// the configured MaxCacheBytes, or a large fallback when it's 0 (uncapped)
// so the tail-degrade loop never fires on a full_cache doc.
func fullCacheBudget(maxCacheBytes int) int {
	if maxCacheBytes <= 0 {
		return 1 << 30 // 1 GiB — effectively uncapped for the degrade loop
	}
	return maxCacheBytes
}

// capCacheDoc truncates a full_cache doc at maxBytes (0 = uncapped),
// returning the (possibly truncated) doc and an honest note ("" when no
// truncation happened). Truncation is byte-bounded but rune-safe.
func capCacheDoc(rendered string, maxBytes int) (string, string) {
	if maxBytes <= 0 || len(rendered) <= maxBytes {
		return rendered, ""
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(rendered[cut]) {
		cut--
	}
	note := fmt.Sprintf("full_cache doc truncated at %d bytes ([handoff].max_cache_bytes) — the source read content exceeded the cap", maxBytes)
	return rendered[:cut] + "\n\n[…full_cache truncated at the byte cap…]\n", note
}

func writeDoc(projectRoot, nameTemplate, shortID, override, rendered string) (string, error) {
	path := override
	if path == "" {
		name := strings.ReplaceAll(orDefault(nameTemplate, "HANDOFF-{shortid}.md"), "{shortid}", shortID)
		dir := projectRoot
		if dir == "" || !dirExists(dir) {
			dir = "."
		}
		path = filepath.Join(dir, name)
	}
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		return "", fmt.Errorf("handoffsvc: write doc: %w", err)
	}
	return path, nil
}

func needsGitignoreHint(projectRoot, docPath string) bool {
	if projectRoot == "" || !dirExists(filepath.Join(projectRoot, ".git")) {
		return false
	}
	rel, err := filepath.Rel(projectRoot, docPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return false
	}
	gi, err := os.ReadFile(filepath.Join(projectRoot, ".gitignore"))
	if err != nil {
		return true
	}
	return !strings.Contains(string(gi), "HANDOFF")
}

func anchorHash(msgs []models.TranscriptMessage, res handoff.ForkResolution) string {
	if res.ResolvedIndex <= 0 || res.ResolvedIndex > len(msgs) {
		return ""
	}
	h := sha256.Sum256([]byte(msgs[res.ResolvedIndex-1].Text))
	return hex.EncodeToString(h[:])
}

func forkKindLabel(fp handoff.ForkPoint) string {
	if fp.Kind == handoff.ForkLast {
		return "last"
	}
	return string(fp.Kind)
}

func estimateJSON(e handoff.EstimateResult) string {
	b, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	return string(b)
}

func newShortID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano()%1_000_000)
	}
	return hex.EncodeToString(b[:])
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orUnspecified(v string) string {
	if v == "" {
		return "unspecified"
	}
	return v
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
