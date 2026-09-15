package copilotcli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// process-*.log line shapes (verified empirically on both WSL and
// Windows-side log captures, 2026-05-17):
//
//	2026-05-17T09:28:27.900Z [INFO] Workspace initialized: <uuid> (checkpoints: 0)
//	2026-05-17T09:28:29.893Z [INFO] Using default model: gpt-5-mini
//	2026-05-17T09:28:38.632Z [INFO] CompactionProcessor: Utilization 14.9% (19052/128000 tokens) below threshold 80%
//	2026-05-17T10:08:24.316Z [DEBUG] response (Request-ID 00000-…):
//	2026-05-17T10:08:24.316Z [DEBUG] data:
//	2026-05-17T10:08:24.316Z [DEBUG] {
//	  "id": "...",
//	  "choices": [...],
//	  "usage": {
//	    "completion_tokens": 565,
//	    "prompt_tokens": 15474,
//	    "total_tokens": 16039,
//	    "prompt_tokens_details": {
//	      "cached_tokens": 2560
//	    },
//	    "completion_tokens_details": {
//	      "reasoning_tokens": 448
//	    }
//	  }
//	}
//
// Continuation lines (inside the multi-line JSON dump) DO NOT carry
// the timestamp/level prefix — they're raw JSON formatting from
// `JSON.stringify(obj, null, 2)`. Brace-counting / line-prefix-match
// is the simplest way to delimit response blocks.
//
// Modern Copilot CLI (1.0.60+) serving Anthropic-via-Bedrock turns adds
// `cache_creation_tokens` next to `cached_tokens` inside
// `prompt_tokens_details`, and a literal `Request-ID null` header (the
// real id moved to events.jsonl). Then `prompt_tokens` is the GROSS prompt
// = input + cached_tokens (cache read) + cache_creation_tokens (cache
// write); see emitTokenEvent for the net-out and resolveRequestIDsFromSibling
// Events for the id recovery.

var (
	reWorkspaceInit = regexp.MustCompile(`\[INFO\] Workspace initialized: ([0-9a-f-]{36})`)
	reDefaultModel  = regexp.MustCompile(`\[INFO\] Using default model: (\S+)`)
	reUtilization   = regexp.MustCompile(`\[INFO\] CompactionProcessor: Utilization [\d.]+% \((\d+)/(\d+) tokens\)`)
	// reResponseModel matches the top-level `"model": "<id>"` field inside
	// a `[DEBUG] response …` JSON body. Some process logs never emit the
	// `[INFO] Using default model: …` line (e.g. resumed sessions), so the
	// response body is the in-band recovery for an otherwise-empty model.
	reResponseModel = regexp.MustCompile(`^\s*"model":\s*"([^"]+)"`)
	// reResponseHdr matches the `[DEBUG] response (Request-ID …):`
	// header that opens each Tier-1 usage block. Empirically Copilot
	// CLI emits Request-IDs in TWO distinct formats interleaved in the
	// same session (operator sample, 2026-05-18):
	//   - `00000-<uuid>` (lowercase-hex-uuid; 8.1% of asst.message rids)
	//   - `<HEX>:<HEX>:<HEX>:<HEX>:<HEX>` (uppercase-hex with colons;
	//     91.9% of asst.message rids — the dominant production format)
	// The original v1.6.6 regex `[0-9a-f-]+` only captured the uuid
	// shape, silently dropping Tier-1 coverage for the hex-colon format.
	// The permissive `[^\s)]+` captures anything up to whitespace or
	// the closing paren — the format-agnostic shape. See
	// docs/copilot-cli-audit-2026-05-18.md §B3.
	reResponseHdr   = regexp.MustCompile(`\[DEBUG\] response \(Request-ID ([^\s)]+)\):`)
	rePromptTokens  = regexp.MustCompile(`^\s*"prompt_tokens":\s*(\d+)`)
	reCompletionTok = regexp.MustCompile(`^\s*"completion_tokens":\s*(\d+)`)
	reTotalTokens   = regexp.MustCompile(`^\s*"total_tokens":\s*(\d+)`)
	reCachedTokens  = regexp.MustCompile(`^\s*"cached_tokens":\s*(\d+)`)
	// reCacheCreationTok matches the `"cache_creation_tokens"` field that
	// modern Copilot CLI (Anthropic-via-Bedrock served turns) emits inside
	// `prompt_tokens_details` alongside `cached_tokens`. `prompt_tokens` is
	// the GROSS prompt = input + cached_tokens (cache read) + this
	// cache_creation (cache write); see emitTokenEvent for the net-out.
	reCacheCreationTok = regexp.MustCompile(`^\s*"cache_creation_tokens":\s*(\d+)`)
	reReasoningTok     = regexp.MustCompile(`^\s*"reasoning_tokens":\s*(\d+)`)
	reTimestampLine    = regexp.MustCompile(`^20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)
)

// logParserState carries log-level context across lines.
type logParserState struct {
	sessionID          string
	model              string
	pendingUtilization int64 // last seen prompt-side utilization (Tier 2 estimate)
	currentRequestID   string
	currentUsage       usageAccum
	inResponseBlock    bool
	// Pre-block tracking: when we encounter `response (Request-ID …):`
	// we may not see the usage immediately — the JSON dump can be very
	// large (~10 KB of encrypted blob). Brace-counting tells us when
	// we're inside the response JSON.
	braceDepth int
	// requestSeq counts response blocks per Request-ID so SourceEventID
	// stays unique across the N response blocks that share one
	// Request-ID (one WebSocket connection can carry multiple
	// response.create calls before closing).
	requestSeq map[string]int
	// seenDebugResponseHeader is set the first time a
	// `[DEBUG] response (Request-ID …):` line fires. When true at
	// end-of-parse, debug logging is on and Tier 1 (full usage)
	// covers every request — pendingTier2 is dropped to avoid
	// double-counting. When false (INFO-only logging), Tier 1 can't
	// fire and pendingTier2 is appended to the result so InputTokens
	// is captured via the utilization-snapshot estimate.
	seenDebugResponseHeader bool
	// pendingTier2 buffers utilization-derived TokenEvents that will
	// only be flushed if !seenDebugResponseHeader at end-of-parse.
	pendingTier2 []models.TokenEvent
}

// usageAccum holds in-flight usage extraction for the current response.
type usageAccum struct {
	prompt        int64
	completion    int64
	total         int64
	cached        int64
	cacheCreation int64
	reasoning     int64
	// model is the per-block model recovered from the response body's
	// top-level "model" field. Preferred over the session-level st.model
	// at emit time so a session that switched models mid-stream attributes
	// each Tier-1 row to the model that actually served it.
	model string
	ts    time.Time
}

func (u usageAccum) hasAny() bool {
	return u.prompt > 0 || u.completion > 0 || u.cached > 0 || u.cacheCreation > 0 || u.reasoning > 0
}

// parseProcessLog scans a Copilot CLI per-process log file and emits
// per-Request-ID TokenEvents. Always re-scans from byte 0 to rebuild
// session-id + model context; only emits events whose source position
// is at or past fromOffset (downstream dedups by SourceEventID).
//
// Tier 1: parse `[DEBUG] response (Request-ID …):` blocks → full
// usage breakdown.
// Tier 2: derive input-token estimates from
// `CompactionProcessor: Utilization X% (CTX/128000 tokens)` lines when
// no debug-level usage block is present for a given Request-ID. (Tier 2
// is best-effort; deferred to a follow-up if accuracy turns out
// problematic — Tier 1 is the load-bearing case.)
func (a *Adapter) parseProcessLog(_ context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return adapter.ParseResult{NewOffset: fromOffset}, nil
		}
		return adapter.ParseResult{}, fmt.Errorf("copilotcli.parseProcessLog open %q: %w", path, err)
	}
	defer f.Close()

	var (
		out    adapter.ParseResult
		offset int64
	)
	st := &logParserState{requestSeq: map[string]int{}}
	br := bufio.NewReader(f)
	for {
		line, readErr := br.ReadString('\n')
		hasTerminator := readErr == nil
		lineStart := offset
		offset += int64(len(line))
		clean := strings.TrimRight(line, "\r\n")
		if clean != "" {
			processLogLine(st, clean, parseLineTimestamp(clean), path, lineStart, fromOffset, &out)
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if !hasTerminator && len(line) > 0 {
					offset = lineStart
				}
				break
			}
			return adapter.ParseResult{}, fmt.Errorf("copilotcli.parseProcessLog read %q: %w", path, readErr)
		}
	}

	// If we ended in-block with a pending usage, flush it.
	if st.inResponseBlock && st.currentUsage.hasAny() && st.currentRequestID != "" {
		emitTokenEvent(st, path, &out)
	}

	// Tier 2 flush: only when --log-level is NOT debug (no [DEBUG]
	// response (Request-ID …) line fired in this file). Otherwise
	// Tier 1 covered every request via the upstream usage block and
	// the buffered Tier 2 estimates would double-count. The Utilization
	// line fires once per outgoing request and its raw value is the
	// gross prompt size — emit one TokenEvent per sample as the input
	// estimate. Cache split is unknown (estimate over-charges the
	// cached portion) → reliability='approximate' at ~5%. The
	// matching Tier 3 (events.jsonl) row provides OutputTokens with
	// its own MessageID; the two rows are joined at the rollup layer
	// rather than at the TokenEvent level.
	if !st.seenDebugResponseHeader && len(st.pendingTier2) > 0 {
		out.TokenEvents = append(out.TokenEvents, st.pendingTier2...)
	}

	// Derive ProjectRoot + GitBranch by reading the sibling
	// workspace.yaml. The log file lives at
	// `<home>/.copilot/logs/process-*.log`; the corresponding session
	// state is at `<home>/.copilot/session-state/<sessionID>/workspace.yaml`.
	// The store.Ingest layer requires a non-empty ProjectRoot to insert
	// TokenEvents for a session it hasn't seen in the same batch, so
	// without this the log-parser-only path silently drops every
	// upserted token row (Tier 1 then never lands in DB).
	ws := resolveProjectFromSibling(path, st.sessionID)
	projectRoot, branch, remote, identity := ws.ProjectRoot, ws.Branch, ws.Remote, ws.Identity

	// Capture surface — the same workspace.yaml read also carries the
	// client that drove the session (see surface.go). Stamped from the
	// log lane too, not only from events.jsonl: a process log can be
	// the first (or only) file the watcher reaches for a session, and
	// SetSessionSurface is first-wins-unless-empty, so a duplicate
	// stamp from the other lane is a no-op.
	if surf, ok := surfaceForClientName(st.sessionID, ws.ClientName); ok {
		out.SessionSurfaces = append(out.SessionSurfaces, surf)
	}

	// Some process logs never emit `[INFO] Using default model: …` and carry
	// no response-body model either. Fall back to the sibling
	// session-state/<id>/events.jsonl selectedModel so Tier-1 rows don't land
	// unpriced as unknown-model.
	if st.model == "" {
		st.model = resolveModelFromSiblingEvents(path, st.sessionID)
	}

	// Set SessionID / Model / ProjectRoot / GitBranch on emitted events.
	for i := range out.TokenEvents {
		if out.TokenEvents[i].SessionID == "" {
			out.TokenEvents[i].SessionID = st.sessionID
		}
		if out.TokenEvents[i].Model == "" {
			out.TokenEvents[i].Model = st.model
		}
		if out.TokenEvents[i].ProjectRoot == "" {
			out.TokenEvents[i].ProjectRoot = projectRoot
		}
		if out.TokenEvents[i].GitBranch == "" {
			out.TokenEvents[i].GitBranch = branch
		}
		if out.TokenEvents[i].GitRemote == "" {
			out.TokenEvents[i].GitRemote = remote
		}
	}
	adapter.ApplyProjectIdentity(&out, identity)

	// Recover the real Request-ID for modern Copilot CLI (1.0.60+) Tier-1
	// rows. The modern process log emits `[DEBUG] response (Request-ID null)`,
	// so reResponseHdr captures the literal "null" instead of the hex:colon
	// Request-ID the older format printed inline. The sibling events.jsonl
	// assistant.message still records it as `requestId`; recover it onto the
	// otherwise-"null" Tier-1 MessageID so the messages timeline shows the
	// real id AND the Tier-1 (otel) row's MessageID matches the Tier-3
	// (events.jsonl) row's — which restores the store-layer
	// (session_id, message_id) sweep that drops the output-only shadow at
	// ingest (store.InsertTokenEvents). Only scan the sibling when a "null"
	// row is actually present, so old-format logs pay nothing.
	needsRequestIDRecovery := false
	for i := range out.TokenEvents {
		if out.TokenEvents[i].MessageID == "null" {
			needsRequestIDRecovery = true
			break
		}
	}
	if needsRequestIDRecovery {
		recoverNullRequestIDs(out.TokenEvents, resolveRequestIDsFromSiblingEvents(path, st.sessionID))
	}

	out.NewOffset = offset
	return out, nil
}

// workspaceMeta is the decoded subset of a session's workspace.yaml
// this adapter consumes. Every field is optional — the zero value is
// the honest "the file was missing or said nothing", never a guess.
type workspaceMeta struct {
	// ProjectRoot is the git-resolved repo root (or the stated
	// git_root/cwd when git.Resolve found nothing).
	ProjectRoot string
	// Branch is the stated `branch`, or the one git.Resolve found.
	Branch string
	// Remote is the normalized "origin" remote, "" when unknown.
	Remote string
	// ClientName is the verbatim `client_name` line — the capture-
	// surface discriminator resolved by surfaceForClientName (see
	// surface.go). Absent on older Copilot CLI builds.
	ClientName string
	// Identity is the Project Identity Resolver v2 bundle for the
	// git-resolved root (zero value when no repo was found).
	Identity git.Identity
}

// resolveProjectFromSibling reads the sibling workspace.yaml for a
// log file and returns the decoded workspaceMeta (project root, branch,
// remote, client_name capture-surface discriminator, and the Project
// Identity Resolver v2 bundle).
//
// The log file lives at `<home>/.copilot/logs/process-*.log`; the
// session-state dir is at `<home>/.copilot/session-state/<sessionID>/`.
func resolveProjectFromSibling(logPath, sessionID string) workspaceMeta {
	if sessionID == "" {
		return workspaceMeta{}
	}
	// <home>/.copilot/logs/...log → <home>/.copilot
	copilotRoot := filepath.Dir(filepath.Dir(logPath))
	yamlPath := filepath.Join(copilotRoot, "session-state", sessionID, "workspace.yaml")
	return resolveProjectFromWorkspaceYAML(yamlPath)
}

// resolveProjectFromWorkspaceYAML reads a Copilot CLI workspace.yaml at
// the given path. Returns the zero workspaceMeta when the file is
// missing; ProjectRoot stays "" when it carries no usable git_root/cwd,
// independently of whether ClientName was stated. Path candidates are
// translated through crossmount.TranslateForeignPath for WSL2 <-> Windows
// session capture, then resolved through git.ResolveIdentity to find the
// actual repo root; Remote is the normalized "origin" remote when a repo
// was found, and "" otherwise (honest gap, not fabricated). Identity is
// the Project Identity Resolver v2 bundle for that same resolution (zero
// value when no repo was found); the root-commit exec is left nil,
// matching every other adapter call site.
//
// workspace.yaml carries `cwd`, `git_root`, `branch`, `client_name` as
// simple `key: value` lines — flat enough to parse without a YAML lib.
// (`name` is the session's first prompt and can be a multi-line quoted
// scalar; it is deliberately not decoded, and its continuation lines
// carry no `key:` shape this parser would mistake for one.)
//
// This is the ONE reader of workspace.yaml. Both parseProcessLog and
// parseEventsJSONL go through it: the events.jsonl path needs the
// project root because some Copilot CLI sessions log a drive-root cwd
// (e.g. "E:\\") in session.start.context while workspace.yaml carries
// the actual repo root, and both paths need `client_name` for the
// capture-surface stamp.
func resolveProjectFromWorkspaceYAML(yamlPath string) workspaceMeta {
	f, err := os.Open(yamlPath)
	if err != nil {
		return workspaceMeta{}
	}
	defer f.Close()
	var cwd, gitRoot string
	var out workspaceMeta
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		k, v, ok := splitYAMLLine(line)
		if !ok {
			continue
		}
		switch k {
		case "cwd":
			cwd = v
		case "git_root":
			gitRoot = v
		case "branch":
			out.Branch = v
		case "client_name":
			out.ClientName = v
		}
	}
	candidate := gitRoot
	if candidate == "" {
		candidate = cwd
	}
	if candidate == "" {
		return out
	}
	translated := crossmount.TranslateForeignPath(candidate)
	if translated == "" {
		translated = candidate
	}
	// STAT-GATE before git.ResolveIdentity (the goose / crush / freebuff
	// precedent): a (possibly cross-OS-translated) path that isn't locally
	// reachable falls through to the STATED path verbatim, not the /mnt
	// form. git.ResolveIdentity returns a non-existent path as its own
	// "root" with no error, so without this gate a Windows-side git_root
	// captured on a WSL host would persist as its /mnt/c translation
	// instead of the session's own canonical root. Identity stays zero
	// (populated only on a real git hit below).
	if _, err := os.Stat(translated); err != nil {
		out.ProjectRoot = candidate
		return out
	}
	info, err := git.ResolveIdentity(translated, git.IdentityOptions{})
	if err == nil && info.Root != "" {
		if info.Branch != "" && out.Branch == "" {
			out.Branch = info.Branch
		}
		out.ProjectRoot = info.Root
		// info.Remote is already NormalizeRemote'd by ResolveIdentity.
		out.Remote = info.Remote
		out.Identity = info
		return out
	}
	out.ProjectRoot = candidate
	return out
}

func splitYAMLLine(line string) (key, value string, ok bool) {
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	value = strings.Trim(value, `'"`)
	return key, value, true
}

//nolint:gocyclo // one branch per copilot-cli log-line shape by design; complexity tracks the upstream format's variant count, not logic depth.
func processLogLine(st *logParserState, line string, ts time.Time, path string, lineStart, fromOffset int64, out *adapter.ParseResult) {
	// Session identity / model — always update state regardless of
	// fromOffset so subsequent emits have correct context.
	if m := reWorkspaceInit.FindStringSubmatch(line); m != nil {
		st.sessionID = m[1]
	}
	if m := reDefaultModel.FindStringSubmatch(line); m != nil && st.model == "" {
		st.model = normalizeResponseModelCandidate(m[1])
	}
	if m := reUtilization.FindStringSubmatch(line); m != nil {
		v, _ := strconv.ParseInt(m[1], 10, 64)
		st.pendingUtilization = v
		// Buffer a Tier 2 candidate. Whether it lands depends on
		// st.seenDebugResponseHeader at end-of-parse — see the
		// pendingTier2 flush in parseProcessLog.
		if v > 0 && lineStart >= fromOffset {
			st.pendingTier2 = append(st.pendingTier2, models.TokenEvent{
				SourceFile:    path,
				SourceEventID: fmt.Sprintf("logdelta:%d", lineStart),
				Timestamp:     ts,
				Tool:          models.ToolCopilotCLI,
				Model:         st.model,
				InputTokens:   v,
				Source:        models.TokenSourceLogDelta,
				Reliability:   models.ReliabilityApproximate,
			})
		}
	}

	// Response-block detection.
	if m := reResponseHdr.FindStringSubmatch(line); m != nil {
		st.seenDebugResponseHeader = true
		// New response — close any prior unfinished one (defensive).
		if st.inResponseBlock && st.currentUsage.hasAny() && st.currentRequestID != "" && lineStart >= fromOffset {
			emitTokenEvent(st, path, out)
		}
		st.currentRequestID = m[1]
		st.currentUsage = usageAccum{ts: ts}
		st.inResponseBlock = true
		st.braceDepth = 0
		return
	}

	// In-block tracking — brace count + extract usage fields.
	if !st.inResponseBlock {
		return
	}

	// New timestamped log line that's NOT inside the JSON dump signals
	// end of the response block. (DEBUG-level continuation lines are
	// the raw JSON without the timestamp prefix.)
	if reTimestampLine.MatchString(line) && !strings.Contains(line, "[DEBUG]") {
		// Block ended.
		if st.currentUsage.hasAny() && st.currentRequestID != "" && lineStart >= fromOffset {
			emitTokenEvent(st, path, out)
		}
		st.inResponseBlock = false
		st.currentRequestID = ""
		st.currentUsage = usageAccum{}
		return
	}

	// Track brace depth for end-of-block detection on closing }.
	for _, r := range line {
		switch r {
		case '{':
			st.braceDepth++
		case '}':
			st.braceDepth--
		}
	}

	// Extract usage fields.
	if m := rePromptTokens.FindStringSubmatch(line); m != nil {
		v, _ := strconv.ParseInt(m[1], 10, 64)
		st.currentUsage.prompt = v
	}
	if m := reCompletionTok.FindStringSubmatch(line); m != nil {
		v, _ := strconv.ParseInt(m[1], 10, 64)
		st.currentUsage.completion = v
	}
	if m := reTotalTokens.FindStringSubmatch(line); m != nil {
		v, _ := strconv.ParseInt(m[1], 10, 64)
		st.currentUsage.total = v
	}
	if m := reCachedTokens.FindStringSubmatch(line); m != nil {
		v, _ := strconv.ParseInt(m[1], 10, 64)
		st.currentUsage.cached = v
	}
	if m := reCacheCreationTok.FindStringSubmatch(line); m != nil {
		v, _ := strconv.ParseInt(m[1], 10, 64)
		st.currentUsage.cacheCreation = v
	}
	if m := reReasoningTok.FindStringSubmatch(line); m != nil {
		v, _ := strconv.ParseInt(m[1], 10, 64)
		st.currentUsage.reasoning = v
	}
	// Recover the model from the response body. Some process logs (notably
	// resumed sessions) never emit `[INFO] Using default model: …`, so this
	// in-band field is the only signal that keeps the Tier-1 row from
	// landing unpriced as an unknown (empty) model.
	if m := reResponseModel.FindStringSubmatch(line); m != nil {
		if model := normalizeResponseModelCandidate(m[1]); model != "" {
			st.currentUsage.model = model
			if st.model == "" {
				st.model = model
			}
		}
	}

	// braceDepth back to 0 after we've seen content — block done.
	if st.braceDepth <= 0 && st.currentUsage.hasAny() {
		if st.currentRequestID != "" && lineStart >= fromOffset {
			emitTokenEvent(st, path, out)
		}
		st.inResponseBlock = false
		st.currentRequestID = ""
		st.currentUsage = usageAccum{}
		st.braceDepth = 0
	}
}

func emitTokenEvent(st *logParserState, path string, out *adapter.ParseResult) {
	// One Request-ID can produce N response blocks (WebSocket
	// connection serves multiple `response.create` calls). The seq
	// disambiguates so all N rows land instead of upserting onto each
	// other.
	st.requestSeq[st.currentRequestID]++
	seq := st.requestSeq[st.currentRequestID]
	// Net non-cached, non-cache-write input. Copilot CLI's debug log
	// captures the upstream API's `prompt_tokens` and
	// `prompt_tokens_details` (OpenAI convention) — `prompt_tokens` is the
	// GROSS prompt, which on Anthropic-via-Bedrock served turns equals
	// input + `cached_tokens` (cache read) + `cache_creation_tokens` (cache
	// write). Live evidence (session 946bfb36): prompt 16267 = 10 input + 0
	// read + 16257 write. The cost engine's TokenBundle.Input contract is
	// NET (engine.go bills Input + CacheRead + CacheCreation additively), so
	// we net BOTH cached subsets out here and surface them in their own
	// columns. Without netting the cache-write portion it would bill at the
	// full input rate AND again as cache_creation — a double-count on
	// cache-write-heavy turns. Clamp at 0 against an upstream anomaly where
	// the subsets exceed the gross (would indicate a parser regression).
	netInput := st.currentUsage.prompt - st.currentUsage.cached - st.currentUsage.cacheCreation
	if netInput < 0 {
		netInput = 0
	}
	// Copilot CLI's debug-log usage block is the OpenAI usage schema:
	// `completion_tokens` is GROSS and ALREADY CONTAINS
	// `completion_tokens_details.reasoning_tokens` (reasoning ⊂ completion).
	// Arithmetic-verified on the captured blocks — prompt_tokens +
	// completion_tokens == total_tokens on every one (e.g. 15474 + 565 ==
	// 16039, 16267 + 152 == 16419), so reasoning is NOT a separate summand:
	// it lives INSIDE completion_tokens. The cost engine bills
	// TokenBundle.Reasoning ADDITIVELY at the output rate ON TOP of Output
	// (cost.ComputeBreakdown), so TokenBundle.Output must be the
	// NON-reasoning completion count. Net the reasoning subset out here at
	// emit time (clamped ≥ 0, mirroring netInput and the codex fix
	// 9f1d1b85); without it every Copilot-CLI reasoning token is billed
	// twice.
	netOutput := st.currentUsage.completion - st.currentUsage.reasoning
	if netOutput < 0 {
		netOutput = 0
	}
	// Prefer the per-block model recovered from this response body; fall
	// back to the session-level model. The end-of-parse fill loop in
	// parseProcessLog still backstops any row left empty here.
	model := st.currentUsage.model
	if model == "" {
		model = st.model
	}
	out.TokenEvents = append(out.TokenEvents, models.TokenEvent{
		SourceFile:          path,
		SourceEventID:       fmt.Sprintf("log:%s:%d", st.currentRequestID, seq),
		Timestamp:           st.currentUsage.ts,
		Tool:                models.ToolCopilotCLI,
		Model:               model,
		InputTokens:         netInput,
		OutputTokens:        netOutput,
		CacheReadTokens:     st.currentUsage.cached,
		CacheCreationTokens: st.currentUsage.cacheCreation,
		ReasoningTokens:     st.currentUsage.reasoning,
		Source:              models.TokenSourceOTel, // not strictly OTel — it's the upstream API's own usage block, captured via debug log. Reuse OTel until a more specific source constant lands.
		Reliability:         models.ReliabilityApproximate,
		MessageID:           st.currentRequestID,
	})
}

// normalizeResponseModelCandidate trims Copilot CLI's routing prefixes
// (capi:, sweagent-capi:) and any `:`-suffixed tail, and drops the "auto"
// router sentinel (which names no real model). NB: unlike the upstream fork
// we deliberately do NOT remap claude-opus-4-7 -> claude-opus-4.7, because our
// pricing table (internal/intelligence/cost/pricing.go) keys on the dashed
// form; remapping would demote an exact price match to a family fallback.
func normalizeResponseModelCandidate(raw string) string {
	model := strings.TrimSpace(raw)
	if model == "" || strings.EqualFold(model, "auto") {
		return ""
	}
	switch {
	case strings.HasPrefix(model, "capi:"):
		model = strings.TrimPrefix(model, "capi:")
	case strings.HasPrefix(model, "sweagent-capi:"):
		model = strings.TrimPrefix(model, "sweagent-capi:")
	}
	if i := strings.Index(model, ":"); i > 0 {
		model = model[:i]
	}
	return model
}

// resolveModelFromSiblingEvents replays <copilotRoot>/session-state/<id>/
// events.jsonl through the events-path state dispatcher and returns the
// resolved selectedModel. Empty string when sessionID is empty, the file is
// absent, or it carries no model. Used as the last-resort model recovery for
// process logs that never emit `[INFO] Using default model: …` and carry no
// response-body model.
func resolveModelFromSiblingEvents(logPath, sessionID string) string {
	if sessionID == "" {
		return ""
	}
	// process-*.log lives at <copilotRoot>/logs/process-*.log; the session
	// state is at <copilotRoot>/session-state/<id>/events.jsonl.
	copilotRoot := filepath.Dir(filepath.Dir(logPath))
	eventsPath := filepath.Join(copilotRoot, "session-state", sessionID, "events.jsonl")
	f, err := os.Open(eventsPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	st := &parserState{
		sessionID:        sessionID,
		toolCalls:        map[string]toolExecutionStartData{},
		permRequests:     map[string]permissionRequestedData{},
		systemHashesSeen: map[string]bool{},
		subagentModels:   map[string]string{},
	}
	br := bufio.NewReader(f)
	for {
		line, readErr := br.ReadString('\n')
		clean := strings.TrimRight(line, "\r\n")
		if clean != "" {
			if env, perr := decodeEnvelope(clean); perr == nil {
				dispatchState(st, env, nil)
			}
		}
		if readErr != nil {
			return st.model
		}
	}
}

// assistantMsgRef is the minimal reference to an events.jsonl
// assistant.message used to recover a Tier-1 row's Request-ID: the real
// requestId Copilot CLI recorded for the turn, plus the output-token count
// and timestamp that map it back to the matching process-log usage block.
type assistantMsgRef struct {
	requestID    string
	outputTokens int64
	ts           time.Time
}

// resolveRequestIDsFromSiblingEvents scans
// <copilotRoot>/session-state/<id>/events.jsonl and returns the ordered list
// of assistant.message (requestId, outputTokens, timestamp) tuples that carry
// a real (non-empty, non-"null") Request-ID. Modern Copilot CLI (1.0.60+)
// emits `[DEBUG] response (Request-ID null)` in the process log — the
// hex:colon Request-ID the older format printed inline is gone — but the
// sibling events.jsonl still records it on the matching assistant.message.
// recoverNullRequestIDs uses these refs to stamp the real id onto the
// otherwise-"null" Tier-1 MessageID. Returns nil when sessionID is empty, the
// file is absent, or no assistant.message carries a real Request-ID.
func resolveRequestIDsFromSiblingEvents(logPath, sessionID string) []assistantMsgRef {
	if sessionID == "" {
		return nil
	}
	// process-*.log lives at <copilotRoot>/logs/process-*.log; the session
	// state is at <copilotRoot>/session-state/<id>/events.jsonl.
	copilotRoot := filepath.Dir(filepath.Dir(logPath))
	eventsPath := filepath.Join(copilotRoot, "session-state", sessionID, "events.jsonl")
	f, err := os.Open(eventsPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var refs []assistantMsgRef
	br := bufio.NewReader(f)
	for {
		line, readErr := br.ReadString('\n')
		clean := strings.TrimRight(line, "\r\n")
		if clean != "" {
			if env, perr := decodeEnvelope(clean); perr == nil && env.Type == "assistant.message" {
				var d assistantMessageData
				if json.Unmarshal(env.Data, &d) == nil && d.RequestID != "" && d.RequestID != "null" {
					refs = append(refs, assistantMsgRef{
						requestID:    d.RequestID,
						outputTokens: d.OutputTokens,
						ts:           parseTimestamp(env.Timestamp),
					})
				}
			}
		}
		if readErr != nil {
			return refs
		}
	}
}

// recoverNullRequestIDs heals Tier-1 TokenEvents whose MessageID is the
// literal "null" (modern Copilot CLI process logs) by matching each to its
// events.jsonl assistant.message ref on output-token count, breaking ties by
// nearest timestamp. Each ref is consumed once so turns with identical output
// counts still map 1:1. Rows with no matching ref keep "null" (graceful — we
// never guess a Request-ID we can't verify).
func recoverNullRequestIDs(events []models.TokenEvent, refs []assistantMsgRef) {
	if len(refs) == 0 {
		return
	}
	used := make([]bool, len(refs))
	for i := range events {
		if events[i].MessageID != "null" {
			continue
		}
		best := -1
		var bestGap time.Duration
		for j := range refs {
			if used[j] || refs[j].outputTokens != events[i].OutputTokens {
				continue
			}
			gap := refs[j].ts.Sub(events[i].Timestamp)
			if gap < 0 {
				gap = -gap
			}
			if best == -1 || gap < bestGap {
				best, bestGap = j, gap
			}
		}
		if best >= 0 {
			events[i].MessageID = refs[best].requestID
			used[best] = true
		}
	}
}

// parseLineTimestamp pulls the ISO timestamp prefix from a log line.
// Empty time.Time when the line is a JSON continuation (no prefix).
func parseLineTimestamp(line string) time.Time {
	if len(line) < 20 || !reTimestampLine.MatchString(line) {
		return time.Time{}
	}
	// Format is "2026-05-17T10:08:24.316Z [LEVEL] …"
	end := strings.IndexByte(line, ' ')
	if end < 0 {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, line[:end])
	if err != nil {
		return time.Time{}
	}
	return t
}
