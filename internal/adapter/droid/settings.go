package droid

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// settingsSuffix is the sibling sidecar written beside every transcript:
// `<uuid>.jsonl` → `<uuid>.settings.json`. The `.settings.json.bak`
// snapshot of the PRIOR settings state is deliberately never read.
const settingsSuffix = ".settings.json"

// tokenBlock is one of droid's three session-level cumulative usage
// blocks. `factoryCredits` is droid's own consumption unit for
// Factory-hosted models and has no TokenBundle counterpart, so it is
// decoded for completeness but never emitted.
type tokenBlock struct {
	InputTokens         int64 `json:"inputTokens"`
	OutputTokens        int64 `json:"outputTokens"`
	CacheCreationTokens int64 `json:"cacheCreationTokens"`
	CacheReadTokens     int64 `json:"cacheReadTokens"`
	ThinkingTokens      int64 `json:"thinkingTokens"`
	FactoryCredits      int64 `json:"factoryCredits"`
}

// empty reports whether the block carries no usage at all.
func (t tokenBlock) empty() bool {
	return t.InputTokens == 0 && t.OutputTokens == 0 &&
		t.CacheCreationTokens == 0 && t.CacheReadTokens == 0 &&
		t.ThinkingTokens == 0
}

// sidecar is the decoded `<uuid>.settings.json`. Only the fields the
// adapter consumes are named; droid's UI knobs (interactionMode,
// autonomyLevel, compactionThresholdCheckEnabled, …) are ignored.
type sidecar struct {
	Model                 string     `json:"model"`
	ReasoningEffort       string     `json:"reasoningEffort"`
	ProviderLock          string     `json:"providerLock"`
	ProviderLockTimestamp string     `json:"providerLockTimestamp"`
	AssistantActiveTimeMs int64      `json:"assistantActiveTimeMs"`
	TokenUsage            tokenBlock `json:"tokenUsage"`
	// InclusiveTokenUsage rolls up child (mission-worker) sessions and is
	// deliberately NOT emitted — each child session has its own
	// transcript + sidecar pair, so emitting the inclusive block here
	// would double-count them.
	InclusiveTokenUsage tokenBlock `json:"inclusiveTokenUsage"`
	// ChildInclusiveTokenUsageBySessionId maps child session id → its
	// rolled-up usage. Decoded only so the child-session keys are
	// available to future work; never emitted (see above).
	ChildInclusiveTokenUsageBySessionID map[string]tokenBlock `json:"childInclusiveTokenUsageBySessionId"`
	// LastCallTokenUsage is the most recent single API call. A strict
	// subset of TokenUsage — decoded for completeness, never emitted,
	// since emitting both would double-count.
	LastCallTokenUsage struct {
		InputTokens     int64 `json:"inputTokens"`
		OutputTokens    int64 `json:"outputTokens"`
		CacheReadTokens int64 `json:"cacheReadTokens"`
	} `json:"lastCallTokenUsage"`
	// EffectiveFactoryRouterModel names the CONCRETE model droid's own
	// auto-router picked for an `auto`-mode session, once it has routed
	// at least one turn. Grounded 2026-09-03: present
	// (`{"modelId":"claude-opus-5","reasoningEffort":"high","fallbacks":[]}`)
	// on an `auto`-mode sidecar that completed a routed turn, ABSENT on
	// one that never did (an empty "New Session" scratch session with
	// `model:"auto"` and no effectiveFactoryRouterModel key at all). See
	// resolvedModel.
	EffectiveFactoryRouterModel struct {
		ModelID string `json:"modelId"`
	} `json:"effectiveFactoryRouterModel"`
}

// autoModel is the sidecar's own sentinel for "let droid's router
// choose", as opposed to an operator-pinned model id.
const autoModel = "auto"

// resolvedModel returns the session's effective model through droid's
// auto-routing ladder:
//
//  1. an explicit, non-"auto" sidecar `model` wins outright — the
//     common case, and the only case for a BYOK `custom:...` alias;
//  2. otherwise, for an `auto`-mode session that has routed at least
//     one turn, `effectiveFactoryRouterModel.modelId` names the
//     concrete model droid actually called;
//  3. otherwise (an `auto`-mode session with no routed turn yet — the
//     empty "New Session" shape) the literal `"auto"` sentinel is
//     returned verbatim rather than guessed at.
//
// A blank `model` (missing sidecar field entirely) falls through the
// same way `"auto"` does, landing on tier 2 then tier 3.
func (sc *sidecar) resolvedModel() string {
	m := strings.TrimSpace(sc.Model)
	if m != "" && m != autoModel {
		return m
	}
	if eff := strings.TrimSpace(sc.EffectiveFactoryRouterModel.ModelID); eff != "" {
		return eff
	}
	return m
}

// settingsPath maps a transcript path to its sidecar path. Returns ""
// when the path is not a `.jsonl` transcript.
func settingsPath(transcript string) string {
	base := strings.TrimSuffix(transcript, ".jsonl")
	if base == transcript {
		return ""
	}
	return base + settingsSuffix
}

// readSidecar reads and decodes the transcript's `<uuid>.settings.json`,
// returning its modification time alongside (used as the token row's
// timestamp when the parsed slice of the transcript carried none).
//
// A missing, symlinked or malformed sidecar is NOT an error — droid
// writes the transcript and the sidecar independently, so a just-created
// session can legitimately have one without the other. Callers get
// (nil, zero, false) and carry on without tokens.
func readSidecar(transcript string) (*sidecar, time.Time, bool) {
	p := settingsPath(transcript)
	if p == "" {
		return nil, time.Time{}, false
	}
	// The sidecar path is DERIVED, not observed: whatever sits at
	// `<uuid>.settings.json` is read without the watcher having claimed
	// it. A symlink there would let anything under ~/.factory that this
	// adapter promises never to read — settings.json (plaintext BYOK
	// customModels[].apiKey), auth.v2.file / auth.v2.key, history.json —
	// be pulled in through the sibling lookup. Refuse symlinks outright:
	// a real droid install never writes one, so this costs nothing and
	// keeps the package doc's "never reads" list true by construction.
	info, err := os.Lstat(p)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return nil, time.Time{}, false
	}
	body, err := os.ReadFile(p) //nolint:gosec // path derives from a watched transcript; symlinks refused above
	if err != nil {
		return nil, time.Time{}, false
	}
	var sc sidecar
	if err := json.Unmarshal(body, &sc); err != nil {
		return nil, time.Time{}, false
	}
	return &sc, info.ModTime().UTC(), true
}

// tokenEvent builds the single session-level TokenEvent for a transcript
// from the sidecar's SELF-ONLY cumulative `tokenUsage` block.
//
// The SourceEventID is the stable `tokens:<session-id>`, so a later parse
// of a grown sidecar rewrites the same (source_file, source_event_id) row
// and store.InsertTokenEvents' ON CONFLICT MAX-upgrade keeps the counts
// monotonically non-decreasing. No adapter-side dedup cursor is needed.
//
// InputTokens is passed through UNCHANGED: droid persists input already
// NET of cacheReadTokens (input < cacheRead on both grounded fixtures,
// which GROSS cannot produce), including under an OpenAI-shaped BYOK
// call. See the package doc for the BYOK-only caveat.
//
// Returns ok=false when the block carries no usage at all, so a
// freshly-created session doesn't get an all-zero token row.
func tokenEvent(sc *sidecar, sourceFile, sessionID, projectRoot, gitBranch, gitRemote string, ts time.Time) (models.TokenEvent, bool) {
	if sc == nil || sessionID == "" || sc.TokenUsage.empty() {
		return models.TokenEvent{}, false
	}
	u := sc.TokenUsage
	return models.TokenEvent{
		SourceFile:          sourceFile,
		SourceEventID:       "tokens:" + sessionID,
		SessionID:           sessionID,
		ProjectRoot:         projectRoot,
		GitBranch:           gitBranch,
		GitRemote:           gitRemote,
		Timestamp:           ts,
		Tool:                models.ToolDroid,
		Model:               sc.resolvedModel(),
		InputTokens:         u.InputTokens,
		OutputTokens:        u.OutputTokens,
		CacheReadTokens:     u.CacheReadTokens,
		CacheCreationTokens: u.CacheCreationTokens,
		ReasoningTokens:     u.ThinkingTokens,
		Source:              models.TokenSourceJSONL,
		Reliability:         models.ReliabilityApproximate,
	}, true
}
