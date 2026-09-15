package geminicodeassist

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// ToolName is the tool id this adapter will write into the `tool`
// column once it is registered. It lives here rather than in
// internal/models because the package is UNREGISTERED (see doc.go): a
// models.Tool* constant is a capability claim, and there is nothing to
// claim until a fixture grounds the parser. Registration moves it to
// `models.ToolGeminiCodeAssist`.
const ToolName = "gemini-code-assist"

// fixtureREADME is named in every honest-refusal warning so an operator
// who sees one knows exactly which document describes the grounding
// step that would make the file parseable.
const fixtureREADME = "testdata/geminicodeassist/README.md"

// Compile-time proof that the skeleton satisfies the full adapter
// contract, so registration later is a one-line change and never a
// refactor.
var _ adapter.Adapter = (*Adapter)(nil)

// Adapter is the skeleton adapter.Adapter implementation for Gemini
// Code Assist Chat Mode. It is not registered anywhere; constructing it
// is currently only done by this package's tests.
//
// It carries no scrubber: the skeleton emits token counts only, never
// prompt or tool content, so there is nothing to scrub. The grounded
// parser that replaces parseSpool WILL need one the moment it starts
// emitting ToolEvents off the memento threads.
type Adapter struct {
	roots []string
}

// New returns an adapter with platform-default watch roots.
func New() *Adapter {
	return &Adapter{roots: defaultRoots()}
}

// NewWithRoots returns an adapter whose watch roots are overridden, for
// tests that stage a fake editor tree under t.TempDir(). An empty roots
// slice falls back to the platform defaults.
func NewWithRoots(roots []string) *Adapter {
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return ToolName }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// pathKind classifies a path against the three Chat Mode candidate
// stores. Unknown paths get kindNone.
type pathKind int

const (
	kindNone pathKind = iota
	// kindSpool is a DRAINED metrics record,
	// `metrics_to_send/<uuid>.json`. The `.tmp` sibling is the
	// half-written form the extension renames from and is deliberately
	// NOT matched — reading one races the writer.
	kindSpool
	// kindCheckpoint is any regular file under `chat_checkpoint_files/`.
	kindCheckpoint
	// kindStateDB is the shared VS Code memento database itself.
	kindStateDB
)

// IsSessionFile implements adapter.Adapter.
//
// Three shapes are claimed, and every one is ANDed with
// adapter.UnderAnyWatchRoot so the predicate can never reach outside
// this adapter's own roots:
//
//  1. `<globalStorage>/google.geminicodeassist/metrics_to_send/<uuid>.json`
//     — the drained token spool. `.tmp` is excluded: it is the
//     half-written pre-rename form.
//  2. any regular file under
//     `<globalStorage>/google.geminicodeassist/chat_checkpoint_files/`
//     — the naming convention is UNVERIFIED, so no extension filter is
//     applied; the directory membership is the whole predicate.
//  3. `<globalStorage>/state.vscdb` exactly — for the products this
//     package owns (see roots.go). The exact-basename test excludes the
//     `-wal` / `-shm` fsnotify sidecars and any `.backup` copy.
//
// Agent Mode's `~/.gemini/tmp/<projectId>/chats/session-*.jsonl` is NOT
// claimed here under any circumstances: internal/adapter/gemini owns it,
// and no root of this adapter is an ancestor of it anyway.
func (a *Adapter) IsSessionFile(path string) bool {
	if classify(path) == kindNone {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

// classify applies the pure shape half of IsSessionFile. Separators are
// folded and the path is lower-cased so a Windows-shaped fixture matches
// on a Linux host and vice versa.
func classify(path string) pathKind {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	base := lower[strings.LastIndex(lower, "/")+1:]
	if base == "" {
		return kindNone
	}

	extPrefix := "/" + extensionDirName + "/"
	switch {
	case strings.Contains(lower, extPrefix+metricsSpoolDirName+"/"):
		if strings.HasSuffix(base, ".json") {
			return kindSpool
		}
		return kindNone
	case strings.Contains(lower, extPrefix+checkpointsDirName+"/"):
		return kindCheckpoint
	case base == stateDBFileName:
		return kindStateDB
	}
	return kindNone
}

// ParseSessionFile implements adapter.Adapter.
//
// The honest contract of a skeleton (plan §4 note 1): a store whose
// record shape has never been observed yields an EMPTY ParseResult plus
// exactly one Warning naming the fixture README — never a guessed row.
// Only the metrics spool is parsed at all, and only for the four token
// field names the bundle read grounded; see parseSpool.
//
// The memento database is NOT opened. There is no SQLite reader in this
// package by design: opening state.vscdb would mean deciding how to
// interpret a row whose JSON shape is UNVERIFIED and login-gated, and a
// wrong guess writes garbage rows that outlive the guess.
func (a *Adapter) ParseSessionFile(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: fromOffset}
	if err := ctx.Err(); err != nil {
		return res, fmt.Errorf("geminicodeassist.ParseSessionFile: %w", err)
	}

	switch classify(path) {
	case kindSpool:
		return a.parseSpool(path, fromOffset)
	case kindCheckpoint:
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"geminicodeassist: chat_checkpoint_files payload shape is UNVERIFIED; %s is not parsed. See %s (operator step-in P3).",
			filepath.Base(path), fixtureREADME))
		return res, nil
	case kindStateDB:
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"geminicodeassist: the geminiCodeAssist.chatThreads memento in %s is UNVERIFIED and login-gated; no reader exists yet. See %s (operator step-in P3).",
			filepath.Base(path), fixtureREADME))
		return res, nil
	default:
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"geminicodeassist: %s does not match any known Chat Mode store shape. See %s.",
			filepath.Base(path), fixtureREADME))
		return res, nil
	}
}

// usageMetadata is the token block whose four field NAMES were read
// verbatim out of the `google.geminicodeassist` 2.98.0 bundle
// [STATIC-GROUNDED]. The object's position inside the spool record is
// [UNVERIFIED] — see walkUsageSites.
type usageMetadata struct {
	PromptTokenCount        int64 `json:"promptTokenCount"`
	CandidatesTokenCount    int64 `json:"candidatesTokenCount"`
	TotalTokenCount         int64 `json:"totalTokenCount"`
	CachedContentTokenCount int64 `json:"cachedContentTokenCount"`
}

// usageMetadataKey is the object key that marks a usage site.
const usageMetadataKey = "usageMetadata"

// modelKeys are the sibling keys checked for a model id, in order.
// BOTH are [UNVERIFIED] — neither was observed beside a usageMetadata
// object; they are the two spellings the Gemini API family uses
// elsewhere. A miss leaves Model empty, which is the honest outcome.
var modelKeys = []string{"model", "modelName"}

// spoolDocument is the top-level envelope of a drained spool file.
//
// [UNVERIFIED]: the bundle read grounded the DIRECTORY and the field
// names inside usageMetadata, not the file's own envelope. Both plausible
// shapes are therefore accepted — a single event object, or an array of
// them — and normalized to Roots. Anything else (a bare string, a
// number) decodes into a one-element Roots that the walk simply finds no
// usage sites in.
type spoolDocument struct {
	Roots []any
}

// UnmarshalJSON implements json.Unmarshaler, normalizing the top-level
// object / top-level array ambiguity. Numbers are decoded as
// json.Number so a large token count never round-trips through float64.
func (d *spoolDocument) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return err
	}
	if arr, ok := v.([]any); ok {
		d.Roots = arr
		return nil
	}
	d.Roots = []any{v}
	return nil
}

// usageSite is one object in the decoded spool that carries a
// usageMetadata block, plus whatever model id sat beside it.
type usageSite struct {
	Usage usageMetadata
	Model string
}

// parseSpool reads one drained `metrics_to_send/<uuid>.json` file and
// emits one TokenEvent per usage site that reports a non-zero prompt or
// candidates count.
//
// A file whose events carry no usageMetadata at all — the
// CHAT_STREAMING_OFFERED_START record is exactly that shape — yields
// zero events and NO warning. That is the expected steady state of a
// telemetry spool, not an anomaly, and warning on it would drown the
// real signals. Malformed JSON, by contrast, yields one warning and no
// error: the watcher must keep making progress.
func (a *Adapter) parseSpool(path string, fromOffset int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: fromOffset}

	info, err := os.Stat(path)
	if err != nil {
		return res, fmt.Errorf("geminicodeassist.ParseSessionFile: %w", err)
	}
	// A spool file is written once, renamed `.tmp` → `.json`, uploaded
	// and deleted; it is never appended to. A non-zero cursor at or
	// past its size means this file was already consumed. A ZERO cursor
	// always falls through, so a zero-byte file still produces its
	// malformed-JSON warning rather than being silently skipped.
	if fromOffset > 0 && fromOffset >= info.Size() {
		return res, nil
	}

	data, err := os.ReadFile(path) //nolint:gosec // path comes from the watcher's own roots
	if err != nil {
		return res, fmt.Errorf("geminicodeassist.ParseSessionFile: %w", err)
	}
	res.NewOffset = int64(len(data))

	var doc spoolDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"geminicodeassist: metrics spool %s is not valid JSON (%v); skipped. See %s.",
			filepath.Base(path), err, fixtureREADME))
		return res, nil
	}

	var sites []usageSite
	for _, root := range doc.Roots {
		walkUsageSites(root, &sites)
	}

	base := filepath.Base(path)
	// SessionID is a PLACEHOLDER: the spool record's linkage to a
	// geminiCodeAssist.chatThreads thread id is UNVERIFIED, so the file
	// stem is used instead. Grounding replaces this with the real thread
	// id — and until it does, one "session" per spool file is the
	// honest granularity, since that is genuinely all we can tell apart.
	sessionID := strings.TrimSuffix(base, filepath.Ext(base))
	ts := info.ModTime()

	for i, site := range sites {
		if site.Usage.PromptTokenCount <= 0 && site.Usage.CandidatesTokenCount <= 0 {
			continue
		}
		// Gemini's promptTokenCount is GROSS — it INCLUDES
		// cachedContentTokenCount. Net at emit time, mirroring
		// internal/adapter/gemini/parser.go::tokenEventFor, or the
		// cached slice is billed twice.
		cacheRead := site.Usage.CachedContentTokenCount
		if cacheRead < 0 {
			cacheRead = 0
		}
		netInput := site.Usage.PromptTokenCount - cacheRead
		if netInput < 0 {
			netInput = 0
		}
		output := site.Usage.CandidatesTokenCount
		if output < 0 {
			output = 0
		}
		res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
			SourceFile: path,
			// Deterministic and re-parse-idempotent: the file name is
			// a uuid the extension generated, and the index is the
			// site's position in a deterministically ordered walk.
			SourceEventID:   fmt.Sprintf("%s:usage:%d", base, i),
			SessionID:       sessionID,
			Timestamp:       ts,
			Tool:            ToolName,
			Model:           site.Model,
			InputTokens:     netInput,
			OutputTokens:    output,
			CacheReadTokens: cacheRead,
			// totalTokenCount is a derived sum of the other three and
			// is deliberately not stored. No thoughts/reasoning count
			// exists anywhere in the grounded field set.
			Source:      models.TokenSourceJSONL,
			Reliability: models.ReliabilityUnreliable,
		})
	}
	return res, nil
}

// walkUsageSites descends v looking for any object that carries a
// usageMetadata block, appending one usageSite per hit.
//
// The descent is depth-first with map keys visited in SORTED order, so
// the index a site lands at — and therefore its SourceEventID — is
// stable across runs despite Go's randomized map iteration. Depth is
// unbounded on purpose: the nesting level of usageMetadata inside a
// spool record is [UNVERIFIED], and a spool file is a few kilobytes.
func walkUsageSites(v any, out *[]usageSite) {
	switch t := v.(type) {
	case map[string]any:
		if site, ok := usageSiteFrom(t); ok {
			*out = append(*out, site)
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == usageMetadataKey {
				continue
			}
			walkUsageSites(t[k], out)
		}
	case []any:
		for _, e := range t {
			walkUsageSites(e, out)
		}
	}
}

// usageSiteFrom extracts a usageSite from object m when m carries a
// usageMetadata object. A usageMetadata whose fields do not decode into
// the typed struct (a string where a count belongs, a fractional count)
// is treated as a miss rather than a partial read.
func usageSiteFrom(m map[string]any) (usageSite, bool) {
	rawUsage, ok := m[usageMetadataKey]
	if !ok {
		return usageSite{}, false
	}
	if _, isObj := rawUsage.(map[string]any); !isObj {
		return usageSite{}, false
	}
	encoded, err := json.Marshal(rawUsage)
	if err != nil {
		return usageSite{}, false
	}
	var u usageMetadata
	if err := json.Unmarshal(encoded, &u); err != nil {
		return usageSite{}, false
	}
	site := usageSite{Usage: u}
	for _, key := range modelKeys {
		if s, ok := m[key].(string); ok && strings.TrimSpace(s) != "" {
			site.Model = strings.TrimSpace(s)
			break
		}
	}
	return site, true
}
