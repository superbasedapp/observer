package grokbot

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

const (
	// storeDirName is the persistence directory inside Electron's userData.
	storeDirName = "sand-client-persistence"
	// appDirName is Electron's userData leaf, which is the app's
	// productName.
	appDirName = "Grok Bot"

	// syntheticRoot is the project root every Grok Bot session lands under.
	// Grok Bot executes in a remote sandbox, so no local working directory
	// exists to resolve — a single shared pseudo-project (the antigravity
	// precedent) is honest and keeps the dashboard from sprouting one
	// singleton project per conversation.
	syntheticRoot = "[grokbot]"

	maxTargetLen = 500
)

// Adapter parses Grok Bot desktop transcript blobs.
type Adapter struct {
	scrubber *scrub.Scrubber
	roots    []string
}

// New returns an adapter with the default scrubber and platform-default roots.
func New() *Adapter {
	return &Adapter{scrubber: scrub.New(), roots: defaultRoots()}
}

// NewWithOptions customizes the scrubber and/or watch roots for tests.
func NewWithOptions(s *scrub.Scrubber, roots ...string) *Adapter {
	if s == nil {
		s = scrub.New()
	}
	if len(roots) == 0 {
		roots = defaultRoots()
	}
	return &Adapter{scrubber: s, roots: roots}
}

// Name implements adapter.Adapter.
func (*Adapter) Name() string { return models.ToolGrokbot }

// WatchPaths implements adapter.Adapter.
func (a *Adapter) WatchPaths() []string { return a.roots }

// appDataSpec declares Grok Bot's Electron userData directory, one shape
// per OS Grok Bot ships on:
//
//	<home>/AppData/Roaming/Grok Bot            (Windows)
//	<home>/Library/Application Support/Grok Bot (macOS)
//
// No ShapeXDGConfig: Grok Bot is not distributed for Linux, and
// inventing ~/.config/"Grok Bot" would be an ungrounded guess.
var appDataSpec = adapter.AppDataSpec{
	Name:   appDirName,
	Shapes: adapter.ShapeWindowsRoaming | adapter.ShapeDarwinAppSupport,
}

// defaultRoots returns the sand-client-persistence directory under every
// detected home, in the shape that belongs to that home's LOGICAL OS.
//
// Both shapes used to be emitted under every home on the theory that the
// daemon commonly runs under WSL2 and the watcher drops what does not
// exist. The premise was right and the conclusion wrong: crossmount
// already tags a /mnt/c home as OS=="windows", so the macOS shape under
// it is not merely absent but impossible — a watch root the daemon
// registers and logs for nothing. adapter.AppDataRoots owns that gate.
func defaultRoots() []string {
	var roots []string
	for _, h := range crossmount.AllHomes() {
		for _, base := range adapter.AppDataRoots(h, appDataSpec) {
			roots = append(roots, filepath.Join(base, storeDirName))
		}
	}
	return adapter.DedupRootsByIdentity(roots)
}

// IsSessionFile implements adapter.Adapter.
//
// This is an ALLOW-LIST, which is what keeps the sibling credential files
// (sand-secrets.json, the sealed local-exec-daemon-*.json, Chromium's
// "Local State", Network/Cookies, the sand-forever-box webview profile)
// structurally unreachable rather than merely un-visited:
//
//  1. the file sits directly in a sand-client-persistence directory,
//  2. its name ends ".blob" (and NOT ".tmp" — a half-written blob),
//  3. the name decodes cleanly under the app's own base32 codec,
//  4. the decoded key is a transcript.replicas slice with an agent id,
//  5. the path is under one of this adapter's watch roots.
func (a *Adapter) IsSessionFile(path string) bool {
	if !matchesShape(path) {
		return false
	}
	return adapter.UnderAnyWatchRoot(path, a.WatchPaths())
}

func matchesShape(path string) bool {
	norm := strings.ReplaceAll(path, `\`, "/")
	// The blob must live directly inside a sand-client-persistence dir.
	if filepath.Base(filepath.Dir(norm)) != storeDirName {
		return false
	}
	return transcriptAgentID(filepath.Base(norm)) != ""
}

// turnIDRe matches the transcript's stable entry-id scheme:
//
//	t<N>u       the user message opening turn N
//	t<N>s<M>    the agent's M-th send within turn N
//
// (`tbs<n>` bootstrap greetings and `event-<uuid>` rows do not match and
// inherit the running turn.)
var turnIDRe = regexp.MustCompile(`^t(\d+)(?:u|s\d+)$`)

// ParseSessionFile implements adapter.Adapter.
//
// CURSOR SEMANTICS: fromOffset is an ENTRY COUNT, not a byte offset. A
// transcript blob is a single JSON document rewritten in place on every
// change, so a byte offset is meaningless — the same reasoning as freebuff's
// message-count cursor. adapter.CursorByteOffset stays the declared kind
// because the value is still a monotonically advancing count of consumed
// records and byte-lag is not consulted for this adapter.
func (a *Adapter) ParseSessionFile(_ context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	data, err := os.ReadFile(path) //nolint:gosec // watched session file
	if err != nil {
		// A DELETED file will never read, so retrying it forever would
		// pin a dead cursor on the poll loop. Any other error (most
		// realistically a Windows share-lock while the app rewrites the
		// blob) is transient and worth another tick — the freshness gate
		// RetrySuggested's contract asks for.
		return adapter.ParseResult{
			NewOffset:      fromOffset,
			RetrySuggested: !os.IsNotExist(err),
		}, nil
	}

	var env blobEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		// The app rewrites the whole blob; a mid-write read is expected
		// and transient. Hold the cursor and retry.
		return adapter.ParseResult{NewOffset: fromOffset, RetrySuggested: true}, nil
	}
	var tv transcriptValue
	if err := json.Unmarshal(env.Value, &tv); err != nil {
		return adapter.ParseResult{
			NewOffset:      fromOffset,
			RetrySuggested: true,
			Warnings:       []string{fmt.Sprintf("grokbot: unreadable transcript value in %s: %v", filepath.Base(path), err)},
		}, nil
	}

	sessID := transcriptAgentID(filepath.Base(strings.ReplaceAll(path, `\`, "/")))
	if sessID == "" {
		// IsSessionFile already guaranteed this; belt-and-braces so a
		// direct call can never mint a session with an empty id.
		return adapter.ParseResult{NewOffset: fromOffset}, nil
	}

	start := int(fromOffset)
	if start < 0 || start > len(tv.Entries) {
		// The transcript shrank (an epoch reset / server re-replication),
		// so our cursor no longer indexes the same sequence. Re-read from
		// the top; every SourceEventID is stable, so the re-emit is an
		// idempotent upsert rather than a duplicate.
		start = 0
	}

	res := adapter.ParseResult{}
	fallback := tv.PersistedAt
	turn := 0
	// Recover the running turn index from the entries we are skipping, so a
	// resumed parse does not restart turn numbering at 0.
	for i := 0; i < start && i < len(tv.Entries); i++ {
		if n, ok := turnOf(tv.Entries[i].ID); ok {
			turn = n
		}
	}

	consumed := start
	for i := start; i < len(tv.Entries); i++ {
		e := tv.Entries[i]
		if e.inFlight() {
			// Stop here: an in-flight entry's body is a truncated prefix
			// and the store's action upsert cannot rewrite a target on
			// conflict, so persisting it now would be permanent. Leave
			// the cursor pointing AT it and ask for a retry.
			res.RetrySuggested = true
			break
		}
		if n, ok := turnOf(e.ID); ok {
			turn = n
		}
		a.emitEntry(&res, path, sessID, turn, e, fallback)
		if e.TimestampMs > 0 {
			fallback = e.TimestampMs
		}
		consumed = i + 1
	}
	res.NewOffset = int64(consumed)
	return res, nil
}

func turnOf(id string) (int, bool) {
	m := turnIDRe.FindStringSubmatch(id)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, false
	}
	return n, true
}

// emitEntry maps one transcript entry onto at most one ToolEvent.
func (a *Adapter) emitEntry(res *adapter.ParseResult, path, sessID string, turn int, e transcriptEntry, fallbackMs int64) {
	if e.ID == "" {
		// The app's own validator requires a non-empty id; without one
		// there is no deterministic SourceEventID, so skip rather than
		// synthesize a non-idempotent one.
		return
	}

	action, rawName, target := a.classify(e)
	if action == "" {
		return // deliberately-ignored kind
	}

	ts := e.TimestampMs
	if ts <= 0 {
		ts = fallbackMs
	}

	res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
		SourceFile:    path,
		SourceEventID: e.ID, // native, stable, unique within the transcript
		SessionID:     sessID,
		ProjectRoot:   syntheticRoot,
		Timestamp:     time.UnixMilli(ts).UTC(),
		TurnIndex:     turn,
		Tool:          models.ToolGrokbot,
		ActionType:    action,
		RawToolName:   rawName,
		Target:        truncate(target, maxTargetLen),
		// Success is true for everything except an explicitly failed
		// tool-call. There is no error body on the desktop side, so
		// ErrorMessage stays empty rather than being invented.
		Success: !(e.Kind == kindToolCall && e.Status == statusFailed),
	})
}

// classify maps an entry onto (ActionType, RawToolName, Target). An empty
// ActionType means "deliberately not ingested".
//
// tool-call maps to ActionUnknown with the raw name preserved rather than
// being force-fit onto ActionRead / ActionEdit / ActionBash: the tool names
// are box-side and unenumerated, and no live tool-call entry has been captured
// yet, so guessing the mapping would be fabrication. RawToolName keeps the
// real name available for a grounded tightening later.
func (a *Adapter) classify(e transcriptEntry) (action, rawName, target string) {
	switch e.Kind {
	case kindMessage:
		if e.isAssistant() {
			return models.ActionAssistantMessage, "assistant-message", a.scrubber.String(e.Content)
		}
		return models.ActionUserPrompt, "user-message", a.scrubber.String(e.Content)

	case kindSendMessage:
		// A box hand-back (the remote sandbox asking the human to take an
		// interactive step) is a real agent action and is kept distinct.
		if e.BoxInstruction != "" {
			return models.ActionUnknown, "box-instruction", a.scrubber.String(e.BoxInstruction)
		}
		if e.Message == nil {
			return "", "", ""
		}
		if e.Message.Type == msgTypeText {
			return models.ActionAssistantMessage, "assistant-message", a.scrubber.String(e.Message.Content)
		}
		// Every non-text payload (widget / secret-request / email-draft /
		// permission-request / connector / …) is recorded by TYPE only.
		// We never reach into the payload — secret-request in particular
		// carries credential-request material.
		return models.ActionAssistantMessage, "assistant-message:" + sanitizeToken(e.Message.Type), ""

	case kindToolCall:
		if e.Name == "" {
			return "", "", ""
		}
		return models.ActionUnknown, e.Name, a.scrubber.String(e.Summary)

	case kindUserAttachment:
		return models.ActionUnknown, "user-attachment", a.scrubber.String(firstNonEmpty(e.FileName, e.FilePath))

	case kindNotice:
		return models.ActionUnknown, "notice", a.scrubber.String(e.Text)

	case kindEvent:
		if e.Event == nil || e.Event.Type == "" {
			return "", "", ""
		}
		return models.ActionUnknown, "event:" + sanitizeToken(e.Event.Type), a.scrubber.String(e.Event.AutomationName)

	case kindFeedback, kindVoiceCall:
		// Known kinds that carry no activity worth an action row. Skipped
		// SILENTLY — warning per occurrence would flood the watcher log.
		return "", "", ""

	default:
		// An unrecognised TYPED kind is forward-compat signal worth one
		// warning; but emit nothing, since we cannot interpret it.
		return "", "", ""
	}
}

// sanitizeToken keeps a type/event name safe to concatenate into a
// RawToolName: the app's own vocabularies are lowercase-and-hyphen, so
// anything else is clamped rather than trusted.
func sanitizeToken(s string) string {
	if len(s) > 64 {
		s = s[:64]
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, s)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…[truncated]"
}
