package antigravity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// IndexEntryResolved is the per-conversation enrichment shape exposed
// to backfill callers: the fields they need for re-attribution
// (project root, title, model hint, conversation creation time)
// without depending on the package-internal indexEntry type.
type IndexEntryResolved struct {
	ProjectRoot string
	GitRemote   string
	Title       string
	ModelHint   string
	Created     time.Time
}

// ResolveIndexEntry maps a .pb conversation file path to its
// state.vscdb index entry, returning the resolved project root and
// metadata. ok is false when the .pb path doesn't sit under a
// recognised .gemini layout, no state.vscdb is present, or the index
// has no entry for the conversation UUID. Used by the
// --antigravity-project-root backfill to re-attribute sessions
// ingested before the statedb deep-parser fix shipped.
func ResolveIndexEntry(pbPath string) (IndexEntryResolved, bool) {
	conversationID := uuidFromFilename(pbPath)
	if conversationID == "" {
		return IndexEntryResolved{}, false
	}
	dbPath := stateDBPathFor(pbPath)
	if dbPath == "" {
		return IndexEntryResolved{}, false
	}
	freshDB, _ := pickFreshIndexDB(dbPath)
	if freshDB == "" {
		return IndexEntryResolved{}, false
	}
	entries, err := readTrajectorySummaries(freshDB)
	if err != nil {
		return IndexEntryResolved{}, false
	}
	e, hit := entries[conversationID]
	if !hit {
		return IndexEntryResolved{}, false
	}
	out := IndexEntryResolved{
		Title:     e.title,
		ModelHint: e.modelHint,
		Created:   e.created,
	}
	if e.workspaceURI != "" {
		// ResolveIndexEntry is the backfill re-attribution path (cmd/observer
		// backfill.go's --antigravity-project-root), which re-resolves git
		// identity itself via a direct git.Resolve call — the richer
		// Project Identity Resolver v2 bundle is intentionally discarded
		// here, matching that call site's existing Root/IsGit-only usage.
		out.ProjectRoot, out.GitRemote, _ = decodeFileURIToRoot(e.workspaceURI)
	}
	return out, true
}

// FetchStructuredTrajectory fetches the GetCascadeTrajectory payload
// for a conversation and parses it into a StructuredEnrichment.
// Mirrors the platform-routing logic in recoverViaLocalGRPC: WSL2
// hosts route through the Windows bridge, native hosts call the
// language_server's gRPC endpoint directly.
//
// Used by the --antigravity-project-root backfill mode to lift
// model + token rows into existing sessions whose .pb files don't
// decrypt locally and were ingested before structured recovery
// shipped. Returns a non-empty error only on configuration / setup
// failures (no bridge, no running language_server); per-conversation
// "not loaded by any server" cases surface as a non-nil error too —
// the caller logs and moves on.
//
// scrubber is applied to artifact-text fields (Tier 1 edits, Tier 2
// payloads) surfaced into ToolEvent payloads. Backfill callers pass
// scrub.New() — never nil in production.
func FetchStructuredTrajectory(ctx context.Context, conversationID, projectRoot, sourceFile string, timeout time.Duration, scrubber Scrubber) (StructuredEnrichment, error) {
	if conversationID == "" {
		return StructuredEnrichment{}, errors.New("antigravity.FetchStructuredTrajectory: conversationID empty")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if isWSL() {
		// Linux-side .pb files (~/.gemini/antigravity/conversations/) are
		// unreachable from the Windows-side bridge — short-circuit
		// before burning the ~3s bridge timeout. Mirrors the gate in
		// recoverViaLocalGRPC (adapter.go).
		if strings.HasPrefix(sourceFile, "/home/") {
			return StructuredEnrichment{}, fmt.Errorf(
				"antigravity.FetchStructuredTrajectory: linux-side conversation %s unreachable from Windows bridge; reopen the originating workspace in Antigravity to recover",
				conversationID,
			)
		}
		raw, err := invokeBridgeStructuredFromWSL(ctx, conversationID, timeout)
		if err != nil {
			return StructuredEnrichment{}, fmt.Errorf("antigravity.FetchStructuredTrajectory: bridge: %w", err)
		}
		return ParseStructuredTrajectory(raw, conversationID, projectRoot, "", sourceFile, scrubber), nil
	}
	servers, err := discoverLanguageServers()
	if err != nil {
		return StructuredEnrichment{}, fmt.Errorf("antigravity.FetchStructuredTrajectory: discover: %w", err)
	}
	var lastErr error
	for _, ls := range servers {
		endpoint := ls.PreferredEndpoint()
		if endpoint == "" {
			continue
		}
		raw, err := callGetCascadeTrajectory(ctx, endpoint, ls.CSRFToken, conversationID, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		return ParseStructuredTrajectory(raw, conversationID, projectRoot, "", sourceFile, scrubber), nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable language_server endpoint")
	}
	return StructuredEnrichment{}, fmt.Errorf("antigravity.FetchStructuredTrajectory: %w", lastErr)
}

// Scrubber is the public alias of the internal stringScrubber
// interface, exported so external callers (cmd/observer/backfill)
// can satisfy it without depending on antigravity's private types.
// *scrub.Scrubber implements it via its String(string) string method.
type Scrubber interface {
	String(s string) string
}

// FetchMarkdownTrajectory fetches the ConvertTrajectoryToMarkdown
// rendering of a conversation. Used by the backfill to recover
// markdown.planner_response rows when structured.assistant_text
// coverage is sparse — gemini sessions emit far fewer 1.2.20.1
// PLANNER_RESPONSE steps than the markdown extractor surfaces.
//
// Mirrors the platform routing in recoverViaLocalGRPC: WSL2 hosts
// route through the Windows bridge; native hosts call the
// language_server's gRPC endpoint directly.
func FetchMarkdownTrajectory(ctx context.Context, conversationID string, timeout time.Duration) (string, error) {
	if conversationID == "" {
		return "", errors.New("antigravity.FetchMarkdownTrajectory: conversationID empty")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if isWSL() {
		return invokeBridgeFromWSL(ctx, conversationID, timeout)
	}
	servers, err := discoverLanguageServers()
	if err != nil {
		return "", fmt.Errorf("antigravity.FetchMarkdownTrajectory: discover: %w", err)
	}
	var lastErr error
	for _, ls := range servers {
		endpoint := ls.PreferredEndpoint()
		if endpoint == "" {
			continue
		}
		md, err := callConvertTrajectory(ctx, endpoint, ls.CSRFToken, conversationID, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		return md, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no usable language_server endpoint")
	}
	return "", fmt.Errorf("antigravity.FetchMarkdownTrajectory: %w", lastErr)
}

// ParseMarkdownPlannerResponses parses a markdown trajectory and
// returns ONLY the `### Planner Response` ToolEvents (assistant
// text). User input + inline tool extraction are suppressed because
// structured emission supersedes them at higher fidelity. Used by
// the backfill to recover lost planner_response coverage on
// gemini sessions whose 1.2.20 PLANNER_RESPONSE step is sparse.
func ParseMarkdownPlannerResponses(path, conversationID, projectRoot string, ts time.Time, scrubber Scrubber, markdown string) []models.ToolEvent {
	res := parseMarkdownConversation(path, conversationID, projectRoot, "", ts, scrubber, markdown,
		true, true, false)
	return res.ToolEvents
}

// ConversationsDirs returns the conversation directories
// the backfill should walk for every crossmount-resolved home — both
// the desktop Antigravity layout (`.gemini/antigravity/conversations`)
// and the agy CLI layout (`.gemini/antigravity-cli/conversations`).
// Mirrors codex's helper for symmetry with the dispatcher.
func ConversationsDirs(homes []string) []string {
	var dirs []string
	for _, h := range homes {
		dirs = append(
			dirs,
			h+"/.gemini/antigravity/conversations",
			h+"/.gemini/antigravity-cli/conversations",
		)
	}
	return dirs
}
