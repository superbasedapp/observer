package cursor

import (
	"context"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// SessionRootLookup resolves a session's STORED project root ("" when
// the session is unknown or has none). *store.Store's
// ProjectRootForSession satisfies it.
type SessionRootLookup func(ctx context.Context, sessionID string) (string, error)

// ResolveSyntheticRoots rewrites SyntheticProjectRoot on events and
// tokens to the session's real root wherever one is known, so a
// root-less hook payload (Cursor sends `workspace_roots: []` on some
// events even for a folder window) never moves a folder session onto
// the placeholder: store.UpsertSession overwrites project_id with the
// incoming event's project, and the event's action row carries it too.
//
// Resolution order per session: a real root carried by another event or
// token of the SAME batch (a replay batch interleaves rooted and
// root-less events), then lookup (the stored session's root), then the
// placeholder — which is only ever right for a conversation nothing
// else has rooted (a Cloud Agent, an empty-window chat). A nil lookup
// resolves batch-locally only. The first lookup error is returned after
// every resolvable row is rewritten; rows whose lookup failed get an
// EMPTY root (never the placeholder, which could flip a folder session).
func ResolveSyntheticRoots(ctx context.Context, events []models.ToolEvent, tokens []models.TokenEvent, lookup SessionRootLookup) error {
	batch := map[string]string{}
	note := func(sid, root string) {
		if sid == "" || root == "" || root == SyntheticProjectRoot {
			return
		}
		if _, ok := batch[sid]; !ok {
			batch[sid] = root
		}
	}
	for _, e := range events {
		note(e.SessionID, e.ProjectRoot)
	}
	for _, t := range tokens {
		note(t.SessionID, t.ProjectRoot)
	}
	resolved := map[string]string{}
	var firstErr error
	resolve := func(sid string) string {
		if r, ok := batch[sid]; ok {
			return r
		}
		if r, ok := resolved[sid]; ok {
			return r
		}
		r := SyntheticProjectRoot
		if lookup != nil && sid != "" {
			got, err := lookup(ctx, sid)
			switch {
			case err != nil:
				// Unknown whether the session has a real project: never
				// risk flipping it. "" makes the store attach a token only
				// to an existing session and skip an action row (the
				// hooks-log replay recovers it later).
				r = ""
				if firstErr == nil {
					firstErr = fmt.Errorf("cursor.ResolveSyntheticRoots: %s: %w", sid, err)
				}
			case got != "":
				r = got
			}
		}
		resolved[sid] = r
		return r
	}
	for i := range events {
		if events[i].ProjectRoot == SyntheticProjectRoot {
			events[i].ProjectRoot = resolve(events[i].SessionID)
		}
	}
	for i := range tokens {
		if tokens[i].ProjectRoot == SyntheticProjectRoot {
			tokens[i].ProjectRoot = resolve(tokens[i].SessionID)
		}
	}
	return firstErr
}

// reconcileReplay applies the two cross-path rules to one hooks-log
// replay batch before it reaches the store:
//
//  1. A conversation whose activity the transcript / state.vscdb path
//     already captured (transcriptCheck) keeps only its usage and its
//     outcome updates: the replay's action rows would be a second,
//     differently-keyed copy of the same turns (`cursor:hook` vs the
//     transcript's own identity), which no UNIQUE key can catch. This
//     mirrors hookCheck, which makes the transcript path defer to hook
//     rows in the other direction.
//  2. Root-less events resolve to the session's real root
//     (ResolveSyntheticRoots).
func (a *Adapter) reconcileReplay(ctx context.Context, res *adapter.ParseResult) {
	if a.transcriptCheck != nil && len(res.ToolEvents) > 0 {
		covered := map[string]bool{}
		kept := res.ToolEvents[:0]
		for _, ev := range res.ToolEvents {
			c, ok := covered[ev.SessionID]
			if !ok {
				has, err := a.transcriptCheck(ctx, ev.SessionID)
				if err != nil {
					res.Warnings = append(res.Warnings,
						fmt.Sprintf("cursor: transcript-check for %s failed (%v); replaying its hook rows", ev.SessionID, err))
				}
				c = err == nil && has
				covered[ev.SessionID] = c
			}
			if !c {
				kept = append(kept, ev)
			}
		}
		res.ToolEvents = kept
	}
	if err := ResolveSyntheticRoots(ctx, res.ToolEvents, res.TokenEvents, a.rootLookup); err != nil {
		res.Warnings = append(res.Warnings, err.Error())
	}
}
