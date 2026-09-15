package qoder

import (
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// layout is the closed vocabulary of on-disk store shapes this adapter
// claims. Every downstream decision (which parser runs, which cursor
// semantics apply, which capture surface is stamped) dispatches on a
// layout resolved ONCE at the path boundary — never on a tool name and
// never on a re-sniff of the file contents (CLAUDE.md module rules #3
// and #5).
type layout int

const (
	// layoutUnknown is "not a qoder store file". Never emitted.
	layoutUnknown layout = iota
	// layoutCLITranscript is the flat per-session transcript the
	// terminal binary writes: `projects/<slug>/<uuid>.jsonl`.
	layoutCLITranscript
	// layoutIDETranscript is the transcript the Qoder IDE (a VS Code
	// fork, `vscodehost` product token "qoder") writes for an in-editor
	// agent task: `projects/<slug>/transcript/<task-id>.jsonl`. Same
	// record shape as the CLI transcript, different subtree.
	layoutIDETranscript
	// layoutSegment is a run-log segment:
	// `logs/sessions/<slug>/<sid>/segments/<ts>-<rand>-p<pid>.jsonl`.
	layoutSegment
	// layoutWorkDB is Qoder Work's desktop store, `main.sqlite` in the
	// app-identifier directory. See work.go.
	layoutWorkDB
)

// hostQoder is the lowercase host token for Qoder's own IDE — the same
// token internal/platform/vscodehost carries for the Qoder VS Code fork,
// so the IDE surface reads identically no matter which subsystem stamped
// it. It doubles as the CLI's host token: one vendor, one binary family.
const hostQoder = "qoder"

// hostQoderWork is the host token for Qoder Work, the separate desktop
// app that DRIVES qodercli (see work.go). It is a surface host, not a
// tool id — see docs/qoder-adapter.md "§2.1 decision".
const hostQoderWork = "qoder-work"

// ideSessionIDSuffix is the Qoder IDE's session-id shape, grounded
// 2026-09-03 against a live in-editor run: `task-<20 hex>.session.execution`
// (both the `sessionId` inside every record and the transcript basename).
// A CLI session id is a plain uuid, so the suffix is an unambiguous
// discriminator that works even where the path shape is not available —
// e.g. a run-log segment, whose `<sid>` path segment is the only clue.
const ideSessionIDSuffix = ".session.execution"

// transcriptDir is the subdirectory the IDE interposes between the
// project slug and its transcript files. GROUNDED 2026-09-03: the IDE
// writes `~/.qoder/projects/<slug>/transcript/<task>.session.execution.jsonl`
// while the CLI writes `~/.qoder/projects/<slug>/<uuid>.jsonl` directly in
// the slug dir. (The two also disagree on slug spelling — the IDE emitted
// `c-Users-…` where the CLI emitted `c--Users-…` for the same cwd — which
// is why the slug is never used for anything but directory naming; the
// project root always comes from the record's raw `cwd`.)
const transcriptDir = "transcript"

// layoutSurfaces is the ONE table mapping a store layout onto the capture
// surface it evidences. Values are templates: surfaceFor stamps the
// session id in.
//
// Both CLI-side layouts (the flat transcript and the run-log segment) are
// the same surface — they are two files the same terminal run writes.
//
// The Work DB entry is the only HOSTED row: it comes from the hosting
// desktop app's own store rather than the agent's self-report, so it
// REPLACES a differing stored value (models.SessionSurface.Hosted; see
// store.setHostedSessionSurface). This is exactly the case the seam was
// built for — a Work-driven run truthfully self-reports `entrypoint:"cli"`
// in its own transcript, because it genuinely IS a qodercli process; only
// Qoder Work knows that a person was typing in a desktop chat tab.
var layoutSurfaces = map[layout]models.SessionSurface{
	layoutCLITranscript: {Surface: models.SurfaceCLI, SurfaceHost: hostQoder},
	layoutSegment:       {Surface: models.SurfaceCLI, SurfaceHost: hostQoder},
	layoutIDETranscript: {Surface: models.SurfaceIDE, SurfaceHost: hostQoder},
	layoutWorkDB:        {Surface: models.SurfaceDesktop, SurfaceHost: hostQoderWork, Hosted: true},
}

// surfaceFor returns the capture-surface stamp for a layout + session id.
//
// The session-id shape is consulted FIRST and overrides the layout: an id
// ending `.session.execution` is an IDE task no matter which of qoder's
// stores the row came out of. That matters for run-log segments, where the
// path shape says only "a qodercli process ran" and the `<sid>` directory
// name is the sole discriminator between an IDE task and a terminal run.
//
// An unmapped layout or an empty session id yields the ZERO value, which
// the caller must NOT emit: no grounded discriminator ⇒ no stamp, never a
// guess (models.SessionSurface's honesty rule).
func surfaceFor(l layout, sessionID string) models.SessionSurface {
	if sessionID == "" {
		return models.SessionSurface{}
	}
	if isIDESessionID(sessionID) {
		s := layoutSurfaces[layoutIDETranscript]
		s.SessionID = sessionID
		return s
	}
	s, ok := layoutSurfaces[l]
	if !ok || s.Surface == "" {
		return models.SessionSurface{}
	}
	s.SessionID = sessionID
	return s
}

// isIDESessionID reports whether a session id carries the Qoder IDE's
// `.session.execution` suffix. Case-insensitive: the id is also a
// filename component, and a case-insensitive mount may hand it back in a
// different case.
func isIDESessionID(sessionID string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(sessionID)), ideSessionIDSuffix)
}

// classify resolves a path onto its layout. Comparison runs on a
// slash-normalized, lower-cased copy so Windows separators and
// case-insensitive mounts classify identically.
//
// It is shape-only and says nothing about watch roots — IsSessionFile
// ANDs it with adapter.UnderAnyWatchRoot, which is what keeps a
// same-shaped file outside the qoder trees unclaimed.
func classify(path string) layout {
	lower := strings.ReplaceAll(strings.ToLower(path), `\`, "/")
	if isWorkDBPath(lower) {
		return layoutWorkDB
	}
	if !strings.HasSuffix(lower, ".jsonl") {
		return layoutUnknown
	}
	if isSegmentPath(lower) {
		return layoutSegment
	}
	if !strings.Contains(lower, "/.qoder/projects/") {
		return layoutUnknown
	}
	// The IDE interposes a `transcript/` directory; the CLI writes the
	// uuid file directly in the slug dir.
	if filepath.Base(filepath.Dir(lower)) == transcriptDir {
		return layoutIDETranscript
	}
	return layoutCLITranscript
}

// isSegmentPath reports whether a slash-normalized lower-cased path is a
// run-log segment file.
func isSegmentPath(lower string) bool {
	return strings.Contains(lower, "/.qoder/logs/sessions/") &&
		strings.Contains(lower, "/segments/")
}
