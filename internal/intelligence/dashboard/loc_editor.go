package dashboard

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Human line capture, daemon side (plan §3.3).
//
// The VS Code extension computes a save's line deltas locally and POSTs
// the COUNTS here. No file content, no diff, no patch, no path in the
// clear past this handler: the path arrives workspace-relative and is
// hashed before it reaches the database.
//
// INTEGRITY POSTURE, stated plainly because the UI relies on it.
// This is a loopback endpoint on a single-user machine. It is classified
// CapabilityLocal, so it is refused outright on any remotely-exposed
// bind, before a principal is even resolved; browserGuard additionally
// requires a loopback Host and rejects a cross-origin POST from a web
// page. What remains is that ANY LOCAL PROCESS on the machine can post
// counts. That is accepted, and it is why these counts are never used
// for enforcement, gating, or any per-developer judgement — they are
// reporting about the operator's own machine, to the operator.
//
// A per-install shared secret narrows that last gap. The daemon generates
// it on first start into [loc].editor_token_file (mode 0600) and the
// extension reads the same file, so a local process that is NOT the
// developer's editor can no longer forge saves without first reading a
// file only this user can open. It is not a defence against the user's own
// other processes — anything running as this user can read a 0600 file —
// which is why [loc].editor_token_required is a hardening step and not a
// security boundary. See locEditorAuth for the exact decision.

// locEditorMaxBody caps the request body. The payload is ~500 bytes of
// counts; 16 KiB is three orders of magnitude of headroom and still
// makes an accidental content POST impossible to land.
const locEditorMaxBody = 16 << 10

// The secret's LIFECYCLE lives in cmd/observer/loc_token.go, not here:
// generate on first daemon start into [loc].editor_token_file (mode 0600),
// read back on every later start, honour the deprecated
// OBSERVER_LOC_EDITOR_TOKEN override for one release. This package receives
// only the resolved VALUE (Options.LocEditorToken) and never touches the
// filesystem or the environment for it, so a handler test needs neither.

// locEditorTokenHeader is the header the extension sends the secret in.
const locEditorTokenHeader = "X-Observer-Token"

// locEditorTokenSettingName is the config key named in a 401 body, so an
// operator debugging a refused save is told what to look at rather than
// left with a bare status code.
const locEditorTokenSettingName = "[loc].editor_token_required" //nolint:gosec // G101: config-key NAME for the error body, not a credential

// locEditorAuth is the endpoint's token decision, split out of the handler
// so the (required × present × matches) matrix is table-testable without an
// HTTP round trip.
//
// The three-way rule, stated once:
//
//   - No configured token at all: nothing to check. The endpoint keeps the
//     loopback + Origin posture described at the top of this file. When
//     required is set but the daemon holds no token, requiring one would
//     refuse every save forever with no way for the extension to comply,
//     so this fails OPEN and the daemon warns at start instead.
//   - A request that CARRIES a token is always verified, required or not.
//     Silently accepting a wrong token would make the credential
//     decorative — the caller believes it authenticated and did not.
//   - A request with NO token is accepted while required is false (an
//     extension older than the token file sends nothing) and refused once
//     required is true.
//
// Comparison is constant time: the endpoint is reachable by any local
// process, which is exactly the position from which a timing oracle on a
// 32-byte secret is practical.
func locEditorAuth(configured, presented string, required bool) bool {
	if configured == "" {
		return true
	}
	if presented == "" {
		return !required
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(configured)) == 1
}

// locEditorAttributionWindow is how stale a session may be and still
// claim an editor save. A developer who saves a file half an hour after
// their agent stopped is doing their own work, not continuing the
// agent's; past this the save books to the project-day bucket with no
// session.
const locEditorAttributionWindow = 30 * time.Minute

// The echo window is owned by internal/store (store.LOCEchoBefore /
// LOCEchoAfter), NOT redeclared here. This handler checks FORWARD at save
// time; the store's deferred pass checks BACKWARD when the AI row finally
// lands. Two copies of the window would let those two directions disagree
// about what counts as the same event.
const (
	locEchoBefore = store.LOCEchoBefore
	locEchoAfter  = store.LOCEchoAfter
)

// LOCStatsRequest is the count payload for one side of a save. It mirrors
// loc.Stats and is deliberately the ONLY numeric shape the endpoint
// accepts — there is no field here that could carry text.
type LOCStatsRequest struct {
	AddedCode      int `json:"added_code"`
	ModifiedCode   int `json:"modified_code"`
	DeletedCode    int `json:"deleted_code"`
	AddedComment   int `json:"added_comment"`
	DeletedComment int `json:"deleted_comment"`
	Whitespace     int `json:"whitespace"`
	Blank          int `json:"blank"`
	Unknown        int `json:"unknown"`
}

// toStats converts the request shape into the internal bucket set,
// clamping negatives to zero. A negative count is not a smaller number,
// it is a broken producer, and letting one through would silently reduce
// a session's totals.
func (r LOCStatsRequest) toStats() loc.Stats {
	nonNeg := func(v int) int {
		if v < 0 {
			return 0
		}
		return v
	}
	return loc.Stats{
		AddedCode:      nonNeg(r.AddedCode),
		ModifiedCode:   nonNeg(r.ModifiedCode),
		DeletedCode:    nonNeg(r.DeletedCode),
		AddedComment:   nonNeg(r.AddedComment),
		DeletedComment: nonNeg(r.DeletedComment),
		Whitespace:     nonNeg(r.Whitespace),
		Blank:          nonNeg(r.Blank),
		Unknown:        nonNeg(r.Unknown),
	}
}

// EditorChangeRequest is the body of POST /api/loc/editor-change.
type EditorChangeRequest struct {
	// Path is workspace-RELATIVE, forward-slashed. It is hashed here and
	// never stored.
	Path string `json:"path"`
	// WorkspaceRoot is the absolute path of the editor's workspace
	// folder, used only to find the matching project row.
	WorkspaceRoot string `json:"workspace_root"`
	Language      string `json:"language"`
	Category      string `json:"category"`
	// Human is the developer's own delta: last-clean-snapshot vs the
	// will-save text.
	Human LOCStatsRequest `json:"human"`
	// System is the formatter's delta: will-save text vs saved text. It
	// is a real, separately-labelled actor, NOT a command class — there
	// is no command that reports "a formatter ran".
	System           LOCStatsRequest `json:"system"`
	HumanConfidence  string          `json:"human_confidence"`
	SystemConfidence string          `json:"system_confidence"`
	// SavedAt is the EDITOR's clock. It is compared against ACTION
	// timestamps by the echo reconciliation, never against ingest time.
	SavedAt           string `json:"saved_at"`
	ClassifierVersion int    `json:"classifier_version"`
	// PossibleAgent says the extension saw the buffer change in a shape
	// a person's keystrokes do not produce — a multi-range or whole-range
	// replacement landing at once — while the document was DIRTY.
	//
	// This is the in-editor-agent hole (review finding M7). Copilot Chat
	// agent mode, the Cline and Kilo VS Code extensions and Cursor all
	// apply their edits through a WorkspaceEdit, which dirties the buffer
	// exactly the way typing does; the extension's on-disk-reload
	// safeguard only fires on a CLEAN document, so those lines were
	// booked as the developer's.
	//
	// The flag is honest about being a HEURISTIC, and the daemon treats
	// it as such: the row is recorded as `unknown`, never reassigned to
	// the agent. Observer did not see which agent wrote it, and inventing
	// an attribution would be the same error in the other direction.
	// An older extension omits the field, which decodes as false and
	// leaves the previous behaviour byte for byte.
	PossibleAgent bool `json:"possible_agent"`
}

// EditorChangeResponse tells the extension what happened, so it can be
// debugged without turning on daemon logging.
type EditorChangeResponse struct {
	// Recorded is how many rows were written (0, 1 or 2 — human and
	// system are separate rows).
	Recorded int `json:"recorded"`
	// SessionID is the session the save attributed to, empty when it fell
	// through to the project-day bucket.
	SessionID string `json:"session_id,omitempty"`
	// Echo reports that the save was recognised as the echo of an AI
	// write and recorded as such rather than as human authorship.
	Echo bool `json:"echo"`
	// Note explains a zero-row outcome in words.
	Note string `json:"note,omitempty"`
}

// handleLOCEditorChange serves POST /api/loc/editor-change.
func (s *Server) handleLOCEditorChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !locEditorAuth(
		strings.TrimSpace(s.opts.LocEditorToken),
		strings.TrimSpace(r.Header.Get(locEditorTokenHeader)),
		s.opts.LocEditorTokenRequired,
	) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "invalid or missing " + locEditorTokenHeader,
			"setting": "this daemon requires the per-install editor token (" +
				locEditorTokenSettingName + "); the extension reads it from " +
				"[loc].editor_token_file",
		})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, locEditorMaxBody+1))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if len(body) > locEditorMaxBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var req EditorChangeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	res, err := s.recordEditorChange(r, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("record editor change: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, res)
}

// recordEditorChange is the handler's logic, split out so it is testable
// without an HTTP round trip.
func (s *Server) recordEditorChange(r *http.Request, req EditorChangeRequest) (EditorChangeResponse, error) {
	ctx := r.Context()
	var out EditorChangeResponse

	rel := store.RelativeProjectPath(req.WorkspaceRoot, req.Path)
	if rel == "" {
		out.Note = "no path"
		return out, nil
	}
	human := req.Human.toStats()
	system := req.System.toStats()
	if human.Total() == 0 && system.Total() == 0 {
		out.Note = "no lines changed"
		return out, nil
	}
	// A generated or vendored file is recognised and dropped, exactly as
	// on the AI side — a save of package-lock.json is not authorship.
	if cat := loc.Category(req.Category); cat != "" && !cat.Counted() {
		out.Note = "skipped: " + req.Category
		return out, nil
	}

	savedAt := parseEditorTime(req.SavedAt)
	st := store.New(s.db())

	projectID, err := st.ProjectIDForRoot(ctx, req.WorkspaceRoot)
	if err != nil {
		return out, err
	}
	if projectID == 0 {
		// A workspace observer has never seen is not an error: the
		// developer may simply not have run an agent in it yet. Recording
		// the save against a conjured project would invent a project row
		// from an editor event, which is not this endpoint's job.
		out.Note = "workspace is not a known project"
		return out, nil
	}

	sessionID, err := st.RecentSessionForProject(ctx, projectID, savedAt, locEditorAttributionWindow)
	if err != nil {
		return out, err
	}
	out.SessionID = sessionID

	pathHash := sha256HexString(rel)
	echo, err := st.EditorSaveIsAIEcho(ctx, projectID, pathHash, savedAt, locEchoBefore, locEchoAfter)
	if err != nil {
		return out, err
	}
	out.Echo = echo

	source := store.LOCSourceEditor
	humanActor := store.LOCActorHuman
	switch {
	case echo:
		// The agent wrote these lines; the editor merely saved what the
		// agent produced. Keep the row as evidence, stop counting it as
		// the developer's authorship.
		source = store.LOCSourceEditorEcho
		humanActor = store.LOCActorUnknown
	case req.PossibleAgent:
		// An in-editor agent wrote into the buffer (see PossibleAgent).
		// The SOURCE stays `editor` — an editor really did report this
		// save, and human_capture must keep saying so — but the actor
		// becomes `unknown`, which is the whole truth: these lines were
		// not typed and Observer cannot name who produced them.
		humanActor = store.LOCActorUnknown
	}

	version := req.ClassifierVersion
	if version <= 0 {
		version = loc.Version
	}

	var rows []store.FileChangeRow
	base := store.FileChangeRow{
		SessionID:    sessionID,
		ProjectID:    projectID,
		FilePathHash: pathHash,
		Language:     req.Language,
		Category:     req.Category,
		Source:       source,
		Version:      version,
		SavedAt:      savedAt,
	}
	if human.Total() > 0 {
		row := base
		row.Actor = humanActor
		row.Confidence = normalizeConfidence(req.HumanConfidence)
		row.Stats = human
		rows = append(rows, row)
	}
	if system.Total() > 0 {
		// The formatter's delta is its own actor and its own row. Folding
		// it into the human number would credit the developer with lines
		// gofmt wrote; dropping it would lose them entirely.
		row := base
		row.Actor = store.LOCActorSystem
		row.Confidence = normalizeConfidence(req.SystemConfidence)
		row.Stats = system
		// A system row must not collide with the human row on
		// (session, path, saved_at): offset it by a nanosecond so both
		// survive the editor unique key.
		row.SavedAt = savedAt.Add(time.Nanosecond)
		rows = append(rows, row)
	}

	n, err := st.InsertFileChanges(ctx, rows)
	if err != nil {
		return out, err
	}
	out.Recorded = n
	return out, nil
}

// normalizeConfidence maps an extension-supplied confidence onto the
// closed set, defaulting to medium. An editor's classifier runs over the
// WHOLE file rather than a fragment, so it has strictly more context than
// the AI-side fragment lexer — but it is still a second implementation of
// the same rules, which is why an unrecognised value degrades rather than
// being trusted as high.
func normalizeConfidence(v string) string {
	switch loc.Confidence(strings.ToLower(strings.TrimSpace(v))) {
	case loc.ConfidenceHigh:
		return string(loc.ConfidenceHigh)
	case loc.ConfidenceLow:
		return string(loc.ConfidenceLow)
	default:
		return string(loc.ConfidenceMedium)
	}
}

// parseEditorTime decodes the extension's RFC3339 save time, falling back
// to now when it is absent or unparseable.
func parseEditorTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Now().UTC()
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

// sha256HexString hashes a project-relative path the same way the store
// does. It is a thin local helper so this file need not reach into the
// store package's unexported hashing.
func sha256HexString(s string) string { return store.HashPath(s) }
