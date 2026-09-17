package dashboard

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsview"
	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// -----------------------------------------------------------------------------
// Agent-guidance inventory API.
//
//	GET /api/projects/guidance?root=<abs>              → inventory for one root
//	GET /api/projects/guidance/file?root=<abs>&rel=…   → one file's body
//	GET /api/projects/guidance/summary                 → per-root roll-up
//
// The inventory itself is metadata the scan loop already persisted (names,
// sizes, hashes, front-matter) — no filesystem work happens on the inventory
// request. Only the /file endpoint touches disk, and it does so through the
// SAME capped, symlink-safe reader the per-terminal project panel uses
// (internal/fsview), then scrubs the text. There is no raw mode: a guidance
// file is prose an operator may have pasted a token into, and the viewer is a
// convenience, not an export.
//
// Two containment rules, both structural:
//
//  1. `root` must be a project root the store already knows. Without this the
//     endpoint would be an arbitrary-directory reader with an fsview fig leaf.
//  2. `rel` is resolved by fsview, which rejects absolute paths, traversal and
//     symlink escapes and never echoes an absolute path in its errors. A
//     user-scope row ("~/…") anchors at the operator's home instead of the
//     project root — see guidanceFileAnchor — because that is where the file
//     actually is; without it the panel offered a link that always 404'd.
// -----------------------------------------------------------------------------

// guidanceReadCap is the per-file read cap the guidance viewer applies. The
// same 256KB fsview default the project panel uses — a guidance file far past
// that is pathological, and the caller is told it was truncated.
const guidanceReadCap = fsview.DefaultMaxReadBytes

// guidanceToolsMeasurable is THE static answer to "can Observer tell you
// whether this tool actually USED a guidance file?" — a per-tool capability
// flag, not a per-tool behaviour branch (CLAUDE.md #3: the surface renders
// from the flag, it does not switch on the tool name).
//
// true means the tool emits a capture signal Observer already ingests that
// names a guidance file, AND that signal's target is GROUNDED against a real
// transcript — because since wave 2 this flag no longer merely enables a
// sentence, it enables a per-file COUNT, and a count of zero prints as "never
// invoked". Claiming measurability for a signal whose target might be empty or
// might be a path spelled differently from the inventory turns an unverified
// join into a fabricated statement of disuse. That is worse than saying
// nothing.
//
// Only claude-code clears that bar today:
//   - `skill_invoke` from the `Skill` tool call, whose target is the skill
//     NAME (internal/adapter/claudecode/adapter.go::extractTarget, grounded
//     against a live transcript in wave 2), and
//   - `instructions_loaded` from its hook (cmd/observer/hook.go,
//     buildClaudeInstructionsLoadedEvent), whose target is the file path.
//     No other adapter produces this signal at all.
//
// DELIBERATELY NOT LISTED, pending grounding: deepseek, muse, mistral-code and
// freebuff each map a native skill call onto models.ActionSkillInvoke
// (internal/tooltax/table.go), so the ACTION exists — but their targets come
// from adapter-specific extraction that has never been checked against a real
// session, and may be a path or empty. Each becomes `true` here when a
// per-adapter fixture test pins what its skill_invoke target actually
// contains, not before. Until then those tools render "usage is not
// measurable", which is exactly true.
//
// A tool absent from this map is false: absence is the zero value and the zero
// value is the honest one.
var guidanceToolsMeasurable = map[string]bool{
	"claude-code": true,
}

// guidanceMeasurableFor projects the static table onto the tools actually
// present in one inventory, so the wire map answers exactly the questions the
// rows raise — never the whole registry.
func guidanceMeasurableFor(rows []store.GuidanceRow) map[string]bool {
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[r.Tool] = guidanceToolsMeasurable[r.Tool]
	}
	return out
}

// The per-row usage enum. Three values, and the third is the whole point:
// `not_measurable` is NOT a zero count, it is the absence of any capture
// signal that could name this file. A surface that collapses it into
// `never_invoked` is fabricating evidence of disuse.
const (
	guidanceUsageInvoked       = "invoked"
	guidanceUsageNeverInvoked  = "never_invoked"
	guidanceUsageNotMeasurable = "not_measurable"
)

// guidanceKindSignal is the per-KIND half of measurability: which capture
// signal, if any, can ever name a guidance file of this kind. A kind absent
// here (agent, command, rule, config) has no naming signal from ANY tool, so
// its rows are always `not_measurable` however capable the tool is.
var guidanceKindSignal = map[string]string{
	string(guidance.KindSkill):        models.ActionSkillInvoke,
	string(guidance.KindInstructions): models.ActionInstructionsLoaded,
}

// guidanceSignalEmitters is the per-TOOL half: which tools emit each signal
// WITH A GROUNDED TARGET. skill_invoke reuses guidanceToolsMeasurable, which
// is narrower than the skill_invoke taxonomy row set on purpose (see that
// table's comment); instructions_loaded comes only from Claude Code's hook
// (cmd/observer/hook.go::buildClaudeInstructionsLoadedEvent) and no adapter
// produces an equivalent.
var guidanceSignalEmitters = map[string]map[string]bool{
	models.ActionSkillInvoke:        guidanceToolsMeasurable,
	models.ActionInstructionsLoaded: {"claude-code": true},
}

// guidanceUsageMeasurable resolves both halves: can Observer observe THIS
// tool using a guidance file of THIS kind? It is a capability lookup, not a
// tool-name branch (CLAUDE.md #3/#5) — a new adapter that gains a skill_invoke
// taxonomy row becomes measurable by adding one map entry, not a case.
func guidanceUsageMeasurable(tool, kind string) bool {
	signal, ok := guidanceKindSignal[kind]
	if !ok {
		return false
	}
	return guidanceSignalEmitters[signal][tool]
}

// guidanceRowOut is one inventory row plus its joined usage facts. The
// embedded store.GuidanceRow flattens into the same JSON object it always
// produced, so the addition is purely additive for an older frontend.
type guidanceRowOut struct {
	store.GuidanceRow
	// InvokedCount / LastInvokedAt come from skill_invoke actions joined on
	// guidance.SkillKey. LoadedCount / LastLoadedAt come from
	// instructions_loaded actions joined on the file's absolute path.
	InvokedCount  int    `json:"invoked_count"`
	LastInvokedAt string `json:"last_invoked_at,omitempty"`
	LoadedCount   int    `json:"loaded_count"`
	LastLoadedAt  string `json:"last_loaded_at,omitempty"`
	// Usage is one of invoked / never_invoked / not_measurable.
	Usage string `json:"usage"`
}

// guidanceRowsWithUsage folds one project's usage aggregate onto its
// inventory rows. Both joins are lookups against pre-normalized keys, so this
// is O(rows) and does no further SQL.
//
// available=false means the usage read did not happen (timed out, or failed).
// Every row then reports `not_measurable` — the ONE honest degrade, because
// "we could not measure this" is literally what happened. Reporting
// never_invoked instead would turn a database timeout into a claim about the
// operator's skills.
func guidanceRowsWithUsage(rows []store.GuidanceRow, usage store.GuidanceUsage, available bool) []guidanceRowOut {
	out := make([]guidanceRowOut, 0, len(rows))
	for _, r := range rows {
		o := guidanceRowOut{GuidanceRow: r, Usage: guidanceUsageNotMeasurable}
		if !available {
			out = append(out, o)
			continue
		}
		if stat, ok := usage.Skills[guidance.SkillKey(r.Tool, guidance.Kind(r.Kind), r.Name)]; ok {
			o.InvokedCount = stat.Count
			o.LastInvokedAt = guidanceStamp(stat.Last)
		}
		if r.AbsPath != "" {
			if stat, ok := usage.Files[filepath.Clean(r.AbsPath)]; ok {
				o.LoadedCount = stat.Count
				o.LastLoadedAt = guidanceStamp(stat.Last)
			}
		}
		if guidanceUsageMeasurable(r.Tool, r.Kind) {
			if o.InvokedCount > 0 || o.LoadedCount > 0 {
				o.Usage = guidanceUsageInvoked
			} else {
				o.Usage = guidanceUsageNeverInvoked
			}
		}
		out = append(out, o)
	}
	return out
}

// guidanceStamp renders a usage timestamp, or the empty string for "never"
// so the omitempty tag keeps the key off the wire entirely rather than
// shipping a zero time a frontend would render as 1 January year 1.
func guidanceStamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// guidanceInventoryResp is the wire shape of GET /api/projects/guidance.
type guidanceInventoryResp struct {
	Root string `json:"root"`
	// ScannedAt is the most recent last_scanned across the returned rows,
	// RFC3339. Empty means this root has never been scanned — distinct
	// from "scanned and found nothing", which returns a zero-length rows
	// array WITH a timestamp.
	ScannedAt string           `json:"scanned_at,omitempty"`
	Rows      []guidanceRowOut `json:"rows"`
	// ToolsMeasurable answers, per tool present in Rows, whether Observer
	// can observe that tool USING its guidance files. See the table above.
	ToolsMeasurable map[string]bool `json:"tools_measurable"`
	// UsageWindowDays is the lookback the per-row counts cover, so a
	// surface can say "invoked 4x in 90d" without hard-coding the number.
	UsageWindowDays int `json:"usage_window_days"`
	// UsageSince is the exact start of that window, RFC3339.
	UsageSince string `json:"usage_since,omitempty"`
	// UsageUnavailable reports that the usage read did not complete, so
	// every row's `usage` is not_measurable for that reason rather than
	// because the tool emits no signal. A surface MUST distinguish the two:
	// one is "Observer cannot see this", the other is "Observer did not
	// look this time".
	UsageUnavailable bool `json:"usage_unavailable,omitempty"`
	// UsageErrorClass is a short closed enum (timeout | query), never the
	// driver's message — the inventory route is remote-reachable and a raw
	// SQL error is host detail.
	UsageErrorClass string `json:"usage_error_class,omitempty"`
}

// guidanceUsageTimeout bounds the usage join on a dashboard GET.
//
// The dashboard server sets only ReadHeaderTimeout, so nothing upstream of
// this handler would ever cut a slow query off: a cold seek over a
// multi-gigabyte actions table would simply hang the panel with no inventory
// at all, even though the inventory itself is a cheap read that was already
// done. Three seconds is well past the warm case and well short of a user
// deciding the page is broken.
const guidanceUsageTimeout = 3 * time.Second

// Closed vocabulary for guidanceInventoryResp.UsageErrorClass.
const (
	guidanceUsageErrTimeout = "timeout"
	guidanceUsageErrQuery   = "query"
)

// guidanceUsageFn is the usage-read seam, so the fail-soft branch is testable
// without a slow database. Nil means the real store read.
type guidanceUsageFn func(ctx context.Context, root string) (store.GuidanceUsage, error)

// readGuidanceUsage runs the usage join under its own deadline and converts
// every failure into the fail-soft triple (zero usage, available=false, error
// class). It never returns an error: the inventory is the primary answer and
// must still be served.
func readGuidanceUsage(ctx context.Context, read guidanceUsageFn, root string) (store.GuidanceUsage, bool, string) {
	uctx, cancel := context.WithTimeout(ctx, guidanceUsageTimeout)
	defer cancel()

	usage, err := read(uctx, root)
	if err == nil {
		return usage, true, ""
	}
	class := guidanceUsageErrQuery
	// The CALLER going away is not a usage failure (the response is
	// discarded anyway); only our own deadline is a timeout.
	if errors.Is(err, context.DeadlineExceeded) || (uctx.Err() != nil && ctx.Err() == nil) {
		class = guidanceUsageErrTimeout
	}
	return store.GuidanceUsage{}, false, class
}

// guidanceFileResp is the wire shape of GET /api/projects/guidance/file.
type guidanceFileResp struct {
	RelPath   string `json:"rel_path"`
	Content   string `json:"content"`
	Truncated bool   `json:"truncated"`
	// Scrubbed is always true — the viewer has no raw mode.
	Scrubbed bool `json:"scrubbed"`
}

// handleProjectGuidance serves the per-root guidance inventory.
func (s *Server) handleProjectGuidance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProjectError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	root, ok := s.knownProjectRoot(r)
	if !ok {
		writeProjectError(w, http.StatusNotFound, "unknown_root")
		return
	}
	st := store.New(s.db())
	rows, err := st.ListGuidance(r.Context(), root, false)
	if err != nil {
		writeErr(w, err)
		return
	}
	if rows == nil {
		rows = []store.GuidanceRow{}
	}
	sortGuidanceRows(rows)

	resp := buildGuidanceInventoryResp(r.Context(), root, rows,
		func(ctx context.Context, root string) (store.GuidanceUsage, error) {
			return st.GuidanceUsage(ctx, root, time.Time{})
		})
	// One line at WARN per degraded request: a panel that quietly stops
	// reporting usage is exactly the kind of silent degrade an operator
	// should be told about once. A cancelled CALLER is not a degrade.
	if resp.UsageUnavailable && r.Context().Err() == nil && s.opts.Logger != nil {
		s.opts.Logger.Warn("dashboard: guidance usage join unavailable, serving inventory without it",
			slog.String("class", resp.UsageErrorClass))
	}
	writeJSON(w, resp)
}

// buildGuidanceInventoryResp assembles the inventory response around a
// BOUNDED, FAIL-SOFT usage read.
//
// It is a separate function from the handler for one reason: the degraded
// branch is the interesting one, and it is testable here with an injected
// failing or slow `read` instead of a genuinely slow database.
func buildGuidanceInventoryResp(
	ctx context.Context,
	root string,
	rows []store.GuidanceRow,
	read guidanceUsageFn,
) guidanceInventoryResp {
	// The usage join is a second read of the SAME database, over the biggest
	// table in it. The inventory is the primary answer and a slow or failing
	// aggregate must never take it down — so the read is bounded and its
	// failure degrades every row to not_measurable, flagged explicitly.
	// Degrading to never_invoked instead would turn a database timeout into
	// a claim about the operator's skills.
	usage, usageOK, usageErrClass := readGuidanceUsage(ctx, read, root)

	var newest time.Time
	for _, row := range rows {
		if row.LastScanned.After(newest) {
			newest = row.LastScanned
		}
	}
	var scannedAt string
	if !newest.IsZero() {
		scannedAt = newest.UTC().Format(time.RFC3339)
	}
	return guidanceInventoryResp{
		Root:             root,
		ScannedAt:        scannedAt,
		Rows:             guidanceRowsWithUsage(rows, usage, usageOK),
		ToolsMeasurable:  guidanceMeasurableFor(rows),
		UsageWindowDays:  store.GuidanceUsageWindowDays,
		UsageSince:       guidanceStamp(usage.Since),
		UsageUnavailable: !usageOK,
		UsageErrorClass:  usageErrClass,
	}
}

// handleProjectGuidanceFile serves one guidance file's scrubbed body.
//
// Classed alongside the per-terminal project-file route: it is a View-tier
// GET, and a remote-exposed caller is refused unless the owner has turned on
// [remote].allow_terminal_view — file CONTENT is at least as sensitive as
// terminal output, and the inventory (paths only) is the lighter surface a
// remote caller keeps.
func (s *Server) handleProjectGuidanceFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProjectError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	// Remote gate FIRST, before the root is even resolved, so the response
	// cannot be used as a project-root oracle.
	if remoteExposedFromContext(r.Context()) && !s.allowTerminalView() {
		writeProjectError(w, http.StatusForbidden, "remote_view_disabled")
		return
	}
	root, ok := s.knownProjectRoot(r)
	if !ok {
		writeProjectError(w, http.StatusNotFound, "unknown_root")
		return
	}
	rel := r.URL.Query().Get("rel")
	if rel == "" {
		writeProjectError(w, http.StatusBadRequest, "bad_path")
		return
	}
	anchor, cleanRel, ok := guidanceFileAnchor(root, rel)
	if !ok {
		writeProjectError(w, http.StatusNotFound, "not_found")
		return
	}
	c, err := fsview.Read(r.Context(), anchor, cleanRel, guidanceReadCap)
	if err != nil {
		status, code := projectFsErr(err)
		writeProjectError(w, status, code)
		return
	}
	// A binary file is not guidance. fsview reports it with empty Data; say
	// so rather than returning an empty body that reads like an empty file.
	if c.Binary {
		writeProjectError(w, http.StatusBadRequest, "bad_path")
		return
	}
	writeJSON(w, guidanceFileResp{
		RelPath:   rel,
		Content:   scrub.New().String(c.Data),
		Truncated: c.Truncated,
		Scrubbed:  true,
	})
}

// guidanceFileAnchor resolves one requested inventory path to the (root, rel)
// pair fsview needs — the same rule internal/mcp's guidanceReadAnchor applies,
// because the panel makes BOTH scopes clickable.
//
// A user-scope row's rel_path is written "~/…" (internal/guidance's
// convention) and lives under the operator's home, not under the project; a
// project-scope row anchors at the project root. Containment is still
// fsview's: anchoring on a DIRECTORY and resolving the relative path inside it
// is what makes that containment mean something, rather than trusting a stored
// absolute path.
func guidanceFileAnchor(projectRoot, rel string) (anchor, cleanRel string, ok bool) {
	if strings.HasPrefix(rel, "~/") {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", "", false
		}
		rel = strings.TrimPrefix(rel, "~/")
		if rel == "" {
			return "", "", false
		}
		return home, rel, true
	}
	if projectRoot == "" || rel == "" {
		return "", "", false
	}
	return projectRoot, rel, true
}

// handleProjectGuidanceSummary serves the per-root roll-up: one entry per
// project root that has any guidance row, newest scan first. A bare JSON
// array — the frontend's project picker consumes it directly.
func (s *Server) handleProjectGuidanceSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProjectError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	rows, err := store.New(s.db()).GuidanceProjects(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	if rows == nil {
		rows = []store.GuidanceProjectSummary{}
	}
	writeJSON(w, rows)
}

// knownProjectRoot resolves the ?root= query parameter against the set of
// project roots the store knows, and reports ok=false for anything else.
//
// This is the containment rule that keeps /file from being an arbitrary-file
// reader: fsview guarantees "inside SOME root", this guarantees "inside a root
// the observer already recorded for itself".
func (s *Server) knownProjectRoot(r *http.Request) (string, bool) {
	want := filepath.Clean(r.URL.Query().Get("root"))
	if want == "" || want == "." {
		return "", false
	}
	roots, err := store.New(s.db()).ProjectRoots(r.Context())
	if err != nil {
		return "", false
	}
	for _, root := range roots {
		if filepath.Clean(root) == want {
			// The CLEANED spelling is what every caller needs: a
			// projects.root_path stored with a trailing slash would
			// otherwise be handed to ListGuidance, whose rows are keyed by
			// the cleaned root the scan pass wrote — and the panel would
			// render empty for a project that has an inventory.
			return want, true
		}
	}
	return "", false
}

// sortGuidanceRows orders an inventory the way the panel renders it: by tool,
// then kind, then relative path. Exported behaviour is the ORDER, which the
// frontend relies on for stable grouping.
func sortGuidanceRows(rows []store.GuidanceRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Tool != b.Tool {
			return a.Tool < b.Tool
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.RelPath < b.RelPath
	})
}
