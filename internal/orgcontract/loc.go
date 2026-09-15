package orgcontract

// loc.go is the Lines-of-Code tracking org wire (W5 of
// docs/plans/lines-of-code-tracking-plan-2026-09-07.md §3.4). Two AGGREGATE
// row types, composed node-side by internal/store/locsummary.go — which is
// deliberately a SEPARATE FILE from internal/store/orgpush.go so the
// `file_changes` table name never appears in the push seam and the privacy
// sentinel in tests/invariant/privacy_test.go can keep forbidding it there.
//
// WHAT NEVER CROSSES. No per-file rows, no file_path_hash, no path, no patch,
// no digest, no excerpt, no content of any kind. The node-local file_changes
// table stores a per-file grain; what ships is the session-level and day-level
// SUM over it. A path hash is deliberately withheld even though it is already
// a hash: a per-file row set is a file-level activity map of the developer's
// working tree, which is a strictly deeper disclosure than "this session's
// agent wrote N lines of code".
//
// DEFAULT POSTURE (plan §2 / §6 ruling 2). The counts, the classifier version
// and the human-capture flag are the same disclosure class as
// SessionRow.TotalActions — a count of work done — so they ship under the
// DEFAULT metadata-only posture, unlike the session-scoped verbosity/cache/
// process wires which all require shipsRawContent(). The ONE gated field is
// LanguageMixJSON: a language mix says what KIND of files a developer touched
// and is content-adjacent in the same way SessionVerbosityRow's
// CodeByLanguageJSON is, so it rides shipsRawContent() exactly like that one.
//
// HONESTY. HumanCapture is "none" until an editor integration reports saves
// for the session. A consumer must NEVER render an "AI share" percentage while
// it is "none": with no human capture the denominator is unknown and any share
// would read as 100% AI. That rule is the reason the flag is on the wire at
// all rather than being inferred server-side from a zero human count.

// LOCLanguageLines is one entry of a SessionLOCRow's LanguageMixJSON array: a
// canonical internal/loc language id, its internal/loc category, and the file
// and line counts attributed to it. Shared between the store-side encoder
// (internal/store/locsummary.go) and the org rollup-side decoder
// (internal/orgserver/rollup/loc.go) so both agree on the JSON shape without
// either importing the other — the same arrangement as
// VerbosityLanguageBytes.
type LOCLanguageLines struct {
	Language string `json:"language"`
	Category string `json:"category"`
	Files    int64  `json:"files"`
	Lines    int64  `json:"lines"`
}

// SessionLOCRow is the per-session line-count aggregate: ONE row per
// (session, project_root_hash). A session that spans several project roots
// produces several rows, because folding them would attribute one project's
// code to another (plan §0 row 27: three sessions on the reference node span
// multiple projects).
//
// Every count is a LINE count produced by internal/loc at
// ClassifierVersion, summed over the node-local per-file rows after the codex
// invocation/executor duplicate pair has been collapsed. The CODE buckets
// (…Code / …Comment / Whitespace / Blank) cover category=code files only;
// docs and config files are carried as two single totals, deliberately kept
// out of the code numbers (plan §1: "`.md/.txt/.rst` = docs, JSON/YAML/TOML =
// config (own buckets, never code)").
//
// Natural key on the server is (org_id, session_id, project_root_hash);
// re-pushing a recomputed trailing window is idempotent, and a classifier
// version bump replaces the row (MAX/last-write on classifier_version — see
// internal/orgserver/ingest/loc.go).
type SessionLOCRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping
	// rule as every other wire row — see ingest.go forcePusherOrgID /
	// forcePusherEmail). A node is one enrolled member, so UserEmail is the
	// developer these lines belong to.
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// SessionID + ProjectRootHash are the natural key. ProjectRootHash is
	// projects.root_path_hash — the SAME hash SessionRow.ProjectRootHash
	// carries, so the org side can join a LOC row to its project group
	// without any new identifier.
	SessionID       string `json:"session_id"`
	ProjectRootHash string `json:"project_root_hash"`

	// --- AI, main line (actor=ai, sidechain=false, category=code) ---
	AIAddedCode      int64 `json:"ai_added_code"`
	AIModifiedCode   int64 `json:"ai_modified_code"`
	AIDeletedCode    int64 `json:"ai_deleted_code"`
	AIAddedComment   int64 `json:"ai_added_comment"`
	AIDeletedComment int64 `json:"ai_deleted_comment"`
	AIWhitespace     int64 `json:"ai_whitespace"`
	AIBlank          int64 `json:"ai_blank"`
	AIUnknown        int64 `json:"ai_unknown"`

	// --- AI, sidechain (subagent) — SPLIT, never folded into the main line.
	// 47% of edit/write rows on the reference node are subagent work; a
	// panel that folds them together is lying about what the developer's own
	// agent turn produced (plan §0 row 27 / acceptance criterion 8). Only the
	// three code buckets ship: the comment/whitespace/blank detail is a
	// session-card concern, not an org one.
	AISidechainAddedCode    int64 `json:"ai_sidechain_added_code"`
	AISidechainModifiedCode int64 `json:"ai_sidechain_modified_code"`
	AISidechainDeletedCode  int64 `json:"ai_sidechain_deleted_code"`

	// --- Human (actor=human): editor-reported saves ONLY. Never inferred,
	// never derived from "changed outside the agent" (which is not a human
	// signal — plan §1 / M10). Zero here with HumanCapture="none" means NOT
	// MEASURED, not "the developer wrote nothing".
	HumanAddedCode    int64 `json:"human_added_code"`
	HumanModifiedCode int64 `json:"human_modified_code"`
	HumanDeletedCode  int64 `json:"human_deleted_code"`

	// --- System (actor=system): the format-on-save reflow the editor
	// reported between will-save and did-save. Kept separate so a formatter
	// never inflates either the human or the AI number.
	SystemAddedCode    int64 `json:"system_added_code"`
	SystemModifiedCode int64 `json:"system_modified_code"`
	SystemDeletedCode  int64 `json:"system_deleted_code"`

	// UnknownLines is every line the classifier could not attribute to an
	// actor (an unparsable or truncated raw input). It is on the wire, and
	// must stay visible in any UI, precisely so a large unknown can never
	// masquerade as a small AI number.
	UnknownLines int64 `json:"unknown_lines"`

	// DocsLines / ConfigLines are added+modified lines in category=docs
	// (.md/.txt/.rst) and category=config (JSON/YAML/TOML) files, across
	// every actor. Deliberately NOT part of the code totals above.
	DocsLines   int64 `json:"docs_lines"`
	ConfigLines int64 `json:"config_lines"`

	// Files is the number of distinct files this session touched under this
	// project root. LowConfidenceFiles is how many of them the classifier
	// graded below high; OverwriteFiles is how many were whole-content
	// writes whose before-image is a RECONSTRUCTED line count rather than
	// text (plan §3.5: the UI must label these, never present a
	// reconstruction as a measurement).
	Files              int64 `json:"files"`
	LowConfidenceFiles int64 `json:"low_confidence_files"`
	OverwriteFiles     int64 `json:"overwrite_files"`

	// HumanCapture is "none" or "vscode". See the honesty note in this
	// file's doc comment: no consumer may render an AI share while it is
	// "none".
	HumanCapture string `json:"human_capture"`
	// ClassifierVersion is internal/loc.Version — the highest version any
	// contributing row was produced by. The server upserts on it so a
	// backfill after a classifier bump replaces the older row and an older
	// straggler push can never overwrite a newer count.
	ClassifierVersion int64 `json:"classifier_version"`

	// LanguageMixJSON is a JSON-encoded []LOCLanguageLines. THE ONE GATED
	// FIELD: it ships only under ShareOptions.shipsRawContent(), matching
	// SessionVerbosityRow.CodeByLanguageJSON. Empty string when withheld —
	// which a consumer must read as "not shared", never as "no languages".
	LanguageMixJSON string `json:"language_mix_json,omitempty"`
}

// LOCDayRow is the day-bucketed (day, project_root_hash) line-count
// aggregate. It exists for ONE reason (plan §2): editor-reported human work
// that happens OUTSIDE any session — a developer editing by hand with no
// agent running — has no session to attach to, so a session-only wire would
// make a CLI-only-agent developer read as 100% AI. The day bucket carries
// that work.
//
// Bucketed on the EVENT time (the action timestamp / editor save time), never
// on ingest time: a backfill of August must land in August.
//
// Natural key on the server is (org_id, user_email, day, project_root_hash) —
// the same grain cache_summaries uses (migration 068).
type LOCDayRow struct {
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	// Day is the UTC date (YYYY-MM-DD) of the counted changes.
	Day string `json:"day"`
	// ProjectRootHash is projects.root_path_hash, as on SessionLOCRow.
	ProjectRootHash string `json:"project_root_hash"`

	// AICodeLines / HumanCodeLines / SystemCodeLines are added + modified
	// code lines for that actor on that day. Deletions are deliberately NOT
	// summed in: this is a "how much code was authored" trend, and mixing
	// deletions into one number makes a refactor that removes more than it
	// adds look like a productive day and a rewrite look like nothing.
	AICodeLines     int64 `json:"ai_code_lines"`
	HumanCodeLines  int64 `json:"human_code_lines"`
	SystemCodeLines int64 `json:"system_code_lines"`

	// Files is the distinct file count for the bucket.
	Files int64 `json:"files"`
	// HumanCapture is "none" or "vscode" for this bucket, same honesty rule
	// as SessionLOCRow.
	HumanCapture string `json:"human_capture"`
	// ClassifierVersion is internal/loc.Version, upserted MAX-wise.
	ClassifierVersion int64 `json:"classifier_version"`
}
