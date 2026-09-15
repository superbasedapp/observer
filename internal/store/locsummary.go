// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// locsummary.go is the org-wire seam for Lines-of-Code tracking (W5 of
// docs/plans/lines-of-code-tracking-plan-2026-09-07.md §3.4). It is a
// SEPARATE FILE from internal/store/orgpush.go on purpose: orgpush.go
// composes the wire by CALLING the two Select functions below, so the
// `file_changes` table name never appears in the push seam and
// tests/invariant/privacy_test.go can keep forbidding it there by name —
// exactly the arrangement routingsummary.go / patternsorgrows.go use for
// router_decisions / project_patterns.
//
// WHAT LEAVES: two aggregates. One row per (session, project root) and one
// row per (day, project root). Never a per-file row, never a file_path_hash,
// never a path, a patch, a digest or an excerpt. The node-local per-file
// grain that file_changes stores is summed away HERE, before anything is
// handed to orgpush.go — the wire types in internal/orgcontract/loc.go have
// no field that could carry it.
//
// DEDUP: the same collapse locread.go's locDedupCTE performs, widened from
// one session to a window. Codex emits every patch twice (the model's
// invocation row and the executor's patch_apply_end row) under two different
// action_ids; grouping on (session, file, digest, actor, source) and keeping
// the lowest id is what makes the org number match the node card's. Rows with
// an EMPTY digest are never collapsed — an empty digest is the absence of a
// fingerprint, not a shared one.
//
// EDITOR ECHOES ARE NOT COUNTED. A `editor-echo` row is, by construction, a
// second measurement of an AI write that is already counted from its own
// action row; migration 103 states the contract plainly ("kept, never
// counted"). Every query here therefore excludes source='editor-echo' — and
// so does the node side: the exclusion lives inside locread.go's locDedupCTE,
// in BOTH arms, so the node card and this wire answer the same question about
// the same session. (An earlier note here warned that LoadSessionLOC still
// surfaced echoes in its Unattributed bucket; that divergence is closed, and
// neither side may reintroduce it — the filter belongs in the shared collapse
// rule, never in individual queries that can forget it.)
//
// The two arms of the collapse must PARTITION the table, which is why arm 1
// requires a session and arm 2 admits every session-less row. The collapse
// group is session-scoped, so a row with no session can never share a group;
// stating it any other way lets node and org disagree about a shape neither
// of them should be inventing an answer for.

// locOrgWindowDays bounds both recomputes to recently-started sessions /
// recent days. The server upserts by natural key, so re-pushing a window is
// idempotent — the same model every other snapshot wire uses.
const locOrgWindowDays = 7

// locOrgKeepCTE is the window-scoped duplicate collapse. The single bound
// parameter is the window start, bound twice (once per arm).
const locOrgKeepCTE = `
WITH keep AS (
    SELECT MIN(id) AS id
      FROM file_changes
     WHERE session_id IS NOT NULL AND input_digest != ''
       AND source != 'editor-echo' AND saved_at >= ?
     GROUP BY session_id, file_path_hash, input_digest, actor, source
    UNION ALL
    SELECT id
      FROM file_changes
     WHERE (input_digest = '' OR session_id IS NULL)
       AND source != 'editor-echo' AND saved_at >= ?
)`

// locOrgBucket is one (actor, sidechain, category) aggregation cell of the
// per-session read, before it is folded into the flat wire row.
type locOrgBucket struct {
	sessionID      string
	rootHash       string
	actor          string
	sidechain      bool
	category       string
	files          int64
	lowConfidence  int64
	overwrites     int64
	addedCode      int64
	modifiedCode   int64
	deletedCode    int64
	addedComment   int64
	deletedComment int64
	whitespace     int64
	blank          int64
	unknown        int64
	version        int64
	editorRows     int64
}

// locScopeClause turns the org-push project scope into a SQL fragment over
// file_changes.project_id, plus its bound args. noMatch=true means the scope
// selects nothing at all and the caller must ship no rows (never "ship
// everything" — a scope that resolves to nothing is a deliberate empty, not
// an absent filter).
func (s *Store) locScopeClause(ctx context.Context, scope ScopeOptions) (clause string, noMatch bool, err error) {
	filter, noMatch, err := s.resolveScopeFilter(ctx, scope)
	if err != nil {
		return "", false, err
	}
	if noMatch {
		return "", true, nil
	}
	if filter == "" {
		return "", false, nil
	}
	return " AND fc.project_id IN (" + filter + ")", false, nil
}

// SelectSessionLOCSummaries composes the per-session line-count aggregate for
// every session started inside the trailing window: one row per
// (session, project_root_hash), because a session that spans several project
// roots must not have one project's code attributed to another.
//
// withLanguageMix is the ShareOptions.shipsRawContent() gate (plan §2 / §6
// ruling 2). It is a PARAMETER rather than a post-hoc strip so the extra
// per-language query is not even run when the mix is not going to ship.
func (s *Store) SelectSessionLOCSummaries(ctx context.Context, scope ScopeOptions, withLanguageMix bool) ([]orgcontract.SessionLOCRow, error) {
	since := isoSinceDays(locOrgWindowDays)
	scopeClause, noMatch, err := s.locScopeClause(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionLOCSummaries: scope: %w", err)
	}
	if noMatch {
		return nil, nil
	}

	//nolint:gosec // G202: every fragment is a code constant or a ?-bound id list; values bind via ? args.
	q := locOrgKeepCTE + `
SELECT fc.session_id, COALESCE(p.root_path_hash, ''),
       fc.actor, fc.sidechain, fc.category,
       COUNT(DISTINCT fc.file_path_hash),
       COALESCE(SUM(CASE WHEN fc.actor_confidence != 'high' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(fc.overwrite), 0),
       COALESCE(SUM(fc.added_code), 0), COALESCE(SUM(fc.modified_code), 0), COALESCE(SUM(fc.deleted_code), 0),
       COALESCE(SUM(fc.added_comment), 0), COALESCE(SUM(fc.deleted_comment), 0),
       COALESCE(SUM(fc.whitespace), 0), COALESCE(SUM(fc.blank), 0), COALESCE(SUM(fc.unknown), 0),
       COALESCE(MAX(fc.classifier_version), 0),
       COALESCE(SUM(CASE WHEN fc.source = 'editor' THEN 1 ELSE 0 END), 0)
  FROM file_changes fc
  JOIN keep k ON k.id = fc.id
  JOIN sessions sess ON sess.id = fc.session_id
  JOIN projects p ON p.id = fc.project_id
 WHERE sess.started_at >= ?` + scopeClause + `
 GROUP BY fc.session_id, p.root_path_hash, fc.actor, fc.sidechain, fc.category
 ORDER BY fc.session_id, p.root_path_hash`

	var buckets []locOrgBucket
	rows, err := s.db.QueryContext(ctx, q, since, since, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectSessionLOCSummaries: %w", err)
	}
	for rows.Next() {
		var b locOrgBucket
		var side int
		if err := rows.Scan(&b.sessionID, &b.rootHash, &b.actor, &side, &b.category,
			&b.files, &b.lowConfidence, &b.overwrites,
			&b.addedCode, &b.modifiedCode, &b.deletedCode,
			&b.addedComment, &b.deletedComment,
			&b.whitespace, &b.blank, &b.unknown,
			&b.version, &b.editorRows); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store.SelectSessionLOCSummaries: scan: %w", err)
		}
		b.sidechain = side != 0
		buckets = append(buckets, b)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("store.SelectSessionLOCSummaries: rows: %w", err)
	}
	_ = rows.Close()

	out := foldSessionLOCBuckets(buckets)
	if len(out) == 0 || !withLanguageMix {
		return out, nil
	}
	if err := s.attachLOCLanguageMix(ctx, since, scopeClause, out); err != nil {
		return nil, err
	}
	return out, nil
}

// foldSessionLOCBuckets flattens the (actor, sidechain, category) cells into
// the flat wire row. Files is counted per (session, root) rather than summed
// across buckets, because one file touched by both an edit and a write is one
// file — summing bucket file counts would double it.
func foldSessionLOCBuckets(buckets []locOrgBucket) []orgcontract.SessionLOCRow {
	type key struct{ session, root string }
	byKey := map[key]*orgcontract.SessionLOCRow{}
	order := []key{}
	// Files is summed across the per-(actor, sidechain, category) distinct
	// counts. A file cannot appear under two categories (its category is a
	// function of its path), so the only way one file is counted twice is
	// when two different ACTORS touched it — which is a real "both an agent
	// and the developer edited this file" signal, not an artefact. Stated
	// here because a reader will otherwise assume it is a bug.
	for _, b := range buckets {
		k := key{b.sessionID, b.rootHash}
		r, ok := byKey[k]
		if !ok {
			r = &orgcontract.SessionLOCRow{
				SessionID:       b.sessionID,
				ProjectRootHash: b.rootHash,
				HumanCapture:    "none",
			}
			byKey[k] = r
			order = append(order, k)
		}
		if b.version > r.ClassifierVersion {
			r.ClassifierVersion = b.version
		}
		r.Files += b.files
		r.LowConfidenceFiles += b.lowConfidence
		r.OverwriteFiles += b.overwrites
		if b.editorRows > 0 {
			r.HumanCapture = "vscode"
		}

		switch b.category {
		case "docs":
			r.DocsLines += b.addedCode + b.modifiedCode + b.addedComment
			continue
		case "config":
			r.ConfigLines += b.addedCode + b.modifiedCode + b.addedComment
			continue
		case "code":
			// fall through to the per-actor code buckets below
		default:
			// generated / vendored / unknown categories are recorded
			// node-side but deliberately contribute to no org number: the
			// plan excludes them from every count (§1 "Exclude
			// generated/vendored/build/docs").
			continue
		}

		switch b.actor {
		case LOCActorAI:
			if b.sidechain {
				r.AISidechainAddedCode += b.addedCode
				r.AISidechainModifiedCode += b.modifiedCode
				r.AISidechainDeletedCode += b.deletedCode
				continue
			}
			r.AIAddedCode += b.addedCode
			r.AIModifiedCode += b.modifiedCode
			r.AIDeletedCode += b.deletedCode
			r.AIAddedComment += b.addedComment
			r.AIDeletedComment += b.deletedComment
			r.AIWhitespace += b.whitespace
			r.AIBlank += b.blank
			r.AIUnknown += b.unknown
		case LOCActorHuman:
			r.HumanAddedCode += b.addedCode
			r.HumanModifiedCode += b.modifiedCode
			r.HumanDeletedCode += b.deletedCode
		case LOCActorSystem:
			r.SystemAddedCode += b.addedCode
			r.SystemModifiedCode += b.modifiedCode
			r.SystemDeletedCode += b.deletedCode
		default:
			r.UnknownLines += b.addedCode + b.modifiedCode + b.deletedCode +
				b.addedComment + b.deletedComment + b.unknown
		}
	}

	out := make([]orgcontract.SessionLOCRow, 0, len(order))
	for _, k := range order {
		r := byKey[k]
		// A session whose whole contribution was generated/vendored files,
		// or which touched nothing countable, ships nothing rather than an
		// all-zero row on every push.
		if locRowIsEmpty(*r) {
			continue
		}
		out = append(out, *r)
	}
	return out
}

// locRowIsEmpty reports whether a composed row carries no counted line at
// all. Files alone is not enough to keep a row: a session whose only touched
// files were generated or vendored has files > 0 and nothing to report.
func locRowIsEmpty(r orgcontract.SessionLOCRow) bool {
	return r.AIAddedCode == 0 && r.AIModifiedCode == 0 && r.AIDeletedCode == 0 &&
		r.AIAddedComment == 0 && r.AIDeletedComment == 0 &&
		r.AIWhitespace == 0 && r.AIBlank == 0 && r.AIUnknown == 0 &&
		r.AISidechainAddedCode == 0 && r.AISidechainModifiedCode == 0 && r.AISidechainDeletedCode == 0 &&
		r.HumanAddedCode == 0 && r.HumanModifiedCode == 0 && r.HumanDeletedCode == 0 &&
		r.SystemAddedCode == 0 && r.SystemModifiedCode == 0 && r.SystemDeletedCode == 0 &&
		r.UnknownLines == 0 && r.DocsLines == 0 && r.ConfigLines == 0
}

// attachLOCLanguageMix fills LanguageMixJSON on rows already composed. It is
// the ONE content-adjacent field on this wire (a language mix says what KIND
// of files a developer touched), so it runs only under shipsRawContent() —
// same posture as SessionVerbosityRow.CodeByLanguageJSON.
func (s *Store) attachLOCLanguageMix(ctx context.Context, since, scopeClause string, rows []orgcontract.SessionLOCRow) error {
	//nolint:gosec // G202: every fragment is a code constant or a ?-bound id list; values bind via ? args.
	q := locOrgKeepCTE + `
SELECT fc.session_id, COALESCE(p.root_path_hash, ''), fc.language, fc.category,
       COUNT(DISTINCT fc.file_path_hash),
       COALESCE(SUM(fc.added_code + fc.modified_code + fc.added_comment), 0)
  FROM file_changes fc
  JOIN keep k ON k.id = fc.id
  JOIN sessions sess ON sess.id = fc.session_id
  JOIN projects p ON p.id = fc.project_id
 WHERE sess.started_at >= ?` + scopeClause + `
 GROUP BY fc.session_id, p.root_path_hash, fc.language, fc.category`

	type key struct{ session, root string }
	mix := map[key][]orgcontract.LOCLanguageLines{}
	qrows, err := s.db.QueryContext(ctx, q, since, since, since)
	if err != nil {
		return fmt.Errorf("store.attachLOCLanguageMix: %w", err)
	}
	for qrows.Next() {
		var k key
		var e orgcontract.LOCLanguageLines
		if err := qrows.Scan(&k.session, &k.root, &e.Language, &e.Category, &e.Files, &e.Lines); err != nil {
			_ = qrows.Close()
			return fmt.Errorf("store.attachLOCLanguageMix: scan: %w", err)
		}
		mix[k] = append(mix[k], e)
	}
	if err := qrows.Err(); err != nil {
		_ = qrows.Close()
		return fmt.Errorf("store.attachLOCLanguageMix: rows: %w", err)
	}
	_ = qrows.Close()

	for i := range rows {
		entries := mix[key{rows[i].SessionID, rows[i].ProjectRootHash}]
		if len(entries) == 0 {
			continue
		}
		sort.Slice(entries, func(a, b int) bool {
			if entries[a].Lines != entries[b].Lines {
				return entries[a].Lines > entries[b].Lines
			}
			return entries[a].Language < entries[b].Language
		})
		enc, err := json.Marshal(entries)
		if err != nil {
			return fmt.Errorf("store.attachLOCLanguageMix: marshal: %w", err)
		}
		rows[i].LanguageMixJSON = string(enc)
	}
	return nil
}

// SelectLOCDaySummaries composes the day-bucketed aggregate: one row per
// (day, project_root_hash) over the trailing window.
//
// Its reason to exist is out-of-session editor work (plan §2): a developer
// typing by hand with no agent running produces file_changes rows with a NULL
// session_id, which the per-session wire above can never carry. Without this
// row a CLI-only-agent developer would read as 100% AI.
//
// Buckets on saved_at — the EVENT time — never created_at, so a row's day
// is the day the edit happened, not the day it was counted.
//
// That is a statement about the bucket KEY, not about reach: the composer
// also FILTERS on saved_at against the trailing locOrgWindowDays window, so
// anything older than it never reaches the wire at all. An `observer
// backfill --loc --loc-since <old date>` therefore writes node-local
// file_changes rows the node's own surfaces render, while loc_days (and
// session_loc, windowed the same way on sessions.started_at) carry only
// what is still inside the window — the same limitation the verbosity wire
// has. Pinned by TestSelectLOCDaySummariesDropsRowsOlderThanTheWireWindow.
func (s *Store) SelectLOCDaySummaries(ctx context.Context, scope ScopeOptions) ([]orgcontract.LOCDayRow, error) {
	since := isoSinceDays(locOrgWindowDays)
	scopeClause, noMatch, err := s.locScopeClause(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("store.SelectLOCDaySummaries: scope: %w", err)
	}
	if noMatch {
		return nil, nil
	}

	//nolint:gosec // G202: every fragment is a code constant or a ?-bound id list; values bind via ? args.
	q := locOrgKeepCTE + `
SELECT substr(fc.saved_at, 1, 10) AS day, COALESCE(p.root_path_hash, ''), fc.actor,
       COUNT(DISTINCT fc.file_path_hash),
       COALESCE(SUM(fc.added_code + fc.modified_code), 0),
       COALESCE(MAX(fc.classifier_version), 0),
       COALESCE(SUM(CASE WHEN fc.source = 'editor' THEN 1 ELSE 0 END), 0)
  FROM file_changes fc
  JOIN keep k ON k.id = fc.id
  JOIN projects p ON p.id = fc.project_id
 WHERE fc.saved_at >= ? AND fc.category = 'code'` + scopeClause + `
 GROUP BY day, p.root_path_hash, fc.actor
 ORDER BY day, p.root_path_hash`

	type key struct{ day, root string }
	byKey := map[key]*orgcontract.LOCDayRow{}
	order := []key{}
	rows, err := s.db.QueryContext(ctx, q, since, since, since)
	if err != nil {
		return nil, fmt.Errorf("store.SelectLOCDaySummaries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var day, root, actor string
		var files, lines, version, editorRows int64
		if err := rows.Scan(&day, &root, &actor, &files, &lines, &version, &editorRows); err != nil {
			return nil, fmt.Errorf("store.SelectLOCDaySummaries: scan: %w", err)
		}
		if strings.TrimSpace(day) == "" {
			// A row with no event time cannot be placed in a day bucket;
			// dropping it is honest, inventing "today" for it is not.
			continue
		}
		k := key{day, root}
		r, ok := byKey[k]
		if !ok {
			r = &orgcontract.LOCDayRow{Day: day, ProjectRootHash: root, HumanCapture: "none"}
			byKey[k] = r
			order = append(order, k)
		}
		if version > r.ClassifierVersion {
			r.ClassifierVersion = version
		}
		r.Files += files
		if editorRows > 0 {
			r.HumanCapture = "vscode"
		}
		switch actor {
		case LOCActorAI:
			r.AICodeLines += lines
		case LOCActorHuman:
			r.HumanCodeLines += lines
		case LOCActorSystem:
			r.SystemCodeLines += lines
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectLOCDaySummaries: rows: %w", err)
	}

	out := make([]orgcontract.LOCDayRow, 0, len(order))
	for _, k := range order {
		r := byKey[k]
		if r.AICodeLines == 0 && r.HumanCodeLines == 0 && r.SystemCodeLines == 0 {
			continue
		}
		out = append(out, *r)
	}
	return out, nil
}

// probeFileChanges is the Track R2 change-detection fingerprint for both LOC
// wire families (internal/store/orgsnapgate.go). It lives HERE, with the
// table's other readers, so orgsnapgate.go names no source table — the same
// one-owner discipline every other probe follows.
func (s *Store) probeFileChanges(ctx context.Context) (string, error) {
	return s.snapProbeScalar(ctx, `SELECT 'fc' || COALESCE(MAX(id), 0) FROM file_changes`)
}
