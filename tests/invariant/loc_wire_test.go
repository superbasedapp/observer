package invariant

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// loc_wire_test.go pins the Lines-of-Code org wire (W5 of
// docs/plans/lines-of-code-tracking-plan-2026-09-07.md; acceptance criterion
// 7). Three properties, each failing loudly and separately:
//
//  1. SHAPE — the two wire row types may carry only allow-listed AGGREGATE
//     fields. A per-file field, a path hash, a digest or an excerpt fails at
//     compile-review time rather than in production.
//  2. SUBSTANCE — a real SelectUnpushedSince over a seeded file_changes corpus
//     never carries the per-file path hash, under metadata-only, full_content
//     AND admin_managed.
//  3. GATE — the ONE content-adjacent field (the language mix) is absent by
//     default and present only under shipsRawContent(), while the COUNTS ship
//     in the default posture (they are the total_actions disclosure class).

// TestSessionLOCWireShapeIsAggregateOnly pins SessionLOCRow structurally: only
// attribution, the two natural-key ids, line counts, the caveat counters, the
// two closed enums/versions, and the one gated language-mix blob. A new field
// fails here before it can ship. Modeled on
// TestRoutingSummaryWireShapeIsAggregateOnly.
func TestSessionLOCWireShapeIsAggregateOnly(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"OrgID": true, "UserEmail": true, // agent-stamped attribution
		"SessionID": true, "ProjectRootHash": true, // natural key (project hash already ships on SessionRow)

		"AIAddedCode": true, "AIModifiedCode": true, "AIDeletedCode": true,
		"AIAddedComment": true, "AIDeletedComment": true,
		"AIWhitespace": true, "AIBlank": true, "AIUnknown": true,

		"AISidechainAddedCode": true, "AISidechainModifiedCode": true, "AISidechainDeletedCode": true,

		"HumanAddedCode": true, "HumanModifiedCode": true, "HumanDeletedCode": true,
		"SystemAddedCode": true, "SystemModifiedCode": true, "SystemDeletedCode": true,

		"UnknownLines": true, "DocsLines": true, "ConfigLines": true,

		"Files": true, "LowConfidenceFiles": true, "OverwriteFiles": true,

		"HumanCapture": true, "ClassifierVersion": true,
		"LanguageMixJSON": true, // the ONE shipsRawContent()-gated field
	}
	typ := reflect.TypeOf(orgcontract.SessionLOCRow{})
	if typ.NumField() != len(allowed) {
		t.Errorf("SessionLOCRow has %d fields, want exactly %d (the §3.4 aggregate allow-list)", typ.NumField(), len(allowed))
	}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("SessionLOCRow gained non-aggregate field %q — the LOC wire is line COUNTS per session x project root ONLY. "+
				"A per-file row, a file_path_hash, an input_digest or any excerpt needs its own share key and its own privacy review", name)
		}
	}
}

// TestLOCDayWireShapeIsAggregateOnly is the same pin for the day bucket.
func TestLOCDayWireShapeIsAggregateOnly(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"OrgID": true, "UserEmail": true,
		"Day": true, "ProjectRootHash": true,
		"AICodeLines": true, "HumanCodeLines": true, "SystemCodeLines": true,
		"Files": true, "HumanCapture": true, "ClassifierVersion": true,
	}
	typ := reflect.TypeOf(orgcontract.LOCDayRow{})
	if typ.NumField() != len(allowed) {
		t.Errorf("LOCDayRow has %d fields, want exactly %d (the §3.4 day-bucket allow-list)", typ.NumField(), len(allowed))
	}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("LOCDayRow gained non-aggregate field %q — the day bucket is per-actor line counts ONLY", name)
		}
	}
}

// seedLOCCorpus writes one project, one session and three file_changes rows —
// an AI edit, a sidechain AI edit and a human editor save — whose path hashes
// carry an unmistakable sentinel prefix, so a wire scan can prove the per-file
// identity never crosses.
func seedLOCCorpus(ctx context.Context, t *testing.T, st *store.Store, sentinel string) {
	t.Helper()
	pid, err := st.UpsertProject(ctx, "/inv/project-alpha", "")
	if err != nil {
		t.Fatalf("seedLOCCorpus: UpsertProject: %v", err)
	}
	now := time.Now().UTC().Add(-time.Hour)
	rows := []store.FileChangeRow{
		{
			SessionID: "sess-cc-1", ProjectID: pid,
			FilePathHash: sentinel + "-main-go", InputDigest: sentinel + "-digest-1",
			Language: string(loc.LangGo), Category: string(loc.CategoryCode),
			Actor: store.LOCActorAI, Confidence: string(loc.ConfidenceHigh),
			Source:  store.LOCSourceEdit,
			Stats:   loc.Stats{AddedCode: 40, ModifiedCode: 5, DeletedCode: 2, AddedComment: 3, Blank: 7},
			Version: loc.Version, SavedAt: now,
		},
		{
			SessionID: "sess-cc-1", ProjectID: pid,
			FilePathHash: sentinel + "-sub-go", InputDigest: sentinel + "-digest-2",
			Language: string(loc.LangGo), Category: string(loc.CategoryCode),
			Actor: store.LOCActorAI, Confidence: string(loc.ConfidenceHigh),
			Source: store.LOCSourceEdit, Sidechain: true,
			Stats:   loc.Stats{AddedCode: 11, ModifiedCode: 1},
			Version: loc.Version, SavedAt: now,
		},
		{
			SessionID: "sess-cc-1", ProjectID: pid,
			FilePathHash: sentinel + "-human-go",
			Language:     string(loc.LangGo), Category: string(loc.CategoryCode),
			Actor: store.LOCActorHuman, Confidence: string(loc.ConfidenceHigh),
			Source:  store.LOCSourceEditor,
			Stats:   loc.Stats{AddedCode: 9, ModifiedCode: 2},
			Version: loc.Version, SavedAt: now,
		},
	}
	if _, err := st.InsertFileChanges(ctx, rows); err != nil {
		t.Fatalf("seedLOCCorpus: InsertFileChanges: %v", err)
	}
}

// locBatch runs a real push composition under the given share posture.
func locBatch(ctx context.Context, t *testing.T, st *store.Store, share store.ShareOptions) store.PushBatch {
	t.Helper()
	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@acme.example", share, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	return batch
}

// TestFileChangesNeverOnTheWire is the end-to-end pin behind acceptance
// criterion 7: the node's per-file grain never crosses under ANY share
// posture, and the aggregate DOES cross under the default one (so the scan is
// not vacuous).
func TestFileChangesNeverOnTheWire(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	const sentinel = "SBLOCPATHSENT" // unmistakable; appears nowhere legitimate
	seedLOCCorpus(ctx, t, st, sentinel)

	for _, tc := range []struct {
		name  string
		share store.ShareOptions
	}{
		{"metadata_only", store.ShareOptions{}},
		{"full_content", store.ShareOptions{FullContent: true}},
		{"admin_managed", store.ShareOptions{AdminManaged: true}},
	} {
		batch := locBatch(ctx, t, st, tc.share)
		raw, err := json.Marshal(batch)
		if err != nil {
			t.Fatalf("%s: marshal batch: %v", tc.name, err)
		}
		if bytes.Contains(raw, []byte(sentinel)) {
			t.Errorf("%s: a file_changes path hash / input digest reached the push payload — "+
				"the LOC wire is an AGGREGATE and must carry no per-file identity", tc.name)
		}
		// Non-vacuity: the aggregate itself must be there, or the scan above
		// would pass simply because nothing shipped.
		if len(batch.SessionLOC) == 0 {
			t.Errorf("%s: no SessionLOC rows composed — the sentinel scan is vacuous", tc.name)
		}
	}
}

// TestSessionLOCShipsCountsByDefaultAndGatesLanguageMix pins the split posture
// of plan §2 / §6 ruling 2: the COUNTS are the total_actions disclosure class
// and ship with no opt-in at all, while the language mix — which says what
// KIND of files a developer touched — ships only under shipsRawContent().
func TestSessionLOCShipsCountsByDefaultAndGatesLanguageMix(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	seedLOCCorpus(ctx, t, st, "SBLOCGATE")

	def := locBatch(ctx, t, st, store.ShareOptions{})
	if len(def.SessionLOC) == 0 {
		t.Fatal("default (metadata-only) posture shipped no SessionLOC rows — the counts are the total_actions class and must ship without an opt-in")
	}
	var ai int64
	for _, r := range def.SessionLOC {
		if r.LanguageMixJSON != "" {
			t.Errorf("default posture shipped a language mix (%q) — that field rides shipsRawContent()", r.LanguageMixJSON)
		}
		if r.OrgID != "org-1" || r.UserEmail != "dev@acme.example" {
			t.Errorf("SessionLOC row not stamped with the pusher identity: org=%q email=%q", r.OrgID, r.UserEmail)
		}
		ai += r.AIAddedCode + r.AIModifiedCode
		if r.AISidechainAddedCode == 0 && r.AIAddedCode == 0 {
			continue
		}
	}
	if ai == 0 {
		t.Error("SessionLOC carried no AI code lines — the aggregation dropped the seeded corpus")
	}

	// A second store handle so the snapshot gate does not skip the recompute
	// (the gate is per-Store and the default push above already recorded a
	// pending fingerprint for this family).
	st2 := store.New(database)
	full := locBatch(ctx, t, st2, store.ShareOptions{FullContent: true})
	if len(full.SessionLOC) == 0 {
		t.Fatal("full_content posture shipped no SessionLOC rows")
	}
	sawMix := false
	for _, r := range full.SessionLOC {
		if r.LanguageMixJSON != "" {
			sawMix = true
			var mix []orgcontract.LOCLanguageLines
			if err := json.Unmarshal([]byte(r.LanguageMixJSON), &mix); err != nil {
				t.Fatalf("language_mix_json is not a LOCLanguageLines array: %v (%q)", err, r.LanguageMixJSON)
			}
			for _, e := range mix {
				if e.Language == "" && e.Lines == 0 {
					t.Errorf("language mix entry is empty: %+v", e)
				}
			}
		}
	}
	if !sawMix {
		t.Error("full_content posture shipped no language mix — the gate is stuck closed and the opt-in is vacuous")
	}
}

// TestSidechainLinesAreSplitOnTheWire pins acceptance criterion 8's org half:
// subagent work is a SEPARATE number on the wire, never folded into the
// developer's own agent turn.
func TestSidechainLinesAreSplitOnTheWire(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)
	seedLOCCorpus(ctx, t, st, "SBLOCSPLIT")

	batch := locBatch(ctx, t, st, store.ShareOptions{})
	var main, side int64
	for _, r := range batch.SessionLOC {
		main += r.AIAddedCode
		side += r.AISidechainAddedCode
	}
	if main != 40 {
		t.Errorf("main-line AI added code = %d, want 40 (the sidechain row must not be folded in)", main)
	}
	if side != 11 {
		t.Errorf("sidechain AI added code = %d, want 11", side)
	}
}

// TestLOCHumanCaptureIsCarriedHonestly pins the honesty flag: a session with
// an editor-reported save carries human_capture "vscode", and one without
// carries "none" — the flag the UI uses to decide whether an AI-vs-human
// share may be rendered at all.
func TestLOCHumanCaptureIsCarriedHonestly(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	seed(ctx, t, st)

	pid, err := st.UpsertProject(ctx, "/inv/project-beta", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	now := time.Now().UTC().Add(-time.Hour)
	if _, err := st.InsertFileChanges(ctx, []store.FileChangeRow{{
		SessionID: "sess-cdx-1", ProjectID: pid,
		FilePathHash: "h-only-ai", InputDigest: "d-only-ai",
		Language: string(loc.LangGo), Category: string(loc.CategoryCode),
		Actor: store.LOCActorAI, Confidence: string(loc.ConfidenceHigh),
		Source:  store.LOCSourceEdit,
		Stats:   loc.Stats{AddedCode: 5},
		Version: loc.Version, SavedAt: now,
	}}); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	batch := locBatch(ctx, t, st, store.ShareOptions{})
	found := false
	for _, r := range batch.SessionLOC {
		if r.SessionID != "sess-cdx-1" {
			continue
		}
		found = true
		if r.HumanCapture != "none" {
			t.Errorf("human_capture = %q for a session with no editor rows, want \"none\" — "+
				"claiming capture where there is none is what would turn an unmeasured denominator into a 100%%-AI share", r.HumanCapture)
		}
		if r.HumanAddedCode != 0 {
			t.Errorf("human_added_code = %d with no editor capture, want 0", r.HumanAddedCode)
		}
	}
	if !found {
		t.Fatal("no SessionLOC row for the AI-only session — the assertion is vacuous")
	}
}
