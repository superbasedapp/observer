package cost

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestParseSnapshot_TableDriven pins the snapshot's decoding rules, one case
// per rule. These are the rules that decide what a shipped binary bills, so
// each one gets a row rather than a paragraph.
func TestParseSnapshot_TableDriven(t *testing.T) {
	t.Parallel()
	f := func(v float64) *float64 { return &v }
	i := func(v int64) *int64 { return &v }
	const fv = SnapshotMinFeedVersion

	for _, tc := range []struct {
		name         string
		doc          snapshotDoc
		wantErr      bool
		wantRows     int
		wantPresent  bool
		wantModel    string
		wantSkipped  int
		wantMinCache map[string]int
	}{
		{
			// The committed zero state. A valid document that simply is not
			// in force yet - never an error, never a row. Exempt from the
			// feed-version floor because it states no rate.
			name:        "zero state parses and is not present",
			doc:         snapshotDoc{SchemaVersion: SnapshotSchemaVersion},
			wantRows:    0,
			wantPresent: false,
		},
		{
			// All-or-nothing: an unknown schema is refused WHOLE.
			name: "unknown schema version is refused whole",
			doc: snapshotDoc{
				SchemaVersion: SnapshotSchemaVersion + 1, FeedVersion: fv,
				Rows: []snapshotRow{{Model: "m", InputPerMTok: f(1), OutputPerMTok: f(2)}},
			},
			wantErr:  true,
			wantRows: 0,
		},
		{
			// Finding 2, the refused direction: an older (still validly
			// signed) bundle must not roll the seed back.
			name: "a feed_version below the compiled floor is refused whole",
			doc: snapshotDoc{
				SchemaVersion: SnapshotSchemaVersion, FeedVersion: fv - 1,
				Rows: []snapshotRow{{Model: "m", InputPerMTok: f(1), OutputPerMTok: f(2)}},
			},
			wantErr:  true,
			wantRows: 0,
		},
		{
			// Finding 2, the accepted direction.
			name: "a feed_version at the floor is accepted",
			doc: snapshotDoc{
				SchemaVersion: SnapshotSchemaVersion, FeedVersion: fv,
				Rows: []snapshotRow{{Model: "m", InputPerMTok: f(1), OutputPerMTok: f(2)}},
			},
			wantRows:    1,
			wantPresent: true,
			wantModel:   "m",
		},
		{
			name: "a feed_version above the floor is accepted",
			doc: snapshotDoc{
				SchemaVersion: SnapshotSchemaVersion, FeedVersion: fv + 5,
				Rows: []snapshotRow{{Model: "m", InputPerMTok: f(1), OutputPerMTok: f(2)}},
			},
			wantRows:    1,
			wantPresent: true,
		},
		{
			name: "a row quoting no rate is dropped, not priced at zero",
			doc: snapshotDoc{
				SchemaVersion: SnapshotSchemaVersion, FeedVersion: fv,
				Rows: []snapshotRow{
					{Model: "rateless", CacheReadPerMTok: f(0.5)},
					{Model: "priced", InputPerMTok: f(1), OutputPerMTok: f(2)},
				},
			},
			wantRows:    1,
			wantPresent: true,
			wantModel:   "priced",
			wantSkipped: 1,
		},
		{
			name: "a negative quoted rate drops the row",
			doc: snapshotDoc{
				SchemaVersion: SnapshotSchemaVersion, FeedVersion: fv,
				Rows: []snapshotRow{{Model: "bad", InputPerMTok: f(-1), OutputPerMTok: f(2)}},
			},
			wantRows:    0,
			wantSkipped: 1,
		},
		{
			name: "a negative fast multiplier drops the row",
			doc: snapshotDoc{
				SchemaVersion: SnapshotSchemaVersion, FeedVersion: fv,
				Rows: []snapshotRow{{Model: "bad", InputPerMTok: f(1), OutputPerMTok: f(2), FastMultiplier: f(-2)}},
			},
			wantRows:    0,
			wantSkipped: 1,
		},
		{
			name: "an unparseable effective_from drops the row",
			doc: snapshotDoc{
				SchemaVersion: SnapshotSchemaVersion, FeedVersion: fv,
				Rows: []snapshotRow{{Model: "bad", EffectiveFrom: "next tuesday", InputPerMTok: f(1), OutputPerMTok: f(2)}},
			},
			wantRows:    0,
			wantSkipped: 1,
		},
		{
			name: "model ids are normalized to lower case",
			doc: snapshotDoc{
				SchemaVersion: SnapshotSchemaVersion, FeedVersion: fv,
				Rows: []snapshotRow{{Model: "  Claude-Opus-5-5 ", InputPerMTok: f(4), OutputPerMTok: f(20)}},
			},
			wantRows:    1,
			wantPresent: true,
			wantModel:   "claude-opus-5-5",
		},
		{
			name: "min-cacheable is carried, and only when positive",
			doc: snapshotDoc{
				SchemaVersion: SnapshotSchemaVersion, FeedVersion: fv,
				Rows: []snapshotRow{
					{Model: "a", InputPerMTok: f(1), OutputPerMTok: f(2), MinCacheableTokens: i(512)},
					{Model: "b", InputPerMTok: f(1), OutputPerMTok: f(2), MinCacheableTokens: i(0)},
					{Model: "c", InputPerMTok: f(1), OutputPerMTok: f(2)},
				},
			},
			wantRows:     3,
			wantPresent:  true,
			wantMinCache: map[string]int{"a": 512},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			meta, rows, minCache := parseSnapshot(mustJSON(t, tc.doc))
			if (meta.Err != nil) != tc.wantErr {
				t.Fatalf("Err = %v, wantErr=%v", meta.Err, tc.wantErr)
			}
			if len(rows) != tc.wantRows {
				t.Errorf("rows = %d, want %d", len(rows), tc.wantRows)
			}
			if meta.Present != tc.wantPresent {
				t.Errorf("Present = %v, want %v", meta.Present, tc.wantPresent)
			}
			if len(meta.Skipped) != tc.wantSkipped {
				t.Errorf("Skipped = %v, want %d entries", meta.Skipped, tc.wantSkipped)
			}
			if tc.wantModel != "" {
				if _, ok := rows[tc.wantModel]; !ok {
					t.Errorf("row %q missing; have %v", tc.wantModel, keysOf(rows))
				}
			}
			if tc.wantMinCache != nil && !reflect.DeepEqual(minCache, tc.wantMinCache) {
				t.Errorf("minCacheable = %v, want %v", minCache, tc.wantMinCache)
			}
		})
	}
}

// snapshotTable parses doc and folds it onto a fresh seed table, the way
// NewTable folds the embedded snapshot.
func snapshotTable(t *testing.T, doc snapshotDoc) *Table {
	t.Helper()
	if doc.SchemaVersion == 0 {
		doc.SchemaVersion = SnapshotSchemaVersion
	}
	if doc.FeedVersion == 0 {
		doc.FeedVersion = SnapshotMinFeedVersion
	}
	meta, rows, _ := parseSnapshot(mustJSON(t, doc))
	if meta.Err != nil || len(meta.Skipped) > 0 {
		t.Fatalf("parse: err=%v skipped=%v", meta.Err, meta.Skipped)
	}
	// The fold is exercised against the HAND LITERAL alone, never against
	// NewTable(): that already carries the embedded generated snapshot, so a
	// test row "restating the literal's rate" would stop restating anything
	// the moment the embedded snapshot is regenerated with a different rate.
	tb := newLiteralTableAt(time.Now().UTC())
	applySnapshotRows(tb, rows)
	if w := tb.ValidateDated(); len(w) > 0 {
		t.Fatalf("snapshot fold broke the flat==newest invariant: %v", w)
	}
	return tb
}

// TestApplySnapshot_PresenceSemantics_RealRows is review finding 1's
// regression test, against REAL literal rows that carry each dimension the
// operator-captured lane cannot state: a long-context tier (gpt-6-astra,
// grok-4.7), a peak schedule (deepseek-v4-pro) and a fast multiplier
// (claude-opus-5-5). A snapshot row that quotes only input/output must leave
// every one of them in force - the earlier overlay zeroed the threshold and
// dropped the peak, silently turning off LC and peak repricing.
func TestApplySnapshot_PresenceSemantics_RealRows(t *testing.T) {
	t.Parallel()
	f := func(v float64) *float64 { return &v }
	before := newLiteralTableAt(time.Now().UTC())
	models := []string{"gpt-6-astra", "grok-4.7", "deepseek-v4-pro", "claude-opus-5-5"}
	var rows []snapshotRow
	for _, m := range models {
		p, ok := before.Lookup(m)
		if !ok {
			t.Fatalf("precondition: %s missing from the literal", m)
		}
		// Restate the literal's own input/output: ONLY the omitted
		// dimensions can differ afterwards.
		rows = append(rows, snapshotRow{Model: m, InputPerMTok: f(p.Input), OutputPerMTok: f(p.Output)})
	}
	tb := snapshotTable(t, snapshotDoc{Rows: rows})

	for _, m := range models {
		want, _ := before.Lookup(m)
		got, _ := tb.Lookup(m)
		if got != want {
			t.Errorf("%s: a partial snapshot row changed an unstated dimension:\n got  %+v\n want %+v", m, got, want)
		}
	}

	// And they still DO something: a prompt past the threshold reprices, a
	// peak-window instant reprices, a fast turn multiplies.
	astra, _ := tb.Lookup("gpt-6-astra")
	if astra.LongContextThreshold != 272_000 || astra.LongContextInput != 20 {
		t.Fatalf("gpt-6-astra LC tier lost: %+v", astra)
	}
	big := TokenBundle{Input: 300_000}
	if got := Compute(astra, big); got < 5.999999 || got > 6.000001 {
		t.Errorf("gpt-6-astra 300K prompt = %v, want the long-context rate", got)
	}
	grok, _ := tb.Lookup("grok-4.7")
	if grok.LongContextThreshold != 200_000 || grok.LongContextInput != 4 {
		t.Errorf("grok-4.7 LC tier lost: %+v", grok)
	}
	ds, _ := tb.Lookup("deepseek-v4-pro")
	if ds.Peak == nil {
		t.Fatal("deepseek-v4-pro peak schedule lost")
	}
	peakAt := time.Date(2026, 9, 23, 2, 0, 0, 0, time.UTC) // Wednesday 02:00 UTC
	if p, _ := tb.LookupAt("deepseek-v4-pro", peakAt); p.Input != ds.Peak.Input {
		t.Errorf("deepseek-v4-pro at a peak instant = %v, want the peak input %v", p.Input, ds.Peak.Input)
	}
	opus, _ := tb.Lookup("claude-opus-5-5")
	if opus.FastMultiplier != 2 {
		t.Errorf("claude-opus-5-5 FastMultiplier = %v, want 2", opus.FastMultiplier)
	}
}

// TestApplySnapshot_StatedDimensionsWin is the other half of presence
// semantics: a row that DOES state the threshold, the peak or the fast
// multiplier replaces the literal's value - including a quoted zero.
func TestApplySnapshot_StatedDimensionsWin(t *testing.T) {
	t.Parallel()
	f := func(v float64) *float64 { return &v }
	i := func(v int64) *int64 { return &v }
	peak := &PeakRates{
		RateSet:  RateSet{Input: 9, Output: 9},
		Schedule: PeakSchedule{Windows: []PeakWindow{{Days: []time.Weekday{time.Monday}, StartUTC: "01:00", EndUTC: "02:00"}}},
	}
	tb := snapshotTable(t, snapshotDoc{Rows: []snapshotRow{
		{Model: "gpt-6-astra", InputPerMTok: f(10), OutputPerMTok: f(50), LongContextThreshold: i(500_000), LongContextInputPerMTok: f(30)},
		{Model: "claude-opus-5-5", InputPerMTok: f(4), OutputPerMTok: f(20), FastMultiplier: f(3)},
		{Model: "deepseek-v4-pro", InputPerMTok: f(0.66), OutputPerMTok: f(1.98), Peak: peak},
		{Model: "brand-new", InputPerMTok: f(1), OutputPerMTok: f(2), LongContextThreshold: i(100_000), FastMultiplier: f(0)},
	}})
	if p, _ := tb.Lookup("gpt-6-astra"); p.LongContextThreshold != 500_000 || p.LongContextInput != 30 || p.LongContextOutput != 75 {
		t.Errorf("gpt-6-astra = %+v, want threshold 500000, LC input 30, unstated LC output 75 kept", p)
	}
	if p, _ := tb.Lookup("claude-opus-5-5"); p.FastMultiplier != 3 {
		t.Errorf("claude-opus-5-5 FastMultiplier = %v, want the stated 3", p.FastMultiplier)
	}
	if p, _ := tb.Lookup("deepseek-v4-pro"); p.Peak == nil || p.Peak.Input != 9 {
		t.Errorf("deepseek-v4-pro peak = %+v, want the stated replacement", p.Peak)
	}
	p, ok := tb.Lookup("brand-new")
	if !ok || p.Input != 1 || p.LongContextThreshold != 100_000 || p.FastMultiplier != 0 {
		t.Errorf("brand-new = %+v ok=%v", p, ok)
	}
	// A snapshot-only model carries no invented rate in the exact table.
	if raw := tb.exact["brand-new"]; raw.CacheRead != 0 {
		t.Errorf("brand-new raw CacheRead = %v; fillDefaults must stay a lookup-time step", raw.CacheRead)
	}
}

// TestApplySnapshot_KeepsEffectiveDates pins review finding 3 for the
// generated seed: a dated snapshot row switches the rate only from its
// instant, retaining the rate in force before it.
func TestApplySnapshot_KeepsEffectiveDates(t *testing.T) {
	t.Parallel()
	f := func(v float64) *float64 { return &v }
	switchAt := time.Date(2026, 9, 22, 19, 0, 0, 0, time.UTC)
	terraLater := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

	tb := snapshotTable(t, snapshotDoc{Rows: []snapshotRow{
		// A model with no literal timeline: history is synthesized from the
		// literal's flat row.
		{Model: "claude-opus-5", EffectiveFrom: "2026-09-22T19:00:00Z", InputPerMTok: f(4), OutputPerMTok: f(20)},
		// A brand-new model: nothing earlier to keep, so no timeline.
		{Model: "brand-new", EffectiveFrom: "2026-09-22T19:00:00Z", InputPerMTok: f(1), OutputPerMTok: f(2)},
		// A row restating the literal's own rate creates no history.
		{Model: "claude-opus-4-8", EffectiveFrom: "2026-09-22T19:00:00Z", InputPerMTok: f(5), OutputPerMTok: f(25)},
	}})

	opusBefore, _ := tb.LookupAt("claude-opus-5", switchAt.Add(-time.Nanosecond))
	opusAt, _ := tb.LookupAt("claude-opus-5", switchAt)
	opusNow, _ := tb.Lookup("claude-opus-5")
	if opusBefore.Input != 5 || opusBefore.Output != 25 {
		t.Errorf("claude-opus-5 before the snapshot instant = %v/%v, want the retained 5/25", opusBefore.Input, opusBefore.Output)
	}
	if opusAt.Input != 4 || opusAt.Output != 20 || opusNow.Input != 4 {
		t.Errorf("claude-opus-5 at/after = %v/%v now %v, want 4/20", opusAt.Input, opusAt.Output, opusNow.Input)
	}
	if opusAt.CacheCreation != 6.25 {
		t.Errorf("claude-opus-5 unstated cache write = %v, want the literal's 6.25", opusAt.CacheCreation)
	}

	// A model WITH a hand timeline: the snapshot extends it. dated.go no
	// longer ships a real one (every timeline moved to the price database,
	// lane R2-RECONCILE 2026-09-28), so the hand timeline is a fixture laid
	// onto the literal the way newLiteralTableAt would, before the fold.
	cut := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	terraFlat := defaultPricing["gpt-5.6-terra"]
	terraPre := terraFlat
	terraPre.Input = 2.50
	withTimeline := newLiteralTableAt(time.Now().UTC())
	withTimeline.MergeDated(map[string][]DatedPricing{"gpt-5.6-terra": {
		{Pricing: terraPre},
		{EffectiveFrom: cut, Pricing: terraFlat},
	}})
	doc := snapshotDoc{
		SchemaVersion: SnapshotSchemaVersion, FeedVersion: SnapshotMinFeedVersion,
		Rows: []snapshotRow{{Model: "gpt-5.6-terra", EffectiveFrom: "2026-09-01", InputPerMTok: f(1.50), OutputPerMTok: f(9)}},
	}
	meta, rows, _ := parseSnapshot(mustJSON(t, doc))
	if meta.Err != nil || len(meta.Skipped) > 0 {
		t.Fatalf("parse: err=%v skipped=%v", meta.Err, meta.Skipped)
	}
	applySnapshotRows(withTimeline, rows)
	if w := withTimeline.ValidateDated(); len(w) > 0 {
		t.Fatalf("snapshot fold broke the flat==newest invariant: %v", w)
	}
	for _, tc := range []struct {
		at   time.Time
		want float64
	}{
		{cut.Add(-time.Hour), 2.50}, // literal pre-cut entry retained
		{cut, 2.00},                 // literal cut entry retained
		{terraLater.Add(-time.Nanosecond), 2.00},
		{terraLater, 1.50}, // snapshot entry
		{time.Time{}, 1.50},
	} {
		if p, _ := withTimeline.LookupAt("gpt-5.6-terra", tc.at); p.Input != tc.want {
			t.Errorf("gpt-5.6-terra at %s input = %v, want %v", tc.at, p.Input, tc.want)
		}
	}
	if n := len(withTimeline.DatedFor("gpt-5.6-terra")); n != 3 {
		t.Errorf("gpt-5.6-terra timeline has %d entries, want 3 (two literal + one snapshot)", n)
	}
	if tb.DatedFor("brand-new") != nil {
		t.Error("a brand-new model grew a dated timeline with nothing to retain")
	}
	if tb.DatedFor("claude-opus-4-8") != nil {
		t.Error("a row restating the in-force rate grew a dated timeline")
	}
}

// TestApplySnapshot_UndatedRowOverlaysEveryPeriod pins the "since forever"
// reading of an undated row: its stated dimensions hold at every instant,
// including the literal's history, and the flat==newest invariant holds.
func TestApplySnapshot_UndatedRowOverlaysEveryPeriod(t *testing.T) {
	t.Parallel()
	f := func(v float64) *float64 { return &v }
	tb := snapshotTable(t, snapshotDoc{Rows: []snapshotRow{
		{Model: "gpt-5.6-luna", InputPerMTok: f(0.20), OutputPerMTok: f(1.20), CacheReadPerMTok: f(0.03)},
	}})
	cut := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	for _, at := range []time.Time{cut.Add(-time.Hour), cut, {}} {
		if p, _ := tb.LookupAt("gpt-5.6-luna", at); p.CacheRead != 0.03 {
			t.Errorf("gpt-5.6-luna cache read at %s = %v, want the stated 0.03", at, p.CacheRead)
		}
	}
}

// TestBakedInDefaults_IsTheEffectiveSeed pins review finding 10: the
// defaults surface exposes the literal PLUS the snapshot, so the Settings
// page can never pre-fill an obsolete literal rate the snapshot corrected.
func TestBakedInDefaults_IsTheEffectiveSeed(t *testing.T) {
	t.Parallel()
	f := func(v float64) *float64 { return &v }
	if got, want := BakedInDefaults(), NewTable().exact; !reflect.DeepEqual(got, want) {
		t.Fatal("BakedInDefaults differs from the flat table NewTable seeds")
	}
	tb := snapshotTable(t, snapshotDoc{Rows: []snapshotRow{
		{Model: "claude-opus-5", InputPerMTok: f(4), OutputPerMTok: f(20)},
		{Model: "brand-new", InputPerMTok: f(1), OutputPerMTok: f(2)},
	}})
	d := bakedInDefaultsOf(tb)
	if d["claude-opus-5"].Input != 4 {
		t.Errorf("defaults for claude-opus-5 = %v, want the snapshot-corrected 4", d["claude-opus-5"].Input)
	}
	if _, ok := d["brand-new"]; !ok {
		t.Error("a snapshot-only model is missing from the defaults surface")
	}
}

// TestZeroStateSnapshotIsByteIdentical pins the "changes nothing until
// generated" promise: while the embedded snapshot is the committed zero
// state, the seed table is exactly the hand literal plus its dated timelines.
func TestZeroStateSnapshotIsByteIdentical(t *testing.T) {
	t.Parallel()
	if PricingSnapshot().Present {
		t.Skip("the embedded snapshot is no longer the zero state")
	}
	tb := NewTable()
	if !reflect.DeepEqual(tb.exact, defaultPricing) {
		t.Fatal("zero-state snapshot changed the flat seed table")
	}
	if len(tb.dated) != len(datedPricing) {
		t.Fatalf("zero-state snapshot changed the dated table: %d timelines, literal has %d", len(tb.dated), len(datedPricing))
	}
	for k, v := range datedPricing {
		if !reflect.DeepEqual(tb.dated[k], v) {
			t.Errorf("zero-state snapshot changed the %s timeline", k)
		}
	}
}

// TestEmbeddedSnapshotIsUsable pins the COMMITTED artifact: whatever it holds,
// it must parse, carry the supported schema version, and never report an error.
func TestEmbeddedSnapshotIsUsable(t *testing.T) {
	t.Parallel()
	meta := PricingSnapshot()
	if meta.Err != nil {
		t.Fatalf("embedded pricing_snapshot.json is unusable: %v", meta.Err)
	}
	if len(meta.Skipped) > 0 {
		t.Fatalf("embedded pricing_snapshot.json has refused rows: %v", meta.Skipped)
	}
	if meta.Present && meta.FeedVersion < SnapshotMinFeedVersion {
		t.Errorf("a snapshot carrying %d rows must carry feed_version >= %d; got %d",
			meta.RowCount, SnapshotMinFeedVersion, meta.FeedVersion)
	}
	if meta.Present && meta.Digest == "" {
		t.Error("a snapshot carrying rows must carry the publisher's digest")
	}
}

// TestSnapshotIsSeedNotOverride pins the precedence rung. The snapshot lives
// INSIDE the seed: a developer's own [intelligence.pricing] override must still
// win over it, exactly as it wins over the hand literal.
func TestSnapshotIsSeedNotOverride(t *testing.T) {
	t.Parallel()
	tb := NewTable()
	tb.Merge(map[string]Pricing{"claude-opus-5-5": {Input: 1, Output: 1}})
	got, ok := tb.Lookup("claude-opus-5-5")
	if !ok {
		t.Fatal("lookup failed")
	}
	if got.Input != 1 || got.Output != 1 {
		t.Errorf("local override did not win: %+v", got)
	}
}

// TestSnapshotGeneratorShapeMatchesConsumer pins tools/pricing-snapshotgen's
// mirror of the snapshot document against this package's, and its restated
// constants against SnapshotSchemaVersion / SnapshotMinFeedVersion. The two
// cannot import each other (the generator is a main package and must not drag
// the cost package's dependencies in), so the generator's source is parsed.
func TestSnapshotGeneratorShapeMatchesConsumer(t *testing.T) {
	t.Parallel()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	src := filepath.Join(filepath.Dir(here), "..", "..", "..", "tools", "pricing-snapshotgen", "main.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse generator: %v", err)
	}
	genTags := map[string][]string{}
	genConsts := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.TypeSpec:
			st, ok := d.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, fld := range st.Fields.List {
				if fld.Tag != nil {
					tag, _ := strconv.Unquote(fld.Tag.Value)
					genTags[d.Name.Name] = append(genTags[d.Name.Name], reflect.StructTag(tag).Get("json"))
				}
			}
		case *ast.ValueSpec:
			for i, name := range d.Names {
				if i < len(d.Values) {
					if lit, ok := d.Values[i].(*ast.BasicLit); ok {
						genConsts[name.Name] = lit.Value
					}
				}
			}
		}
		return true
	})
	tagsOf := func(v any) []string {
		var out []string
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			out = append(out, rt.Field(i).Tag.Get("json"))
		}
		return out
	}
	for name, v := range map[string]any{"snapshotDoc": snapshotDoc{}, "snapshotRow": snapshotRow{}} {
		want := tagsOf(v)
		got := genTags[name]
		sort.Strings(want)
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("generator %s json tags drifted from the consumer:\n generator %v\n consumer  %v", name, got, want)
		}
	}
	if genConsts["snapshotSchemaVersion"] != strconv.Itoa(SnapshotSchemaVersion) {
		t.Errorf("generator snapshotSchemaVersion = %s, consumer %d", genConsts["snapshotSchemaVersion"], SnapshotSchemaVersion)
	}
	if genConsts["snapshotMinFeedVersion"] != strconv.FormatInt(SnapshotMinFeedVersion, 10) {
		t.Errorf("generator snapshotMinFeedVersion = %s, consumer %d", genConsts["snapshotMinFeedVersion"], SnapshotMinFeedVersion)
	}
}

func keysOf(m map[string][]snapshotPrice) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestApplySnapshot_ThresholdPresence is test (f) for the seed snapshot: a row
// with the threshold OMITTED keeps the seed's tier, while a row that STATES 0
// (the snapshot can say it; the generator never writes it) is quoted flat.
func TestApplySnapshot_ThresholdPresence(t *testing.T) {
	t.Parallel()
	f := func(v float64) *float64 { return &v }
	i := func(v int64) *int64 { return &v }
	tb := snapshotTable(t, snapshotDoc{Rows: []snapshotRow{
		{Model: "grok-4.7", InputPerMTok: f(2), OutputPerMTok: f(6), CacheReadPerMTok: f(0.50)},
		{Model: "gpt-6-astra", InputPerMTok: f(10), OutputPerMTok: f(50), LongContextThreshold: i(0)},
		{Model: "deepseek-v4-pro", InputPerMTok: f(0.66), OutputPerMTok: f(1.98), Peak: &PeakRates{}},
	}})
	if p, _ := tb.Lookup("grok-4.7"); p.LongContextThreshold != 200_000 {
		t.Errorf("omitted threshold: grok-4.7 = %d, want the seed's 200000", p.LongContextThreshold)
	}
	if p, _ := tb.Lookup("gpt-6-astra"); p.LongContextThreshold != 0 {
		t.Errorf("stated 0: gpt-6-astra threshold = %d, want 0 (quoted flat)", p.LongContextThreshold)
	}
	if p, _ := tb.Lookup("deepseek-v4-pro"); p.Peak != nil {
		t.Errorf("stated empty peak: deepseek-v4-pro Peak = %+v, want nil (quoted flat)", p.Peak)
	}
}

// TestEmbeddedSnapshotIsNotARehearsal refuses a committed snapshot that
// tools/pricing-snapshotgen's TestRehearsalSnapshot produced: that bridge
// signs an UNSIGNED rehearsal envelope with a throwaway key and names the
// source REHEARSAL-UNSIGNED-*, so its prices never came from a published feed.
// Set PRICING_SNAPSHOT_REHEARSAL=1 to run the package's tests against one
// locally (lane R2-RECONCILE's rehearsal did); never commit it.
func TestEmbeddedSnapshotIsNotARehearsal(t *testing.T) {
	var doc struct {
		Source string `json:"source"`
		KeyID  string `json:"key_id"`
	}
	if err := json.Unmarshal(pricingSnapshotJSON, &doc); err != nil {
		t.Fatalf("decode embedded snapshot: %v", err)
	}
	if !strings.HasPrefix(doc.Source, "REHEARSAL-") && !strings.HasPrefix(doc.KeyID, "rehearsal-") {
		return
	}
	if os.Getenv("PRICING_SNAPSHOT_REHEARSAL") == "1" {
		t.Logf("embedded snapshot is a REHEARSAL (%s, key %s); allowed by PRICING_SNAPSHOT_REHEARSAL=1", doc.Source, doc.KeyID)
		return
	}
	t.Fatalf("embedded snapshot is a REHEARSAL (%s, key %s); regenerate it from the signed feed with "+
		"`make pricing-snapshot BUNDLE=<signed observer-pricing-vN.json>`", doc.Source, doc.KeyID)
}
