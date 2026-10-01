package cost

import (
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// contextwindow.go is the SEED rung of the model context-window table: the
// per-model context_window_tokens the embedded, generated Tokenomics snapshot
// (pricing_snapshot.json, see snapshot.go) states for each row.
//
// A context window is NOT a rate and never reaches [Pricing]. It rides in the
// same generated artifact for the reason MinCacheableTokens does: one
// Tokenomics projection feeds every per-model fact a node needs before it has
// seen a feed, instead of a hand-edited table drifting from the database
// (operator ruling 2026-09-30: no hand-coded context windows anywhere). The
// runtime rungs above it (the standalone feed's economics and the org rail's
// context_windows sibling) are composed by the store
// (store.LoadModelContextWindows); this file only answers what the compiled
// snapshot says.
//
// The document is decoded here with its own minimal row shape rather than
// through snapshotRow so this rung reads the key whether or not the typed
// snapshot row has grown the field yet: a snapshot that does not carry
// context_window_tokens simply yields an empty table (every model unknown),
// never a guessed default.

var (
	snapshotWindowsOnce sync.Once
	snapshotWindows     map[string]int64
)

// SnapshotContextWindows returns the embedded Tokenomics snapshot's per-model
// context windows in tokens, keyed by the row's model id (trimmed,
// lower-cased). A model the snapshot states no positive window for is absent,
// so it reads as unknown rather than 0. When a model has several dated rows,
// the window of the latest-effective row that states one wins. A snapshot
// that fails to decode, or carries an unsupported schema_version, yields an
// empty table. The returned map is a fresh copy the caller may keep.
func SnapshotContextWindows() map[string]int64 {
	snapshotWindowsOnce.Do(func() {
		snapshotWindows = parseSnapshotContextWindows(pricingSnapshotJSON)
	})
	out := make(map[string]int64, len(snapshotWindows))
	for k, v := range snapshotWindows {
		out[k] = v
	}
	return out
}

// snapshotWindowDoc is the minimal decode of pricing_snapshot.json this rung
// needs: the schema version (to refuse a document this build does not
// understand, as parseSnapshot does) and each row's model, start instant and
// context window.
type snapshotWindowDoc struct {
	SchemaVersion int `json:"schema_version"`
	Rows          []struct {
		Model               string `json:"model"`
		EffectiveFrom       string `json:"effective_from,omitempty"`
		ContextWindowTokens *int64 `json:"context_window_tokens,omitempty"`
	} `json:"rows"`
}

// parseSnapshotContextWindows decodes the context-window rung from a snapshot
// document. Pure; split out so a test can feed it a literal document.
func parseSnapshotContextWindows(raw []byte) map[string]int64 {
	out := map[string]int64{}
	if len(raw) == 0 {
		return out
	}
	var doc snapshotWindowDoc
	if err := json.Unmarshal(raw, &doc); err != nil || doc.SchemaVersion != SnapshotSchemaVersion {
		return out
	}
	latest := map[string]time.Time{}
	for _, r := range doc.Rows {
		model := strings.ToLower(strings.TrimSpace(r.Model))
		if model == "" || r.ContextWindowTokens == nil || *r.ContextWindowTokens <= 0 {
			continue
		}
		var from time.Time
		if r.EffectiveFrom != "" {
			t, err := time.Parse(time.RFC3339, r.EffectiveFrom)
			if err != nil {
				continue
			}
			from = t
		}
		if prev, seen := latest[model]; seen && from.Before(prev) {
			continue
		}
		latest[model] = from
		out[model] = *r.ContextWindowTokens
	}
	return out
}
