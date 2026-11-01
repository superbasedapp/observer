package loc

import (
	"encoding/json"
	"strings"
)

// ShapeBobChanges is the ladder row for IBM Bob's exact per-file change
// record. Bob's edit and write tools (write_file, search_and_replace,
// apply_diff, insert_content) answer with a tool result whose
// `_meta.changes` maps each touched file's URI to `{before, after, patch}`,
// where `patch` is the unified diff Bob itself applied (grounded on the
// live WSL and Windows stores, bobshell 2.0.6, 2026-10-21). The ibm-bob
// adapter copies that diff into the call's raw_tool_input under
// BobChangesKey, reduced to its changed lines (see BobChangesKey), so the
// count comes from what the tool actually did rather than from the
// arguments the model sent (a search_and_replace that hit several
// occurrences, a write_file over an existing file whose before-image the
// arguments never carry).
const ShapeBobChanges Shape = "ibm_bob_changes"

// BobChangesKey is the raw_tool_input member the ibm-bob adapter adds when
// a call's result carried `_meta.changes`:
//
//	"_bob_changes": [{"path": "<file>", "hunks": "@@\n-old\n+new\n"}]
//
// `hunks` holds only the diff's `+` and `-` lines; each run of unchanged
// context lines (and the diff's own `@@ -a,b +c,d @@` headers) is replaced
// by a bare `@@` separator, so no unchanged file content is stored. The
// separators keep two change runs from being paired across the context that
// sat between them, so the counts equal those of the full diff.
const BobChangesKey = "_bob_changes"

// bobChange is one element of the BobChangesKey array.
type bobChange struct {
	Path  string `json:"path"`
	Hunks string `json:"hunks"`
}

// parseBobChanges counts the exact per-file hunks the ibm-bob adapter
// recorded. An entry with no hunks is skipped; a payload with no usable
// entry yields nothing so the ladder falls through to the argument shapes
// (search/replace, insert_content, content, diff) that estimate the change.
func parseBobChanges(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
	var changes []bobChange
	if err := json.Unmarshal(obj[BobChangesKey], &changes); err != nil || len(changes) == 0 {
		return nil
	}
	out := make([]FileStats, 0, len(changes))
	for _, c := range changes {
		if strings.TrimSpace(c.Hunks) == "" {
			continue
		}
		path := c.Path
		if path == "" {
			path = in.Target
		}
		fs := unifiedDiffStats(path, c.Hunks)
		fs.Shape = ShapeBobChanges
		out = append(out, fs)
	}
	if len(out) == 0 {
		return nil
	}
	sortFileStats(out)
	return out
}
