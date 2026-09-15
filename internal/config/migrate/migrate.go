package migrate

import "strconv"

// rename describes one deprecated key and where it goes. A nil `to`
// means the key is removed outright (no in-process analog). Both from
// and to are dotted TOML paths as segment slices.
type rename struct {
	from []string
	to   []string // nil ⇒ removal
	note string
}

// step is one versioned batch of renames. Applying every step whose
// version is greater than the file's current config_version brings it
// up to LatestVersion(). Add a new rename as a data row (a new step for
// a new version), never new control flow.
type step struct {
	version int
	renames []rename
}

// steps is the ordered migration registry. Order within a step matters
// for precedence: when two legacy keys map to the same target and the
// target is absent, the FIRST listed wins (mirrors the in-memory
// migrateLegacyCodeGraph precedence — compression over intelligence).
var steps = []step{
	{
		version: 1, // codegraph → codeintel (Phase 4 decommission)
		renames: []rename{
			{from: k("compression", "code_graph", "enabled"), to: k("codeintel", "enabled"), note: "renamed to codeintel.enabled"},
			{from: k("compression", "code_graph", "auto_index"), to: k("codeintel", "index", "on_start"), note: "renamed to codeintel.index.on_start"},
			{from: k("compression", "code_graph", "auto_install"), to: nil, note: "removed (in-process index; no binary download)"},
			{from: k("compression", "code_graph", "path"), to: nil, note: "removed (no external graph.db)"},
			{from: k("intelligence", "code_graph", "enabled"), to: k("codeintel", "enabled"), note: "renamed to codeintel.enabled"},
		},
	},
	{
		version: 2, // flat org_client.share obs_* → nested [org_client.share.obs] (plane-separation audit M1)
		renames: []rename{
			{from: k("org_client", "share", "obs_summary"), to: k("org_client", "share", "obs", "summary"), note: "renamed to org_client.share.obs.summary"},
			{from: k("org_client", "share", "obs_traces"), to: k("org_client", "share", "obs", "traces"), note: "renamed to org_client.share.obs.traces"},
			{from: k("org_client", "share", "obs_content"), to: k("org_client", "share", "obs", "content"), note: "renamed to org_client.share.obs.content"},
			{from: k("org_client", "share", "obs_eval_summary"), to: k("org_client", "share", "obs", "eval_summary"), note: "renamed to org_client.share.obs.eval_summary"},
		},
	},
	{
		version: 3, // codeintel.index.disk_budget_mb removed (corpus-archival P4)
		renames: []rename{
			// No target: the knob was never implemented, and the age-based
			// [codeintel].retention_days + [archive] pair replaces the job it
			// claimed to do. See migrateRemovedCodeIntelKeys for the reasoning
			// and docs/codeintel/configuration.md for the operator-facing note.
			{from: k("codeintel", "index", "disk_budget_mb"), to: nil, note: "removed (never implemented; use codeintel.retention_days + [archive])"},
		},
	},
}

func k(segs ...string) []string { return segs }

// configVersionPath is where the schema-version stamp lives.
var configVersionPath = k("observer", "config_version")

// Change records one applied edit for reporting.
type Change struct {
	From string // dotted source path
	To   string // dotted target path; "" for a removal
	Kind string // "rename" | "remove" | "stamp"
	Note string
}

// Result is the outcome of Apply.
type Result struct {
	Text        string   // migrated text (== input when nothing changed / Skipped)
	Changes     []Change // applied edits (empty when Migrated is false)
	FromVersion int      // config_version read from the input (0 if absent)
	ToVersion   int      // config_version after migration
	Migrated    bool     // true iff ≥1 change was applied and Text differs
	Skipped     bool     // true iff a needed edit was unsafe; Text == input
	SkipReason  string
}

// LatestVersion is the config_version a fully-migrated file carries.
func LatestVersion() int {
	max := 0
	for _, s := range steps {
		if s.version > max {
			max = s.version
		}
	}
	return max
}

// Apply migrates config.toml text. It reads the [observer]
// config_version (absent ⇒ 0), applies every registry step newer than
// that, and — only when ≥1 real edit is made — stamps config_version to
// LatestVersion(). A pristine or already-current file is returned
// unchanged (Migrated=false). If any required edit cannot be performed
// by safe line surgery (a multiline/array/inline-table value), Apply
// makes NO change and returns Skipped=true — a migration never
// corrupts the file.
func Apply(text string) (Result, error) {
	doc := parseDocument(text)
	from := 0
	if v, ok := doc.readInt(configVersionPath); ok {
		from = v
	}
	latest := LatestVersion()
	res := Result{Text: text, FromVersion: from, ToVersion: from}
	if from >= latest {
		return res, nil
	}

	// Plan the edits against the ORIGINAL document so precedence and
	// target-existence are computed before any mutation.
	drop := map[int]bool{}
	type up struct {
		path []string
		rhs  string
	}
	var upserts []up
	var changes []Change
	satisfied := map[string]bool{} // target dotted paths already present or pending

	for _, m := range doc.metas {
		if m.kind == kKeyVal {
			satisfied[dottedPath(m.path)] = true
		}
	}

	for _, st := range steps {
		if st.version <= from {
			continue
		}
		for _, rn := range st.renames {
			idx := doc.findKey(rn.from)
			if idx < 0 {
				continue // legacy key not present
			}
			// Every touched source line must be a single-line scalar,
			// else we can't safely delete/move it → Skip the whole run.
			if !scalarSafe(doc.metas[idx].rhs) {
				res.Skipped = true
				res.SkipReason = "unsafe value at " + dottedPath(rn.from) + " (multiline/array/inline-table); run `observer config migrate` manually"
				res.Text = text
				res.Changes = nil
				return res, nil
			}
			drop[idx] = true
			if rn.to == nil {
				changes = append(changes, Change{From: dottedPath(rn.from), Kind: "remove", Note: rn.note})
				continue
			}
			toKey := dottedPath(rn.to)
			if satisfied[toKey] {
				// Target already set (in file or by an earlier rename):
				// drop the legacy source, keep the target authoritative.
				changes = append(changes, Change{From: dottedPath(rn.from), To: toKey, Kind: "rename", Note: "dropped (target already set)"})
				continue
			}
			upserts = append(upserts, up{path: rn.to, rhs: doc.metas[idx].rhs})
			satisfied[toKey] = true
			changes = append(changes, Change{From: dottedPath(rn.from), To: toKey, Kind: "rename", Note: rn.note})
		}
	}

	if len(drop) == 0 && len(upserts) == 0 {
		// Nothing to do (no legacy keys present). Leave the file
		// untouched — pristine configs are never rewritten.
		return res, nil
	}

	// Execute: deletions first, then upserts (each into its table),
	// then clean up hollow legacy tables, then stamp the version.
	doc.removeIndices(drop)
	for _, u := range upserts {
		doc.upsertScalar(u.path, u.rhs)
	}
	doc.dropEmptyTable(k("compression", "code_graph"))
	doc.dropEmptyTable(k("intelligence", "code_graph"))
	doc.upsertScalar(configVersionPath, strconv.Itoa(latest))
	changes = append(changes, Change{From: dottedPath(configVersionPath), Kind: "stamp", Note: "config_version = " + strconv.Itoa(latest)})

	res.Text = doc.render()
	res.Changes = changes
	res.ToVersion = latest
	res.Migrated = res.Text != text
	return res, nil
}
