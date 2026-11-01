package main

import (
	"fmt"
	"io"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// printProjectRootRepair renders the --foreign-project-roots report: one
// line per repaired row, then its per-table counts, then the foreign-looking
// rows left alone.
func printProjectRootRepair(w io.Writer, r store.ProjectRootRepairReport) {
	mode := "DRY RUN (rolled back; pass --apply to commit)"
	if r.Applied {
		mode = "APPLIED"
	}
	fmt.Fprintf(w, "foreign-project-roots: %d row(s) to repair - %s\n", len(r.Repairs), mode)
	for _, rep := range r.Repairs {
		switch rep.Action {
		case store.RepairMerge:
			fmt.Fprintf(w, "  merge  #%d %q -> #%d %q\n", rep.ProjectID, rep.Root, rep.TwinID, rep.NewRoot)
		default:
			fmt.Fprintf(w, "  rename #%d %q -> %q\n", rep.ProjectID, rep.Root, rep.NewRoot)
		}
		printRepairCounts(w, "moved", rep.Repointed)
		printRepairCounts(w, "dropped (twin's copy kept)", rep.Collisions)
		printRepairCounts(w, "root-keyed, left as written", rep.RootKeyed)
	}
	if len(r.Unrepaired) > 0 {
		fmt.Fprintf(w, "  %d foreign-looking row(s) with no unambiguous host spelling, left alone:\n", len(r.Unrepaired))
		for _, u := range r.Unrepaired {
			fmt.Fprintf(w, "    #%d %q\n", u.ID, u.Root)
		}
	}
}

func printRepairCounts(w io.Writer, label string, counts map[string]int64) {
	if len(counts) == 0 {
		return
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "         %s:", label)
	for _, k := range keys {
		fmt.Fprintf(w, " %s=%d", k, counts[k])
	}
	fmt.Fprintln(w)
}
