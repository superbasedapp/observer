package archive

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Reclaim leftovers: the pure half of `observer archive reclaim-cleanup`
// (T-493).
//
// `observer archive reclaim --run` never deletes anything: it renames the
// original database aside as <db>.pre-reclaim-<stamp> (with its -wal / -shm)
// and leaves it for the operator. That copy is as large as the database was
// before the reclaim (the 35.7 GB one filled the disk on 2026-09-26), and
// until T-493 nothing offered to remove it. The cleanup is operator-invoked
// only, never automatic (the archive arc's standing invariant: no automatic
// deletion, no automatic full-file rewrite), and it refuses unless the
// database now in place is present and passes PRAGMA quick_check, because
// the leftover may be the only good copy.
//
// Everything here is name matching and refusal rules. The caller lists the
// directory, measures the live database and deletes; this decides.

// reclaimStamp is the UTC stamp performReclaim writes (20060102T150405Z).
const reclaimStamp = `\d{8}T\d{6}Z`

var (
	leftoverRE   = regexp.MustCompile(`^\.pre-reclaim-(` + reclaimStamp + `)(-wal|-shm)?$`)
	inProgressRE = regexp.MustCompile(`^\.reclaim-(` + reclaimStamp + `)(-wal|-shm|-journal)?$`)
)

// LeftoverFile is one file in the database's directory.
type LeftoverFile struct {
	Name  string `json:"name"`
	Bytes int64  `json:"bytes"`
}

// ReclaimLeftover is one reclaim's leftover: the renamed-aside original and
// the -wal / -shm carried with it.
type ReclaimLeftover struct {
	// Stamp is the reclaim's UTC stamp ("20260917T043021Z").
	Stamp string `json:"stamp"`
	// Files are the leftover's files, the database first.
	Files []LeftoverFile `json:"files"`
	// Bytes is the total size of Files.
	Bytes int64 `json:"bytes"`
}

// MatchLeftovers groups the reclaim leftovers of the database named dbBase
// (the base name of [observer].db_path) among a directory's files, oldest
// first, and reports whether a reclaim copy is still being written there
// (<db>.reclaim-<stamp>, which `reclaim --run` renames into place at its
// end). A name that only resembles a leftover (another database's, or a
// hand-made copy) is never matched.
func MatchLeftovers(dbBase string, files []LeftoverFile) (leftovers []ReclaimLeftover, inProgress bool) {
	byStamp := map[string]*ReclaimLeftover{}
	for _, f := range files {
		rest, ok := strings.CutPrefix(f.Name, dbBase)
		if !ok || dbBase == "" {
			continue
		}
		if inProgressRE.MatchString(rest) {
			inProgress = true
			continue
		}
		m := leftoverRE.FindStringSubmatch(rest)
		if m == nil {
			continue
		}
		l := byStamp[m[1]]
		if l == nil {
			l = &ReclaimLeftover{Stamp: m[1]}
			byStamp[m[1]] = l
		}
		l.Files = append(l.Files, f)
		l.Bytes += f.Bytes
	}
	for _, l := range byStamp {
		// The database first (the shortest name), then -shm, -wal.
		sort.Slice(l.Files, func(i, j int) bool {
			a, b := l.Files[i].Name, l.Files[j].Name
			if len(a) != len(b) {
				return len(a) < len(b)
			}
			return a < b
		})
		leftovers = append(leftovers, *l)
	}
	sort.Slice(leftovers, func(i, j int) bool { return leftovers[i].Stamp < leftovers[j].Stamp })
	return leftovers, inProgress
}

// CleanupDecision is the verdict on deleting reclaim leftovers.
type CleanupDecision string

// The closed CleanupDecision vocabulary.
const (
	// CleanupReady: the leftovers may be deleted.
	CleanupReady CleanupDecision = "ready"
	// CleanupNothing: there is nothing to delete.
	CleanupNothing CleanupDecision = "nothing_to_clean"
	// CleanupInProgress: a reclaim copy is still being written; the leftover
	// it is about to make (or the one it would restore on failure) must not
	// disappear underneath it.
	CleanupInProgress CleanupDecision = "reclaim_in_progress"
	// CleanupLiveMissing: there is no database at db_path, so a leftover may
	// be the only copy.
	CleanupLiveMissing CleanupDecision = "live_db_missing"
	// CleanupLiveUnhealthy: the database in place does not pass quick_check
	// (or could not be checked), so a leftover may be the good copy.
	CleanupLiveUnhealthy CleanupDecision = "live_db_unhealthy"
)

// CleanupInput is everything measured for a cleanup decision.
type CleanupInput struct {
	Leftovers  []ReclaimLeftover
	InProgress bool
	// LivePresent reports a regular file at db_path.
	LivePresent bool
	// LiveQuickCheck is the database's PRAGMA quick_check(1) answer ("ok"
	// when healthy); empty when it could not be run.
	LiveQuickCheck string
}

// CleanupPlan is the decision and what it covers.
type CleanupPlan struct {
	Decision CleanupDecision `json:"decision"`
	// Bytes is what deleting every leftover returns to the disk.
	Bytes int64 `json:"bytes"`
	// Reason is the operator-facing sentence for a refusal, empty when ready.
	Reason string `json:"reason,omitempty"`
}

// OK reports whether the plan permits the deletion.
func (p CleanupPlan) OK() bool { return p.Decision == CleanupReady }

// cleanupRule is one row of the ordered refusal table.
type cleanupRule struct {
	match    func(CleanupInput) bool
	decision CleanupDecision
	reason   func(CleanupInput) string
}

var cleanupRules = []cleanupRule{
	{
		func(in CleanupInput) bool { return len(in.Leftovers) == 0 },
		CleanupNothing,
		func(CleanupInput) string { return "no reclaim leftovers next to the database" },
	},
	{
		func(in CleanupInput) bool { return in.InProgress },
		CleanupInProgress,
		func(CleanupInput) string {
			return "a reclaim copy (.reclaim-<stamp>) is still next to the database: a reclaim is running or was interrupted. " +
				"Let it finish (or remove that partial copy) before deleting the leftovers"
		},
	},
	{
		func(in CleanupInput) bool { return !in.LivePresent },
		CleanupLiveMissing,
		func(CleanupInput) string {
			return "there is no database at db_path, so a leftover may be the only copy of your data. Nothing was deleted"
		},
	},
	{
		func(in CleanupInput) bool { return in.LiveQuickCheck != "ok" },
		CleanupLiveUnhealthy,
		func(in CleanupInput) string {
			got := in.LiveQuickCheck
			if got == "" {
				got = "could not be run"
			}
			return fmt.Sprintf("the database now in place does not pass quick_check (%s), so a leftover may be the good copy. "+
				"Investigate with the integrity check (Run the integrity check in Settings > Health, or `observer doctor db --integrity`) before deleting anything", got)
		},
	},
	{
		func(CleanupInput) bool { return true },
		CleanupReady,
		func(CleanupInput) string { return "" },
	},
}

// PlanLeftoverCleanup applies the refusal rules in order, first match wins
// (CLAUDE.md rule 5).
func PlanLeftoverCleanup(in CleanupInput) CleanupPlan {
	var plan CleanupPlan
	for _, l := range in.Leftovers {
		plan.Bytes += l.Bytes
	}
	for _, r := range cleanupRules {
		if r.match(in) {
			plan.Decision, plan.Reason = r.decision, r.reason(in)
			break
		}
	}
	return plan
}
