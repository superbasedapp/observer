package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer backfill --commits` — a full-history read-only `git log` pass
// over every known project (or one named project), for an operator who
// wants the Projects page's commit ledger populated immediately rather
// than waiting for the daemon-lifetime scanner (internal/commitscan) to
// walk up to it on its own ticks. Goes through the exact same
// newCommitScanner wiring the daemon loop uses (commitscan_wire.go) —
// FullScan, not ScanOnce — so a backfilled row and a live-captured one are
// identical by construction (the lines-of-code tracking "one path" rule).

// CommitsBackfillReport is the JSON-shaped summary of one --commits run.
type CommitsBackfillReport struct {
	ProjectsScanned int                             `json:"projects_scanned"`
	CommitsSeen     int                             `json:"commits_seen"`
	Inserted        int                             `json:"inserted"`
	Projects        map[string]CommitsProjectReport `json:"projects,omitempty"`
}

// CommitsProjectReport is one project's outcome within a --commits run.
type CommitsProjectReport struct {
	ProjectID   int64  `json:"project_id"`
	CommitsSeen int    `json:"commits_seen"`
	Inserted    int    `json:"inserted"`
	Error       string `json:"error,omitempty"`
}

// commitsBackfillArgs carries the --commits-* flags into the pass.
type commitsBackfillArgs struct {
	Since     string
	ProjectID int64
}

// commitsSinceDays matches a bare "<N>d" relative-days shorthand
// (e.g. "90d"), the one duration form --commits-since accepts beyond an
// absolute RFC3339/date timestamp.
var commitsSinceDays = regexp.MustCompile(`^(\d+)d$`)

// parseCommitsSince parses --commits-since as EITHER a relative "<N>d"
// duration or an absolute RFC3339/RFC3339Nano/YYYY-MM-DD timestamp. Empty
// means the beginning of history (a true full-history scan).
func parseCommitsSince(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if m := commitsSinceDays.FindStringSubmatch(s); m != nil {
		days, err := strconv.Atoi(m[1])
		if err == nil {
			return time.Now().UTC().AddDate(0, 0, -days), nil
		}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("backfillCommits: --commits-since %q: want <N>d, RFC3339, or YYYY-MM-DD", s)
}

// backfillCommits runs a FullScan over every known project (or just
// args.ProjectID, when set), writing through the SAME commitscan.Scanner
// the daemon loop uses.
func backfillCommits(ctx context.Context, database *sql.DB, args commitsBackfillArgs, out io.Writer) (CommitsBackfillReport, error) {
	rep := CommitsBackfillReport{Projects: map[string]CommitsProjectReport{}}

	since, err := parseCommitsSince(args.Since)
	if err != nil {
		return rep, err
	}

	st := store.New(database)
	// Every KNOWN project (sinceDays<=0 = no bound) — a backfill is an
	// explicit operator request, not the daemon's "only active projects"
	// polling posture.
	roots, err := st.ActiveProjectRoots(ctx, 0)
	if err != nil {
		return rep, fmt.Errorf("backfillCommits: list projects: %w", err)
	}
	if args.ProjectID > 0 {
		filtered := roots[:0]
		for _, r := range roots {
			if r.ID == args.ProjectID {
				filtered = append(filtered, r)
			}
		}
		roots = filtered
		if len(roots) == 0 {
			return rep, fmt.Errorf("backfillCommits: no project with id %d", args.ProjectID)
		}
	}

	sc := newCommitScanner(st, config.ProjectsConfig{CommitLinkWindowDays: 14}, nil)

	for _, r := range roots {
		res, serr := sc.FullScan(ctx, commitscan.Root{ProjectID: r.ID, RootPath: r.RootPath}, since, 0)
		pr := CommitsProjectReport{ProjectID: r.ID, CommitsSeen: res.CommitsSeen, Inserted: res.Inserted}
		if serr != nil {
			pr.Error = serr.Error()
		}
		rep.Projects[r.RootPath] = pr
		rep.ProjectsScanned++
		rep.CommitsSeen += res.CommitsSeen
		rep.Inserted += res.Inserted
		if out != nil {
			status := "ok"
			if serr != nil {
				status = "error: " + serr.Error()
			}
			fmt.Fprintf(out, "  commits: %s — %d commits, %d inserted (%s)\n", r.RootPath, res.CommitsSeen, res.Inserted, status)
		}
	}
	return rep, nil
}
