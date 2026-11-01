// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// deliverysummary.go is the org-wire seam for delivery (commit to PR to
// merge; docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md 6.2 and 12,
// operator decision D-689). It is a SEPARATE FILE from orgpush.go on purpose,
// the commitownersummary.go arrangement: orgpush.go composes the wire by
// CALLING SelectDeliveryWireRows, so the node-local delivery tables never
// appear in the push seam and tests/invariant/privacy_test.go keeps
// forbidding them there by name.
//
// This file names none of those tables either: it reaches them through the
// owning loaders in delivery.go. The only table it reads is projects (via
// commitOwnershipRootHash), for the root hash every org row carries.
//
// WHAT LEAVES:
//
//   - DeliveryDayRow, from EVERY node: per (project root hash, day) counts.
//     No sha, no branch, no title, no URL, no repo slug.
//   - PullRequestRow, ONLY under ShareOptions.shipsRawContent() (the shipRaw
//     parameter, decided by orgpush.go): provider, repo slug and its hash,
//     number, title, URL, state, readiness, merge method, dates, and the
//     sha256 of each of this node's AI-touched commits in it (the
//     CommitOwnershipRow.CommitSHAHash rule). A node not under the raw
//     posture sends none at all.
//
// COUNTING (DeliveryDayRow): commit counts are by the commit's committer day
// and by its CURRENT, EXCLUSIVE status (a landed commit counts in
// ai_commits_landed only, not also in ai_commits_pushed); landing_lost,
// in_flight and local_only count only in ai_commits. PR counts are by the
// PR's own event day (opened on created_at, merged on merged_at, closed on
// closed_at); the open-state snapshot counts (open ready, open blocked,
// draft) land on today's row, bucketed by delivery.PRBucket (an open PR
// whose readiness is unknown is neither ready nor blocked). Time to merge
// is over PRs merged that day.

// deliveryOrgWindowDays bounds which commits and PR events ship: the
// trailing window recomputed every push (the server replaces rows by natural
// key, so re-pushing is idempotent). Longer than the LOC window because a
// commit usually lands days after it is written, and its day row must still
// be inside the window when it does.
const deliveryOrgWindowDays = 30

// SelectDeliveryWireRows composes the delivery wire for every project with an
// evaluated commit committed at or after since, honouring the org-push
// project scope like SelectCommitOwnershipRows (a scope that resolves to
// nothing ships nothing). shipRaw is ShareOptions.shipsRawContent(): only
// then are PullRequestRows composed at all.
func (s *Store) SelectDeliveryWireRows(ctx context.Context, scope ScopeOptions, since time.Time, shipRaw bool) ([]orgcontract.DeliveryDayRow, []orgcontract.PullRequestRow, error) {
	now := time.Now().UTC()
	allowed, noMatch, err := s.commitOwnershipScope(ctx, scope)
	if err != nil {
		return nil, nil, fmt.Errorf("store.SelectDeliveryWireRows: scope: %w", err)
	}
	if noMatch {
		return nil, nil, nil
	}
	landings, err := s.loadLandingsWithCommitTime(ctx, 0, since, now.Add(time.Minute))
	if err != nil {
		return nil, nil, fmt.Errorf("store.SelectDeliveryWireRows: %w", err)
	}
	prs, err := s.loadWirePullRequests(ctx, since)
	if err != nil {
		return nil, nil, fmt.Errorf("store.SelectDeliveryWireRows: %w", err)
	}
	mirrors, err := s.ListDeliveryMirrors(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("store.SelectDeliveryWireRows: %w", err)
	}

	in := deliveryWireInput{since: since, now: now, mirrors: mirrors, shipRaw: shipRaw}
	in.landings = map[int64][]landingWithCommit{}
	for _, l := range landings {
		if allowed == nil || allowed[l.ProjectID] {
			in.landings[l.ProjectID] = append(in.landings[l.ProjectID], l)
		}
	}
	in.prs = map[int64][]wirePR{}
	for _, p := range prs {
		if allowed == nil || allowed[p.ProjectID] {
			in.prs[p.ProjectID] = append(in.prs[p.ProjectID], p)
		}
	}
	pids := map[int64]bool{}
	for pid := range in.landings {
		pids[pid] = true
	}
	for pid := range in.prs {
		pids[pid] = true
	}
	ordered := make([]int64, 0, len(pids))
	for pid := range pids {
		ordered = append(ordered, pid)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })

	in.rootHash, in.remotes = map[int64]string{}, map[int64][]delivery.Remote{}
	for _, pid := range ordered {
		h, err := s.commitOwnershipRootHash(ctx, pid)
		if err != nil {
			return nil, nil, fmt.Errorf("store.SelectDeliveryWireRows: %w", err)
		}
		in.rootHash[pid] = h
		rs, err := s.LoadProjectRemotes(ctx, pid)
		if err != nil {
			return nil, nil, fmt.Errorf("store.SelectDeliveryWireRows: %w", err)
		}
		in.remotes[pid] = rs
	}
	days, prRows := deliveryWireRows(in, ordered)
	return days, prRows, nil
}

// deliveryWireInput is everything deliveryWireRows reads, already loaded and
// scoped, so the emission rule is testable without a database.
type deliveryWireInput struct {
	since, now time.Time
	landings   map[int64][]landingWithCommit
	prs        map[int64][]wirePR
	rootHash   map[int64]string
	remotes    map[int64][]delivery.Remote
	mirrors    []delivery.Mirror
	shipRaw    bool
}

// dayKey is one DeliveryDayRow's node-side key.
type dayKey struct {
	project int64
	day     string
}

// landedBucket maps a landing kind to the wire's landed_* split, the same
// buckets as delivery.Summarise.
var landedBucket = map[delivery.LandingKind]func(r *orgcontract.DeliveryDayRow){
	delivery.KindExactSHA:    func(r *orgcontract.DeliveryDayRow) { r.LandedExact++ },
	delivery.KindMerge:       func(r *orgcontract.DeliveryDayRow) { r.LandedExact++ },
	delivery.KindPatchID:     func(r *orgcontract.DeliveryDayRow) { r.LandedPatch++ },
	delivery.KindRebase:      func(r *orgcontract.DeliveryDayRow) { r.LandedPatch++ },
	delivery.KindSquash:      func(r *orgcontract.DeliveryDayRow) { r.LandedSquash++ },
	delivery.KindSquashFiles: func(r *orgcontract.DeliveryDayRow) { r.LandedSquash++ },
}

// statusCounter maps a landing status to the wire counter it increments
// (statuses not listed count only in ai_commits).
var statusCounter = map[delivery.LandingStatus]func(r *orgcontract.DeliveryDayRow){
	delivery.StatusPushed:       func(r *orgcontract.DeliveryDayRow) { r.AICommitsPushed++ },
	delivery.StatusInPR:         func(r *orgcontract.DeliveryDayRow) { r.AICommitsInPR++ },
	delivery.StatusLanded:       func(r *orgcontract.DeliveryDayRow) { r.AICommitsLanded++ },
	delivery.StatusAbandoned:    func(r *orgcontract.DeliveryDayRow) { r.AICommitsAbandoned++ },
	delivery.StatusLikelyLanded: func(r *orgcontract.DeliveryDayRow) { r.AICommitsLikelyLanded++ },
}

// deliveryWireRows turns the loaded input into wire rows. Pure.
func deliveryWireRows(in deliveryWireInput, projects []int64) ([]orgcontract.DeliveryDayRow, []orgcontract.PullRequestRow) {
	rows := map[dayKey]*orgcontract.DeliveryDayRow{}
	merges := map[dayKey][]time.Duration{}
	today := in.now.UTC().Format("2006-01-02")
	var prOut []orgcontract.PullRequestRow

	for _, pid := range projects {
		source, evidenceAt := deliveryEvidence(in, pid)
		get := func(day string) *orgcontract.DeliveryDayRow {
			k := dayKey{pid, day}
			r := rows[k]
			if r == nil {
				r = &orgcontract.DeliveryDayRow{
					ProjectRootHash: in.rootHash[pid], Day: day, RuleVersion: delivery.RuleVersion,
					Source: source, FetchAgeBucket: delivery.FetchAgeBucket(evidenceAt, in.now),
				}
				rows[k] = r
			}
			return r
		}
		for _, l := range in.landings[pid] {
			r := get(l.CommittedAt.UTC().Format("2006-01-02"))
			r.AICommits++
			if inc, ok := statusCounter[l.Landing.Status]; ok {
				inc(r)
			}
			if l.Landing.Status == delivery.StatusLanded {
				if inc, ok := landedBucket[l.Landing.Kind]; ok {
					inc(r)
				}
			}
		}
		for _, w := range in.prs[pid] {
			p := w.PR
			if inWindow(p.CreatedAt, in.since) {
				get(p.CreatedAt.UTC().Format("2006-01-02")).PRsOpened++
			}
			switch delivery.PRBucket(p.State, p.Readiness) {
			case delivery.BucketMerged:
				if inWindow(p.MergedAt, in.since) {
					day := p.MergedAt.UTC().Format("2006-01-02")
					get(day).PRsMerged++
					if !p.CreatedAt.IsZero() && !p.MergedAt.Before(p.CreatedAt) {
						merges[dayKey{pid, day}] = append(merges[dayKey{pid, day}], p.MergedAt.Sub(p.CreatedAt))
					}
				}
			case delivery.BucketClosedUnmerged:
				if inWindow(p.ClosedAt, in.since) {
					get(p.ClosedAt.UTC().Format("2006-01-02")).PRsClosedUnmerged++
				}
			case delivery.BucketDraft:
				get(today).PRsDraft++
			case delivery.BucketOpenReady:
				get(today).PRsOpenReady++
			case delivery.BucketOpenBlocked:
				get(today).PRsOpenBlocked++
			}
			if in.shipRaw {
				prOut = append(prOut, pullRequestWireRow(p, w.SHAs, in.rootHash[pid]))
			}
		}
	}
	for k, ds := range merges {
		p50, p75 := delivery.Percentiles(ds)
		r := rows[k]
		r.MergeSecondsP50, r.MergeSecondsP75 = int64(p50/time.Second), int64(p75/time.Second)
		r.MergeSamples = int64(len(ds))
	}

	days := make([]orgcontract.DeliveryDayRow, 0, len(rows))
	for _, r := range rows {
		days = append(days, *r)
	}
	sort.Slice(days, func(i, j int) bool {
		if days[i].Day != days[j].Day {
			return days[i].Day > days[j].Day // newest first: truncation drops the oldest
		}
		return days[i].ProjectRootHash < days[j].ProjectRootHash
	})
	sort.SliceStable(prOut, func(i, j int) bool {
		if prOut[i].RepoSlugHash != prOut[j].RepoSlugHash {
			return prOut[i].RepoSlugHash < prOut[j].RepoSlugHash
		}
		return prOut[i].Number < prOut[j].Number
	})
	return days, prOut
}

// inWindow reports whether a non-zero event time is at or after since.
func inWindow(t, since time.Time) bool { return !t.IsZero() && !t.Before(since) }

// deliveryEvidence decides a project's Source and the time its evidence was
// last refreshed: "provider" with the newest PR fetch when a provider
// answered for it in the window, else "local" with the newest of the user's
// FETCH_HEAD and an Observer mirror refresh for one of its remotes.
func deliveryEvidence(in deliveryWireInput, pid int64) (string, time.Time) {
	var newest time.Time
	for _, w := range in.prs[pid] {
		if w.PR.FetchedAt.After(newest) {
			newest = w.PR.FetchedAt
		}
	}
	if len(in.prs[pid]) > 0 {
		return string(delivery.SourceProvider), newest
	}
	for _, r := range in.remotes[pid] {
		if r.FetchHeadAt.After(newest) {
			newest = r.FetchHeadAt
		}
		for _, m := range in.mirrors {
			if m.Status == "ok" && m.URL != "" && m.URL == r.URL && m.LastRefreshAt.After(newest) {
				newest = m.LastRefreshAt
			}
		}
	}
	return "local", newest
}

// pullRequestWireRow builds one raw-content PR row.
func pullRequestWireRow(p delivery.PullRequest, shas []string, rootHash string) orgcontract.PullRequestRow {
	hashes := make([]string, 0, len(shas))
	for _, sha := range shas {
		hashes = append(hashes, sha256Hex(sha))
	}
	sort.Strings(hashes)
	return orgcontract.PullRequestRow{
		Provider:        string(p.Provider),
		RepoSlug:        p.RepoSlug,
		RepoSlugHash:    delivery.RepoSlugHash(p.Host, p.RepoSlug),
		Number:          p.Number,
		Title:           p.Title,
		URL:             p.URL,
		PRState:         string(p.State),
		MergeReadiness:  string(p.Readiness),
		MergeMethod:     string(p.MergeMethod),
		CreatedAt:       rfc3339OrEmpty(p.CreatedAt),
		MergedAt:        rfc3339OrEmpty(p.MergedAt),
		ClosedAt:        rfc3339OrEmpty(p.ClosedAt),
		ProjectRootHash: rootHash,
		CommitSHAHashes: hashes,
	}
}

func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
