// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
)

// commitownersummary.go is the org-wire seam for commit ownership (lane
// F-PROJ, internal/orgcontract/commitowner.go). It is a SEPARATE FILE from
// internal/store/orgpush.go on purpose, the locsummary.go arrangement:
// orgpush.go composes the wire by CALLING SelectCommitOwnershipRows, so the
// node-local commit tables (project_commits / project_commit_files /
// project_commit_scan) never appear in the push seam and
// tests/invariant/privacy_test.go keeps forbidding them there by name.
//
// This file names none of those tables either. It reaches them only through
// their owning loaders: ProjectsWithCommitsSince (commits.go) picks the
// candidate projects, and LoadCommitOwnership (commitowner.go) runs the ONE
// ownership fold the node dashboard's session "Commits" section and the
// Projects commit ledger read, so the node and the org can never answer
// "which session owned this commit" with two different rules. The only table
// this file reads directly is projects, to map a project id to the
// root_path_hash every other org wire row already carries.
//
// WHAT LEAVES (COMMIT-3 in docs/security.md): per commit, ids and counts,
// keyed by the sha256 HASH of the commit id. Never the author hash
// (COMMIT-2), never a path, a rel_path or a path hash. The raw commit id and
// the subject only under the raw-content posture (the shipRaw parameter,
// decided by orgpush.go from ShareOptions.shipsRawContent(); review
// 2026-09-29 finding 3).
//
// WHICH COMMITS: an OWNED commit (at least one AI contributor) committed in
// the trailing window; and an UNREACHABLE non-merge commit anywhere in the
// FOLD window (the emit window plus the link window), as an identity-only row
// (sha hash, time, flags, reason) so the server can flip a row it stored
// earlier to "no longer on the checked-out branch" while keeping the last
// known owner. The unreachable flip is emitted across the whole fold window,
// not only the emit window (review 2026-09-29 finding 5): a commit the org
// stored while it was in the window and that fell out of HEAD after it aged
// past the window must still reach the org. The scanner revalidates
// reachability over LinkWindow + 24h, which the fold window (7d + LinkWindow)
// covers. A commit no AI edit reached, a foreign-author commit, and every
// merge, stay on the node.

// commitOwnershipOrgWindowDays bounds which commits ship: those COMMITTED in
// the trailing window. It is the Lines-of-Code wire's window
// (locOrgWindowDays): the server upserts by natural key, so re-pushing the
// window is idempotent, and a commit older than the window keeps the row the
// server already holds.
const commitOwnershipOrgWindowDays = locOrgWindowDays

// orgCommitLinkWindow is the link window the org composer folds with. The
// store has no route to the node's [projects].commit_link_window_days (the
// config lives with the dashboard and the commit scanner, not the push seam),
// so the wire uses the rule's own default, projectroi.DefaultLinkWindow - the
// same 14 days the config ships with. A node that configured a different
// window can therefore see a different owner on its own dashboard for a
// commit whose contributing prompts sit between the two windows; that
// divergence is documented in docs/projects-page.md "Org projection of commit
// ownership".
const orgCommitLinkWindow = projectroi.DefaultLinkWindow

// orgOwnershipCaps are the loader caps for one project's fold, the node
// dashboard's own Projects caps (internal/intelligence/dashboard/projects.go
// promptLinkCap / editLinkCap / commitLinkCap), so both surfaces fold the same
// input on any realistic project.
var orgOwnershipCaps = OwnershipCaps{Prompts: 10000, Edits: 100000, Commits: 5000}

// SelectCommitOwnershipRows composes the commit-ownership wire for every
// project with a commit in the trailing window, honouring the org-push
// project scope the way locsummary.go's locScopeClause does (a scope that
// resolves to nothing ships nothing). shipRaw is the
// ShareOptions.shipsRawContent() gate for the raw commit id and the commit
// subject; linkWindow <= 0 means projectroi.DefaultLinkWindow.
//
// The fold for each project loads [now - window - linkWindow, now]: every
// prompt that can still be carried by a commit inside the window is inside
// that span, so an in-window commit's owner is exactly the owner the node's
// own views compute. Owned rows are emitted only for commits committed inside
// the window; unreachable identity-only rows for any commit in the fold span.
func (s *Store) SelectCommitOwnershipRows(ctx context.Context, scope ScopeOptions, shipRaw bool, linkWindow time.Duration) ([]orgcontract.CommitOwnershipRow, error) {
	if linkWindow <= 0 {
		linkWindow = projectroi.DefaultLinkWindow
	}
	now := time.Now().UTC()
	emitSince := now.AddDate(0, 0, -commitOwnershipOrgWindowDays)
	loadSince := emitSince.Add(-linkWindow)
	until := now.Add(time.Minute) // the loaders' upper bound is exclusive

	allowed, noMatch, err := s.commitOwnershipScope(ctx, scope)
	if err != nil {
		return nil, fmt.Errorf("store.SelectCommitOwnershipRows: scope: %w", err)
	}
	if noMatch {
		return nil, nil
	}
	// Candidates are projects with ANY commit in the fold span (not only the
	// emit window), so an older commit's unreachable flip is still composed.
	pids, err := s.ProjectsWithCommitsSince(ctx, loadSince)
	if err != nil {
		return nil, fmt.Errorf("store.SelectCommitOwnershipRows: %w", err)
	}
	var out []orgcontract.CommitOwnershipRow
	for _, pid := range pids {
		if allowed != nil && !allowed[pid] {
			continue
		}
		rootHash, err := s.commitOwnershipRootHash(ctx, pid)
		if err != nil {
			return nil, fmt.Errorf("store.SelectCommitOwnershipRows: %w", err)
		}
		res, err := s.LoadCommitOwnership(ctx, pid, loadSince, until, linkWindow, orgOwnershipCaps)
		if err != nil {
			return nil, fmt.Errorf("store.SelectCommitOwnershipRows: %w", err)
		}
		out = append(out, commitOwnershipWireRows(res, rootHash, emitSince, shipRaw)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.CommittedAt != b.CommittedAt {
			return a.CommittedAt > b.CommittedAt // newest first: truncation drops the oldest
		}
		if a.ProjectRootHash != b.ProjectRootHash {
			return a.ProjectRootHash < b.ProjectRootHash
		}
		return a.CommitSHAHash < b.CommitSHAHash
	})
	return out, nil
}

// commitOwnershipWireRows turns one project's fold into wire rows. Pure over
// its inputs so the emission rule is testable without a database. The rule,
// top-down per commit:
//
//  1. committed inside the emit window AND owned -> the full row;
//  2. unreachable and not a merge (ANY age the fold loaded) -> identity only;
//  3. anything else never leaves the node.
//
// Every row carries CommitSHAHash; CommitSHA and Subject only under shipRaw.
func commitOwnershipWireRows(res CommitOwnershipResult, rootHash string, emitSince time.Time, shipRaw bool) []orgcontract.CommitOwnershipRow {
	// Distinct AI-carried files per commit, from the same Linkage the
	// ownership was folded from (a superseded pair carries nothing).
	aiPaths := map[int64]map[string]bool{}
	for _, chain := range res.Linkage.Chains {
		for _, f := range chain.Files {
			if f.Superseded || f.CommitID == 0 {
				continue
			}
			set := aiPaths[f.CommitID]
			if set == nil {
				set = map[string]bool{}
				aiPaths[f.CommitID] = set
			}
			set[f.PathHash] = true
		}
	}

	var out []orgcontract.CommitOwnershipRow
	for _, c := range res.Commits {
		inWindow := !c.CommittedAt.Before(emitSince)
		own := res.Ownership[c.ID]
		row := orgcontract.CommitOwnershipRow{
			ProjectRootHash: rootHash,
			CommitSHAHash:   sha256Hex(c.SHA),
			CommittedAt:     c.CommittedAt.UTC().Format(time.RFC3339),
			Reachable:       c.Reachable,
			IsMerge:         c.IsMerge,
			OwnerReason:     own.Reason,
			RuleVersion:     projectroi.OwnershipRuleVersion,
		}
		if shipRaw {
			row.CommitSHA = c.SHA
		}
		switch {
		case inWindow && own.OwnerSessionID != "":
			row.FilesCount, row.Added, row.Deleted = int64(c.FilesCount), int64(c.Added), int64(c.Deleted)
			row.OwnerSessionID = own.OwnerSessionID
			row.ShareBasis = own.ShareBasis
			row.AIFiles = int64(len(aiPaths[c.ID]))
			for _, con := range own.Contributors {
				row.AICodeLines += int64(con.CodeLines)
				row.AICommentLines += int64(con.CommentLines)
				row.Contributors = append(row.Contributors, orgcontract.CommitContributorRow{
					SessionID: con.SessionID, Share: con.Share,
					CodeLines: int64(con.CodeLines), CommentLines: int64(con.CommentLines),
					Files: int64(con.Files), Prompts: int64(con.Prompts),
				})
			}
			if shipRaw {
				row.Subject = c.Subject
			}
		case !c.Reachable && !c.IsMerge:
			// Identity only: enough for the server to flip a stored row's
			// reachable flag, nothing about the commit's content or author.
			// Any age the fold loaded (finding 5): the owner ranking treats
			// an unreachable commit as owner=none, so this row never
			// carries numstat, contributors or a subject.
		default:
			// A commit no AI edit reached, or a merge: never leaves the node.
			continue
		}
		out = append(out, row)
	}
	return out
}

// commitOwnershipScope resolves the org-push project scope to an allowed
// project-id set. A nil set with noMatch=false means "no filter".
func (s *Store) commitOwnershipScope(ctx context.Context, scope ScopeOptions) (allowed map[int64]bool, noMatch bool, err error) {
	filter, noMatch, err := s.resolveScopeFilter(ctx, scope)
	if err != nil || noMatch || filter == "" {
		return nil, noMatch, err
	}
	allowed = map[int64]bool{}
	for _, part := range strings.Split(filter, ",") {
		id, perr := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if perr != nil {
			return nil, false, fmt.Errorf("store.commitOwnershipScope: parse %q: %w", part, perr)
		}
		allowed[id] = true
	}
	return allowed, false, nil
}

// commitOwnershipRootHash returns projects.root_path_hash for one project ("" when
// the column is NULL).
func (s *Store) commitOwnershipRootHash(ctx context.Context, projectID int64) (string, error) {
	var h *string
	if err := s.db.QueryRowContext(ctx, `SELECT root_path_hash FROM projects WHERE id = ?`, projectID).Scan(&h); err != nil {
		return "", fmt.Errorf("store.commitOwnershipRootHash: %w", err)
	}
	if h == nil {
		return "", nil
	}
	return *h, nil
}

// probeCommitOwnership is the snapshot-gate fingerprint for the
// commit-ownership family: the fold reads commits AND AI line changes, so the
// fingerprint is both owners' probes joined. Neither table name appears here;
// each probe lives with its table's owner (commits.go, locsummary.go).
func (s *Store) probeCommitOwnership(ctx context.Context) (string, error) {
	pc, err := s.probeProjectCommits(ctx)
	if err != nil {
		return "", err
	}
	fc, err := s.probeFileChanges(ctx)
	if err != nil {
		return "", err
	}
	return pc + "|" + fc, nil
}
