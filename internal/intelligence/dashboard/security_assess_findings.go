//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_assess_findings.go is what the plan reads of the node's findings
// store: the secret check of the Refuse setting and the digest's list of open
// findings (depth plan W3.2, W4.4 and the lane A review fixes). The two reads are
// separate, because they answer differently when the store cannot:
//
//   - the digest's list is advice, so a store that cannot be read gives no list;
//   - the secret check is the only thing Observer enforces about environment
//     files, so under Refuse a store that cannot be read, a project the store has
//     never seen, or a read that ran out of pages is a refusal, never "none".

// securityAssessFindingsSource is the part of the findings store the two reads
// use (a *store.Store; the interface lets a test make it fail).
type securityAssessFindingsSource interface {
	ListSecFindings(ctx context.Context, f store.SecFindingFilter) ([]secfinding.Finding, error)
	SecFindingGroups(ctx context.Context, f store.SecFindingFilter, q store.SecGroupQuery) (store.SecFindingGroupsPage, error)
	SecLastScan(ctx context.Context, rootHash string) (time.Time, error)
}

// securityAssessSecretState is what the findings store says about secrets in
// environment and key files.
type securityAssessSecretState struct {
	// OpenSecret says an open secret finding sits in an environment or key file
	// (any depth, by the one table secassess.IsEnvOrKeyFile).
	OpenSecret bool
	// Unreadable says the store could not answer completely: no store, no
	// project, an error, or more open secrets than the bounded read covers
	// without finding one.
	Unreadable bool
	// Scan is secassess.ScanDone or ScanNever (ScanUnasked when Unreadable);
	// LastScan is the day of the newest scan ("2006-01-02").
	Scan     string
	LastScan string
}

// securityAssessReadSecretState reads the open secret findings of the project
// page by page until it finds one in an environment or key file or runs out of
// rows (no row window: the older read took 500 rows and filtered them, so an
// environment file's finding past the 500th was missed), and asks when the
// project was last scanned, so "none open" is never said for a project nobody
// has scanned.
func securityAssessReadSecretState(ctx context.Context, src securityAssessFindingsSource, hash string) securityAssessSecretState {
	if src == nil || hash == "" {
		return securityAssessSecretState{Unreadable: true}
	}
	out := securityAssessSecretState{}
	complete := false
	for page := 0; page < securityAssessSecretsPages; page++ {
		rows, err := src.ListSecFindings(ctx, store.SecFindingFilter{
			ProjectRootHash: hash, Status: policy.FindingStatusOpen, Categories: []string{string(policy.FindingSecret)},
			Limit: securityAssessSecretsPage, Offset: page * securityAssessSecretsPage,
		})
		if err != nil {
			return securityAssessSecretState{Unreadable: true}
		}
		for _, f := range rows {
			if secassess.IsEnvOrKeyFile(f.Location.RelPath) {
				out.OpenSecret = true
				break
			}
		}
		if out.OpenSecret {
			complete = true
			break
		}
		if len(rows) < securityAssessSecretsPage {
			complete = true
			break
		}
	}
	// An open secret in an environment file is an answer however far the read got;
	// "none" is only an answer when every row was seen.
	if !complete {
		out.Unreadable = true
		return out
	}
	last, err := src.SecLastScan(ctx, hash)
	if err != nil {
		return securityAssessSecretState{Unreadable: true, OpenSecret: out.OpenSecret}
	}
	if last.IsZero() {
		out.Scan = secassess.ScanNever
		return out
	}
	out.Scan, out.LastScan = secassess.ScanDone, last.UTC().Format("2006-01-02")
	return out
}

// securityAssessOpenList is the digest's list of open findings.
type securityAssessOpenList struct {
	// Refs are the first securityAssessMaxGroundFindings open findings by
	// severity that are neither Observer's own assessment findings, nor secrets,
	// nor in an environment or key file (so the digest never hands the agent the
	// file and line of a live secret).
	Refs []secassess.FindingRef
	// Total is how many open findings the project has that are not secrets and
	// not Observer's own assessment findings (a finding left out of Refs only for
	// its path still counts, and the digest says the rest are not listed).
	Total int
}

// securityAssessNonSecretCategories are the finding categories the digest
// reads: every category but secret.
func securityAssessNonSecretCategories() []string {
	var out []string
	for _, c := range policy.FindingCategories() {
		if c != policy.FindingSecret {
			out = append(out, string(c))
		}
	}
	return out
}

// securityAssessReadOpenList reads the digest's list. It pages by severity until
// it has securityAssessMaxGroundFindings rows to list or runs out of rows (the
// module's own findings can fill a window, so there is no fixed window), and
// counts the whole set by rule (one grouped query), so the digest can say "top
// 20 of N". A store that cannot be read gives an empty list: the plan is advice.
func securityAssessReadOpenList(ctx context.Context, src securityAssessFindingsSource, hash string) securityAssessOpenList {
	var out securityAssessOpenList
	if src == nil || hash == "" {
		return out
	}
	cats := securityAssessNonSecretCategories()
	base := store.SecFindingFilter{ProjectRootHash: hash, Status: policy.FindingStatusOpen, Categories: cats}
	for off := 0; ; off += store.SecGroupMaxLimit {
		page, err := src.SecFindingGroups(ctx, base, store.SecGroupQuery{By: store.SecGroupRule, Limit: store.SecGroupMaxLimit, Offset: off})
		if err != nil {
			return securityAssessOpenList{}
		}
		for _, g := range page.Groups {
			if !securityAssessOwnRule(g.RuleID) {
				out.Total += g.Count
			}
		}
		if len(page.Groups) < store.SecGroupMaxLimit {
			break
		}
	}
	for page := 0; page < securityAssessFindingsPages && len(out.Refs) < securityAssessMaxGroundFindings; page++ {
		f := base
		f.Limit, f.Offset, f.Sort, f.Desc = securityAssessFindingsPage, page*securityAssessFindingsPage, store.SecSortSeverity, true
		rows, err := src.ListSecFindings(ctx, f)
		if err != nil {
			return securityAssessOpenList{}
		}
		for _, r := range rows {
			if securityAssessOwnRule(r.Rule.ID) || secassess.IsEnvOrKeyFile(r.Location.RelPath) {
				continue
			}
			out.Refs = append(out.Refs, secassess.FindingRef{RuleID: r.Rule.ID, Path: r.Location.RelPath, Line: r.Location.StartLine})
			if len(out.Refs) == securityAssessMaxGroundFindings {
				break
			}
		}
		if len(rows) < securityAssessFindingsPage {
			break
		}
	}
	return out
}
