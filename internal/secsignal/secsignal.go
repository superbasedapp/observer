package secsignal

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secrank"
	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secreachsvc"
)

// Inputs are one project's findings and the injected reads.
type Inputs struct {
	// Root is the project root the findings are listed under ("" when
	// unknown: every tier is then unknown, the exploit answer still reads).
	Root string
	// Findings are the project's findings; only vulnerable_dependency ones
	// get a signal.
	Findings []secfinding.Finding
	// Evidence maps a finding id to its redacted dependency evidence
	// (store.SecDependencyEvidence).
	Evidence map[string]string
	// Record reads one OSV record from the node's LOCAL database
	// (osvdb.DetailLookup); nil reads none (every tier unknown, the exploit
	// ids are the finding's own).
	Record func(eco, id string) ([]byte, error)
	// Exploit answers the exploit data for a finding's ids
	// (osvdb.ExploitLookup); nil answers every finding "unavailable".
	Exploit func(ids []string) secexploit.Exploit
	// Reach are the options of the reach tier (secreachsvc.WithCache,
	// WithCodeIntel, PreferCodeIntel).
	Reach []secreachsvc.Option
	// Symbol are the project's stored Go symbol checks
	// (secreachsvc.LoadSymbolRuns; plan section 14.5 item 3b); nil leaves
	// every tier at import level.
	Symbol []secreach.SymbolRun
	// Sightings returns every project-relative path a finding was seen at
	// (store.SecFindingSightings). nil, or an error, means only the
	// finding's location is known, and a symbol check then never says "not
	// called" for it.
	Sightings func(ctx context.Context, findingID string) ([]string, error)
}

// Signal is one dependency finding's signals.
type Signal struct {
	// Reach is the import-level reachability tier.
	Reach secreach.Tier
	// Exploit is the KEV and EPSS answer; both kinds unavailable when the
	// data is missing or stale (never "not exploited").
	Exploit secexploit.Exploit
}

// Key is the signal's rank key (secrank).
func (s Signal) Key() secrank.Key { return secrank.KeyOf(s.Reach, s.Exploit) }

// Compute returns the signals of every vulnerable_dependency finding of
// in.Findings, keyed by finding id (other findings are not in the map).
func Compute(ctx context.Context, in Inputs) map[string]Signal {
	record := memoRecord(in.Record)
	advs := map[string]secreach.Advisory{}
	pkgs := map[string]secdepdetail.Package{}
	ids := map[string][]string{}
	symIDs := map[string][]string{}
	var deps []secfinding.Finding
	for _, f := range in.Findings {
		if f.Category != policy.FindingVulnerableDependency {
			continue
		}
		deps = append(deps, f)
		own := secdepdetail.AdvisoryIDs(f.Rule.ID, f.Message)
		pkg, recs, ok := secdepdetail.LookupAffectedImports(secdepdetail.Input{
			Category: string(f.Category), Evidence: in.Evidence[f.ID], RuleID: f.Rule.ID, Message: f.Message,
			LookupRecord: record,
		})
		if ok {
			for _, r := range recs {
				own = append(own, r.ID)
				own = append(own, r.Aliases...)
			}
			adv := secreachsvc.AdvisoryFrom(pkg, recs)
			adv.Artifact = secreachsvc.IsGoBinaryStdlib(pkg.Ecosystem, pkg.Name, f.Location.RelPath)
			advs[f.ID] = adv
			pkgs[f.ID] = pkg
		}
		if len(in.Symbol) > 0 {
			symIDs[f.ID] = dedupe(own, len(own))
		}
		ids[f.ID] = dedupe(own, secexploit.MaxLookupIDs)
	}
	out := make(map[string]Signal, len(deps))
	if len(deps) == 0 {
		return out
	}
	lookup := func(id string) (secreach.Advisory, bool) {
		a, ok := advs[id]
		return a, ok
	}
	tiers := secreachsvc.Tiers(ctx, in.Root, deps, lookup, in.Reach...)
	for _, f := range deps {
		s := Signal{Reach: tiers[f.ID]}
		if s.Reach.Level == "" {
			s.Reach = secreach.UnknownTier(secreach.ReasonNoImportData)
		}
		if pkg, ok := pkgs[f.ID]; ok && len(in.Symbol) > 0 {
			s.Reach = secreach.ApplySymbol(s.Reach, symbolQuery(ctx, in, f, pkg, symIDs[f.ID]), in.Symbol)
		}
		if in.Exploit != nil {
			s.Exploit = in.Exploit(ids[f.ID])
		}
		out[f.ID] = s
	}
	return out
}

// symbolQuery is what the symbol checks are matched against for one
// finding: its package, every advisory id it names or was read through,
// and every path it was seen at.
func symbolQuery(ctx context.Context, in Inputs, f secfinding.Finding, pkg secdepdetail.Package, ids []string) secreach.SymbolQuery {
	q := secreach.SymbolQuery{Module: pkg.Name, Version: pkg.Version, IDs: ids}
	if f.Location.RelPath != "" {
		q.Paths = append(q.Paths, f.Location.RelPath)
	}
	if in.Sightings == nil {
		return q
	}
	seen, err := in.Sightings(ctx, f.ID)
	if err != nil {
		return q
	}
	q.PathsKnown = true
	for _, p := range seen {
		dup := false
		for _, have := range q.Paths {
			dup = dup || have == p
		}
		if !dup && p != "" {
			q.Paths = append(q.Paths, p)
		}
	}
	return q
}

// memoRecord reads each (ecosystem, id) record once per Compute.
func memoRecord(read func(eco, id string) ([]byte, error)) func(eco, id string) ([]byte, error) {
	if read == nil {
		return nil
	}
	type res struct {
		b   []byte
		err error
	}
	seen := map[string]res{}
	return func(eco, id string) ([]byte, error) {
		k := eco + "\x00" + id
		r, ok := seen[k]
		if !ok {
			r.b, r.err = read(eco, id)
			seen[k] = r
		}
		return r.b, r.err
	}
}

func dedupe(ids []string, max int) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] || len(out) >= max {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
