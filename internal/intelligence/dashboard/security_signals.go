//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secexploit"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrank"
	"github.com/marmutapp/superbased-observer/internal/secreach"
	"github.com/marmutapp/superbased-observer/internal/secreachsvc"
	"github.com/marmutapp/superbased-observer/internal/secsignal"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_signals.go is the Code security page's view of the per-finding
// ranking signals of dependency findings (OS and CI scanning plan sections
// 14.5 and 14.7, M3L-1): the import-level reachability tier and the CISA
// KEV and FIRST EPSS labels, computed at VIEW time by internal/secsignal
// (never stored) and ordered by internal/secrank. Ruling Q14-4 (a): they
// rank and label only; they never close, hide or re-grade a finding or
// change its severity, and the posture never reads them.
//
// The reach tier reads the project's import list through a cache shared by
// every request (a cold parse of a large tree can take seconds; the parse
// is bounded by secreachsvc's limits, and the codeintel index is tried
// first when it holds the whole project). The exploit data is the
// installed, verified files only (security_depdetail_osv.go); missing or
// stale data reads "exploit data unavailable", never "not exploited".

// securityReachCache is the import lists the findings list and drawer
// share, one per project root: fresh for secreachsvc.DefaultCacheTTL, then
// served for up to securityReachStale while it rebuilds in the background
// (at most securityReachWorkers parses at once). While it was a plain
// cache, every findings page past the TTL re-parsed each project it showed
// inline: 10 to 20 s per page on a node with twenty worktrees of one large
// repository (2026-11-06).
var securityReachCache = sync.OnceValue(func() *secreachsvc.Cache {
	return secreachsvc.NewBackgroundCache(0, securityReachStale, securityReachWorkers)
})

// securityReachStale is how long past its TTL an import list is served
// while it rebuilds; securityReachWorkers bounds the background parses.
const (
	securityReachStale   = 6 * time.Hour
	securityReachWorkers = 2
)

// securityPendingReasons are the unknown reasons a list that is still
// being built produces (no Go list, no codeintel list, no Python
// metadata): a list read that did not wait relabels them as pending.
var securityPendingReasons = map[secreach.Reason]bool{
	secreach.ReasonNoImportData:  true,
	secreach.ReasonNoCodeIntel:   true,
	secreach.ReasonNoNameMapping: true,
	secreach.ReasonIncomplete:    true,
}

// securityReachJS is a dependency finding's reachability tier.
type securityReachJS struct {
	// Level is "called", "imported", "potentially_affected", "not_called",
	// "not_imported_directly" or "unknown".
	Level     string `json:"level"`
	TestsOnly bool   `json:"tests_only,omitempty"`
	// Approximate: the tier rests on a name match (a Rust call site, a
	// Python distribution's own name).
	Approximate bool `json:"approximate,omitempty"`
	// Source is "go imports", "codeintel" or "codeintel-rust-callsite" for
	// an import-level tier, "go-buildinfo" for a binary's version match,
	// "govulncheck-binary" or "govulncheck-source" for a symbol-level one.
	Source string `json:"source,omitempty"`
	// Reason says why the tier is unknown.
	Reason string `json:"reason,omitempty"`
	// Target is the project-relative binary or go.mod a symbol-level tier
	// rests on.
	Target string `json:"target,omitempty"`
	// Symbol is the listed function a "called" tier reached.
	Symbol string `json:"symbol,omitempty"`
	// SymbolNote says why a symbol check that covered the finding could
	// not decide ("stripped_binary"); the tier is then the import level's.
	SymbolNote string `json:"symbol_note,omitempty"`
	// Label is the tier in words ("imported (go imports)").
	Label string `json:"label"`
}

// securityExploitJS is a dependency finding's exploit labels. A kind that
// is not available says so (KEVAvailable / EPSSAvailable false); it is
// never read as "not exploited".
type securityExploitJS struct {
	KEVAvailable  bool                   `json:"kev_available"`
	EPSSAvailable bool                   `json:"epss_available"`
	KEV           *securityExploitKEVJS  `json:"kev,omitempty"`
	EPSS          *securityExploitEPSSJS `json:"epss,omitempty"`
	// Badges are the labels in words (secexploit.Badges), most severe
	// first; "Exploit data unavailable" when neither kind answered.
	Badges []string `json:"badges"`
	// EPSSCitation is FIRST's requested citation, set whenever an EPSS
	// value is shown.
	EPSSCitation string `json:"epss_citation,omitempty"`
	// KEVNotice is the plain-words KEV source line (no CISA branding), set
	// when the finding is listed.
	KEVNotice string `json:"kev_notice,omitempty"`
}

type securityExploitKEVJS struct {
	CVE        string `json:"cve"`
	DateAdded  string `json:"date_added"`
	Ransomware bool   `json:"ransomware,omitempty"`
}

type securityExploitEPSSJS struct {
	CVE        string  `json:"cve"`
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Model      string  `json:"model,omitempty"`
	Date       string  `json:"date,omitempty"`
}

func securityReachJSOf(t secreach.Tier) *securityReachJS {
	out := &securityReachJS{
		Level: string(t.Level), TestsOnly: t.TestsOnly, Approximate: t.Approximate, Source: t.Source, Reason: string(t.Reason), Label: t.Label(),
		Target: t.Target, SymbolNote: string(t.SymbolNote),
	}
	if t.Level == secreach.Called && t.Target != "" {
		out.Symbol = t.Match
	}
	return out
}

func securityExploitJSOf(x secexploit.Exploit) *securityExploitJS {
	out := &securityExploitJS{KEVAvailable: x.KEVAvailable, EPSSAvailable: x.EPSSAvailable, Badges: secexploit.Badges(x)}
	if x.KEVAvailable && x.KEV != nil {
		out.KEV = &securityExploitKEVJS{CVE: x.KEV.CVE, DateAdded: x.KEV.DateAdded, Ransomware: x.KEV.Ransomware}
		out.KEVNotice = secexploit.KEVNotice
	}
	if x.EPSSAvailable && x.EPSS != nil {
		out.EPSS = &securityExploitEPSSJS{CVE: x.EPSSCVE, Score: x.EPSS.Score, Percentile: x.EPSS.Percentile, Model: x.EPSSModel, Date: x.EPSSDate}
		out.EPSSCitation = secexploit.EPSSCitation
	}
	return out
}

// securitySignals computes the signals of the dependency findings of fs,
// one secsignal.Compute per project (roots maps a project root hash to its
// root path; a project with none reads every tier unknown). It waits for a
// project's import list when nobody has built it yet: the finding drawer's
// read, one project.
func (s *Server) securitySignals(ctx context.Context, st *store.Store, fs []secfinding.Finding, evidence map[string]string, roots map[string]string) map[string]secsignal.Signal {
	return s.computeSecuritySignals(ctx, st, fs, evidence, roots, true)
}

// securityListSignals is securitySignals for the findings list, which never
// waits for a cold parse: a project whose import list nobody has built yet
// gets it built in the background, and its findings that needed it read
// the pending reason (securityReachPending), so the page asks again
// shortly instead of parsing twenty projects inline.
func (s *Server) securityListSignals(ctx context.Context, st *store.Store, fs []secfinding.Finding, evidence map[string]string, roots map[string]string) map[string]secsignal.Signal {
	return s.computeSecuritySignals(ctx, st, fs, evidence, roots, false)
}

// securityReachPending reports whether any signal's reach tier is pending
// (a list read that did not wait for a cold parse): the findings page
// answers reach_pending so the page refetches for the final labels.
func securityReachPending(sigs map[string]secsignal.Signal) bool {
	for _, sig := range sigs {
		if sig.Reach.Reason == secreach.ReasonPending {
			return true
		}
	}
	return false
}

// computeSecuritySignals is securitySignals (wait true) and
// securityListSignals (wait false).
func (s *Server) computeSecuritySignals(ctx context.Context, st *store.Store, fs []secfinding.Finding, evidence map[string]string, roots map[string]string, wait bool) map[string]secsignal.Signal {
	byProject := map[string][]secfinding.Finding{}
	var order []string
	for _, f := range fs {
		if f.Category != policy.FindingVulnerableDependency {
			continue
		}
		h := f.Project.RootHash
		if _, ok := byProject[h]; !ok {
			order = append(order, h)
		}
		byProject[h] = append(byProject[h], f)
	}
	out := map[string]secsignal.Signal{}
	if len(order) == 0 {
		return out
	}
	record, exploit := s.securityOSVLookup(), s.securityExploitLookup()
	secDir := s.securitySecurityDir()
	for _, h := range order {
		pctx, pending := ctx, func() bool { return false }
		if !wait {
			pctx, pending = secreachsvc.WithoutColdWait(ctx)
		}
		sigs := secsignal.Compute(pctx, secsignal.Inputs{
			Root: roots[h], Findings: byProject[h], Evidence: evidence, Record: record, Exploit: exploit,
			Reach:     []secreachsvc.Option{secreachsvc.WithCache(securityReachCache()), secreachsvc.WithCodeIntel(st), secreachsvc.PreferCodeIntel()},
			Symbol:    secreachsvc.LoadSymbolRuns(secDir, h),
			Sightings: st.SecFindingSightings,
		})
		// A list that did not wait for a cold parse decided some findings
		// without it: those read pending, not "no import data".
		cold := pending()
		for id, sig := range sigs {
			if cold && sig.Reach.Level == secreach.Unknown && securityPendingReasons[sig.Reach.Reason] {
				sig.Reach = secreach.UnknownTier(secreach.ReasonPending)
			}
			out[id] = sig
		}
	}
	return out
}

// applySecuritySignals sets each dependency row's reach and exploit labels.
func applySecuritySignals(rows []securityFindingJS, sigs map[string]secsignal.Signal) {
	for i := range rows {
		if sig, ok := sigs[rows[i].ID]; ok {
			rows[i].Reach, rows[i].Exploit = securityReachJSOf(sig.Reach), securityExploitJSOf(sig.Exploit)
		}
	}
}

// rankSecurityFindings orders fs (already worst severity first) by the
// ranking rule: the dependency findings reordered among their places by
// KEV, reach and EPSS (secrank), every other finding left where it is.
func rankSecurityFindings(fs []secfinding.Finding, sigs map[string]secsignal.Signal) []secfinding.Finding {
	return secrank.Apply(fs, func(f secfinding.Finding) secrank.Key {
		if f.Category != policy.FindingVulnerableDependency {
			return secrank.Key{}
		}
		if sig, ok := sigs[f.ID]; ok {
			return sig.Key()
		}
		return secrank.NoSignal()
	})
}

// securitySecurityDir is the node's security directory (the Go symbol
// checks' record lives under it, secreachsvc.SymbolPath), "" when the config
// path cannot be resolved.
func (s *Server) securitySecurityDir() string {
	resolved, err := config.ResolveGlobalPath(s.opts.ConfigPath)
	if err != nil {
		return ""
	}
	return secposture.LayoutFor(resolved).Dir
}

// securityRootsOf maps each project root hash to its root path.
func securityRootsOf(ctx context.Context, st *store.Store) map[string]string {
	index, err := securityProjectIndex(ctx, st)
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(index))
	for h, ref := range index {
		out[h] = ref.Root
	}
	return out
}
