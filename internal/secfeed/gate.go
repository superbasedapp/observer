package secfeed

import (
	"context"
	"path/filepath"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// gate.go is the install gate's one entry function (security plan sections
// 5.4 and 8.3): for an event's installs (or a manifest edit's additions) it
// looks each package up in the offline index and the online-answer cache,
// asks the online check once, batched, for the public names the cache does
// not answer, and decides each through the verdict table. Every source is
// injected, so the hook (cache file, the daemon over local IPC) and the
// daemon (its own cache, the online client or the org relay) run the same
// decision.

// Classifier decides whether a name may be sent to a public source: true
// for a public-routable name, false for a private one (a private scope or
// registry), which is never sent and never called a near miss.
type Classifier func(spec InstallSpec) (public bool)

// CacheLookup returns a fresh cached online answer.
type CacheLookup func(eco Ecosystem, name, version string) (OnlineAnswer, bool)

// Asker asks the online check about public names and waits at most the
// install-gate budget (ctx carries it). It answers each spec it can; a
// spec it does not answer is online_unknown.
type Asker func(ctx context.Context, specs []InstallSpec) ([]OnlineAnswer, error)

// GateInput is one gate run.
type GateInput struct {
	Specs []InstallSpec
	// Public is the classifier. nil means nothing is known to be public:
	// every name is private, never asked about and never called a near
	// miss. A spec the command itself made Private (a registry or index
	// flag or variable on the command line, X4) is private whatever Public
	// says. The Asker's side classifies again with its own configuration
	// (the daemon answers a private name with OnlineAnswer.Private, never
	// sending it anywhere).
	Public         Classifier
	Index          *Index
	IndexFreshness content.Freshness
	Cache          CacheLookup
	// Ask is nil when online checks are off, not yet disclosed, or there
	// is nothing to ask (no daemon reachable is the Asker's error).
	Ask    Asker
	MinAge time.Duration
	Now    time.Time
}

// GateReasonDaemonDown and friends are the OnlineAnswer.Reason codes the
// gate itself writes.
const (
	GateReasonNoAnswer  = "no_answer"
	GateReasonAskFailed = "ask_failed"
)

// Gate decides every spec. The result is ordered like Specs and capped at
// policy.InstallChecksMax. When an event names more distinct packages than
// that, every one is still looked up in the offline index, the riskiest
// offline verdicts keep their slots, and the last slot is one
// too_many_packages check for the rest (S-744 or S-748, never silence).
func Gate(ctx context.Context, in GateInput) []policy.InstallCheck {
	specs, overflow := capSpecs(in.Specs, in.Index)
	type item struct {
		in   DecideInput
		need bool
	}
	items := make([]item, len(specs))
	var ask []InstallSpec
	for i, s := range specs {
		d := DecideInput{Spec: s, IndexFreshness: in.IndexFreshness, MinAge: in.MinAge, Now: in.Now, Online: OnlineAnswer{Status: OnlineNotAsked}}
		if !s.Invalid {
			d.Offline = in.Index.Lookup(s.Eco, s.Name, s.Version)
			d.Private = s.Private || in.Public == nil || !in.Public(s)
		}
		online := !s.Invalid && !d.Private
		items[i].in = d
		if !online || d.Offline.Malicious || d.Offline.Popular {
			continue
		}
		if in.Cache != nil {
			if a, ok := in.Cache(s.Eco, Normalize(s.Eco, s.Name), s.Version); ok {
				items[i].in.Online = a
				continue
			}
		}
		if in.Ask != nil {
			items[i].need = true
			ask = append(ask, s)
		}
	}
	if len(ask) > 0 {
		answers, err := in.Ask(ctx, ask)
		byKey := map[string]OnlineAnswer{}
		for _, a := range answers {
			byKey[answerKey(a.Eco, a.Name, a.Version)] = a
		}
		for i := range items {
			if !items[i].need {
				continue
			}
			s := items[i].in.Spec
			a, ok := byKey[answerKey(s.Eco, Normalize(s.Eco, s.Name), s.Version)]
			switch {
			case err != nil:
				a = OnlineAnswer{Eco: s.Eco, Name: s.Name, Status: OnlineFailed, Reason: GateReasonAskFailed}
			case !ok:
				// An answer must name the package asked about (JSP-11).
				a = OnlineAnswer{Eco: s.Eco, Name: s.Name, Status: OnlineFailed, Reason: GateReasonNoAnswer}
			}
			items[i].in.Online = a
		}
	}
	out := make([]policy.InstallCheck, 0, len(items)+1)
	for _, it := range items {
		out = append(out, Decide(it.in))
	}
	if overflow {
		out = append(out, tooManyCheck(in.Ask != nil))
	}
	return out
}

// capSpecs drops repeated specs and, when more than
// policy.InstallChecksMax remain, keeps InstallChecksMax-1 of them, the
// ones the offline index rates riskiest first (stable, so the event's order
// breaks ties), and reports the overflow.
func capSpecs(all []InstallSpec, ix *Index) ([]InstallSpec, bool) {
	if len(all) <= policy.InstallChecksMax {
		return all, false
	}
	seen := make(map[string]bool, len(all))
	specs := make([]InstallSpec, 0, len(all))
	for _, s := range all {
		k := answerKey(s.Eco, s.Name, s.Version)
		if s.Invalid {
			k = "!" + s.Spec
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		specs = append(specs, s)
	}
	if len(specs) <= policy.InstallChecksMax {
		return specs, false
	}
	rank := make(map[string]int, len(specs))
	for _, s := range specs {
		if s.Invalid {
			continue
		}
		a := ix.Lookup(s.Eco, s.Name, s.Version)
		switch {
		case a.Malicious:
			rank[answerKey(s.Eco, s.Name, s.Version)] = 3
		case a.ListedVersions:
			rank[answerKey(s.Eco, s.Name, s.Version)] = 2
		case a.NearMiss != "" && !s.Private:
			rank[answerKey(s.Eco, s.Name, s.Version)] = 1
		}
	}
	rankOf := func(s InstallSpec) int {
		if s.Invalid {
			return 0
		}
		return rank[answerKey(s.Eco, s.Name, s.Version)]
	}
	sort.SliceStable(specs, func(i, j int) bool { return rankOf(specs[i]) > rankOf(specs[j]) })
	return specs[:policy.InstallChecksMax-1], true
}

// tooManyCheck stands for the packages capSpecs left out: online_unknown
// (S-748) when online checks were on, else unknown (S-744). Each left-out
// name was still looked up offline and none ranked above the kept ones.
func tooManyCheck(online bool) policy.InstallCheck {
	c := policy.InstallCheck{Verdict: policy.InstallUnknownName, Source: policy.InstallSourceOffline, Reason: ReasonTooMany}
	if online {
		c.Verdict, c.Source = policy.InstallOnlineUnknown, policy.InstallSourceOnline
	}
	return c
}

// answerKey keys an answer by ecosystem, normalized name and version.
func answerKey(eco Ecosystem, name, version string) string {
	return string(eco) + "\x00" + Normalize(eco, name) + "\x00" + version
}

// EventSpecs returns what the gate checks for an event: the installs of a
// shell command, or the dependencies a manifest edit adds. manifest reports
// the second.
func EventSpecs(ev *policy.Event) (specs []InstallSpec, customRegistry, manifest bool) {
	if ev == nil {
		return nil, false, false
	}
	if ev.Kind == policy.KindShellExec {
		in := ParseInstalls(ev)
		return in.Specs, in.CustomRegistry, false
	}
	if ev.Kind != policy.KindFileAccess || len(ev.Edits) == 0 {
		return nil, false, false
	}
	if _, ok := IsManifest(filepath.ToSlash(ev.Target)); !ok {
		return nil, false, false
	}
	for _, e := range ev.Edits {
		specs = append(specs, ManifestAdditions(ev.Target, e.Old, e.New)...)
		if len(specs) >= MaxParsedInstallSpecs {
			specs = specs[:MaxParsedInstallSpecs]
			break
		}
	}
	return specs, false, true
}
