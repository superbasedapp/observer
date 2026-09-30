package mcpaccess

import "sort"

// fastKey is the PDP index key.
type fastKey struct {
	VServer string
	Action  Action
	Name    string // "" = the any-name bucket
}

// FastIndex is the PDP fast-path index: (vserver, action, name) -> the
// candidate grants for that exact name plus the any-name bucket, each
// pre-sorted by precedence. A lookup filters the two buckets by subject
// class and floors and takes the strongest effect.
type FastIndex struct {
	registry Registry
	buckets  map[fastKey][]Grant
}

// CompileFastPath builds the index.
func CompileFastPath(spec Spec, now int64) (FastIndex, error) {
	n, err := Normalize(spec, now)
	if err != nil {
		return FastIndex{}, err
	}
	idx := FastIndex{registry: n.Registry, buckets: map[fastKey][]Grant{}}
	for _, g := range n.Grants {
		k := fastKey{VServer: g.Resource.VServer, Action: g.Action, Name: g.Resource.Name}
		idx.buckets[k] = append(idx.buckets[k], g)
	}
	for k := range idx.buckets {
		b := idx.buckets[k]
		sort.SliceStable(b, func(i, j int) bool { return precedenceLess(b[i], b[j]) })
	}
	return idx, nil
}

// Evaluate resolves one request from the two candidate buckets.
func (f FastIndex) Evaluate(in EvalInput) Decision {
	if ok, why := requireInvariantsHold(f.registry, in); !ok {
		return denyDecision(in, "invariant: "+why)
	}
	var best *Grant
	consider := func(gs []Grant) {
		for i := range gs {
			g := gs[i]
			if !subjectMatches(g, f.registry, in) || !conditionsHold(g, in.Principal) || !resourceMatches(g, f.registry, in) {
				continue
			}
			if best == nil || precedenceLess(g, *best) {
				c := g
				best = &c
			}
		}
	}
	consider(f.buckets[fastKey{VServer: in.VServer, Action: in.Action, Name: in.Name}])
	if in.Name != "" {
		consider(f.buckets[fastKey{VServer: in.VServer, Action: in.Action}])
	}
	if best == nil {
		return denyDecision(in, "fast path: no candidate (default-deny)")
	}
	return decisionFor(*best, "fast path: strongest candidate")
}

// Visible filters a catalogue (tools/list, resources/list ...) response for
// the principal: an entry is visible when the same principal's call/read of
// it would be allowed or asked (never a denied or unmatched one). action is
// the governed action the catalogue advertises (call for tools/list, read
// for resources/list); server is the backend target ("" = unknown).
func (f FastIndex) Visible(p Principal, vserver string, action Action, server string, names []string) []string {
	var out []string
	for _, n := range names {
		d := f.Evaluate(EvalInput{Principal: p, VServer: vserver, Action: action, Server: server, Name: n})
		if !d.Denied() {
			out = append(out, n)
		}
	}
	return out
}
