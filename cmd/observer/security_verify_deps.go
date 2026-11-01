//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"errors"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secverify"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// verifyDependencyCheck loads a signed install index from dir (the content
// channel layout: the two kinds installed by `observer security index
// import` or copied from a node's ~/.observer/security/content) and returns
// the install_index detector's check over it. The index must verify
// against the vendor key compiled into this binary; an index past its age
// floor is refused, so a frozen index cannot pass a check.
func verifyDependencyCheck(dir string) (secverify.DependencyCheck, error) {
	store := contentchan.Store{Root: dir}
	ix, fresh := loadInstallIndex(store, depsTrust())
	if fresh == content.Unknown {
		return nil, errors.New("no usable malicious-packages list in the directory (missing, not signed by the vendor key, or past its age floor)")
	}
	return func(path, added string) ([]secverify.DependencyHit, bool) {
		if _, ok := secfeed.IsManifest(path); !ok {
			return nil, false
		}
		var hits []secverify.DependencyHit
		for _, s := range secfeed.ManifestAdditions(path, "", added) {
			c := secfeed.Decide(secfeed.DecideInput{Spec: s, Offline: ix.Lookup(s.Eco, s.Name, s.Version), IndexFreshness: fresh})
			switch c.Verdict {
			case policy.InstallMalicious, policy.InstallNearMiss:
				hits = append(hits, secverify.DependencyHit{Ecosystem: c.Ecosystem, Name: c.Name, Verdict: string(c.Verdict), NearMiss: c.NearMiss})
			}
		}
		return hits, true
	}, nil
}
