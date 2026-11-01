package sectrustitem

import (
	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/sectrust"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// FromReasons returns the reasons that carry a digest as store items, in
// order: a reason in one of the developer's own files is in the
// project-local scope, any other in the project-shared scope.
func FromReasons(reasons []sectrust.Reason) []store.SecTrustItem {
	var out []store.SecTrustItem
	for _, r := range reasons {
		if r.Digest == "" {
			continue
		}
		scope := agentconfig.ScopeProjectShared
		if r.Local {
			scope = agentconfig.ScopeProjectLocal
		}
		out = append(out, store.SecTrustItem{
			ContentHash: r.Digest, Scope: string(scope), PathClass: string(r.Class),
			RelPath: r.File, ItemKey: r.Key, ReasonCode: r.Code,
		})
	}
	return out
}

// FromUserReasons returns the reasons of a user-scope check (the config
// baseline over the home directory's agent config) that carry a digest as
// store items, in order, all in the user scope; RelPath stays relative to
// the home directory.
func FromUserReasons(reasons []sectrust.Reason) []store.SecTrustItem {
	out := FromReasons(reasons)
	for i := range out {
		out[i].Scope = string(agentconfig.ScopeUser)
	}
	return out
}
