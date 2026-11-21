//go:build !sbo_omit_security

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
	"github.com/marmutapp/superbased-observer/internal/secdepdetail/projectfs"
	"github.com/marmutapp/superbased-observer/internal/secexplain"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_feedback_fix.go is the suggest-a-fix half of the explain flow
// (`observer security explain <id> --fix`, os-and-ci plan section 14.8): the
// rule's fix hint and, for a dependency finding, the package, the installed
// version and the smallest fixed version, composed at view time from the
// lockfile and the node's LOCAL OSV database (internal/secdepdetail). Only
// versions and the rule's own template reach the prompt; advisory prose is
// never read into it. The call itself, its caps, the advisory label and the
// JUDGE-1 routing are explainSecurityFindingWith's, unchanged.

// securityFixContextFunc builds the suggest-a-fix rule data of finding f
// (evidence is its redacted evidence).
type securityFixContextFunc func(ctx context.Context, f secfinding.Finding, evidence string) secexplain.FixContext

// securityProjectRoots is the read-only store surface the fix context needs:
// the projects a finding's root hash can name.
type securityProjectRoots interface {
	SecProjectRefs(ctx context.Context) ([]store.SecProjectRef, error)
}

// securityFixContextFor returns the fix-context builder over the store and
// the injected local OSV record read (securityLocalOSVLookup). A finding
// whose project is no longer known, or whose lockfile cannot be read, still
// gets its hint and the package and version from the evidence; the fixed
// version is then simply absent (the prompt says none is known).
func securityFixContextFor(roots securityProjectRoots, lookup func(eco, id string) ([]byte, error)) securityFixContextFunc {
	return func(ctx context.Context, f secfinding.Finding, evidence string) secexplain.FixContext {
		fx := secexplain.FixContext{FixHint: f.FixHint}
		in := secdepdetail.Input{
			Category: string(f.Category), Evidence: evidence, RuleID: f.Rule.ID, Message: f.Message,
			RelPath: f.Location.RelPath, LookupRecord: lookup,
		}
		if root := securityProjectRootOf(ctx, roots, f.Project.RootHash); root != "" {
			in.ReadFile = func(rel string) ([]byte, error) { return projectfs.Read(root, rel, projectfs.MaxLockfileBytes) }
		}
		if d, ok := secdepdetail.Build(in); ok {
			fx.Package, fx.Version, fx.FixedVersion = d.Name, d.Version, d.SuggestedVersion
		}
		return fx
	}
}

// securityProjectRootOf resolves a finding's project root hash to the
// project's root path ("" when unknown).
func securityProjectRootOf(ctx context.Context, roots securityProjectRoots, hash string) string {
	if roots == nil || hash == "" {
		return ""
	}
	refs, err := roots.SecProjectRefs(ctx)
	if err != nil {
		return ""
	}
	for _, r := range refs {
		if secposture.ProjectRootHash(r.Root) == hash {
			return r.Root
		}
	}
	return ""
}
