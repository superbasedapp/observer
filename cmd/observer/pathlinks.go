package main

import (
	"errors"
	"io/fs"
	"path/filepath"
)

// pathlinks.go holds the symlink resolver that both the isolation seam
// (isolation_wire.go) and the security module's Go reachability source run
// (security_reach_go_source.go) use. It carries no build tag: the resolver
// is plain path handling with no isolation dependency, so a build that omits
// the isolation component (sbo_omit_isolation) still has it.

// resolveThroughLinks returns p with every symlink resolved. A path that
// does not exist yet (an output directory created later) keeps its missing
// tail on the resolved deepest existing ancestor. Relative and empty paths
// are returned unchanged, for the planner to refuse.
func resolveThroughLinks(p string) (string, error) {
	if p == "" || !filepath.IsAbs(p) {
		return p, nil
	}
	p = filepath.Clean(p)
	real, err := filepath.EvalSymlinks(p)
	if err == nil {
		return real, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(p)
	if parent == p {
		return p, nil
	}
	rp, err := resolveThroughLinks(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(rp, filepath.Base(p)), nil
}
