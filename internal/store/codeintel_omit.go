//go:build sbo_omit_codeintel

package store

import (
	"context"
	"errors"
)

// codeintel_omit.go stands in for codeintel.go in a build without the
// codeintel component (-tags sbo_omit_codeintel, lane MP-L1H, T-715): the
// index read/write surface and the resolve / semantic passes are not linked.
// The per-project delete and the retention prune stay (codeintelprune.go).
// These are the two derived-data passes an archive rehydrate asks for; they
// refuse, so a rehydrated project is reported as needing a re-index by a
// build that has the component.

var errCodeIntelNotInBuild = errors.New("store: codeintel is not in this build")

// CodeIntelResolveCalls refuses: the call resolver is not linked.
func (s *Store) CodeIntelResolveCalls(context.Context, string) (int, error) {
	return 0, errCodeIntelNotInBuild
}

// CodeIntelBuildDerived refuses: the semantic pass is not linked.
func (s *Store) CodeIntelBuildDerived(context.Context, string) error {
	return errCodeIntelNotInBuild
}

// CodeIntelProjectImports refuses: the codeintel index is not linked.
func (s *Store) CodeIntelProjectImports(context.Context, string, string, int) (CodeIntelImports, error) {
	return CodeIntelImports{}, errCodeIntelNotInBuild
}

// CodeIntelProjectCalls refuses: the codeintel index is not linked.
func (s *Store) CodeIntelProjectCalls(context.Context, string, string, []string, int) (CodeIntelCalls, error) {
	return CodeIntelCalls{}, errCodeIntelNotInBuild
}
