//go:build sbo_omit_codeintel

package store

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/codequality"
)

// LoadCodeQualityDuplication stands in for codequality_dup.go in a build
// without the codeintel component (-tags sbo_omit_codeintel): the index is
// not read, and the duplication figure reports codequality.StateNotInBuild.
func (s *Store) LoadCodeQualityDuplication(context.Context, []string) (codequality.DuplicationInput, error) {
	return codequality.DuplicationInput{Index: codequality.IndexFacts{NotInBuild: true}}, nil
}

// LoadCodeQualityComplexity stands in for codequality_cx.go in a build
// without the codeintel component: the index is not read, and the
// complexity figure reports codequality.StateNotInBuild.
func (s *Store) LoadCodeQualityComplexity(context.Context, []string) (codequality.ComplexityInput, error) {
	return codequality.ComplexityInput{Index: codequality.IndexFacts{NotInBuild: true}}, nil
}
