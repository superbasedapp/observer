//go:build !sbo_omit_security

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// securityKnownProjectRoot resolves dir to a project the store knows and its
// checkout (the actionlint and IaC verbs share it, so it lives outside the
// actionlint file: a build that omits actionlint still has the IaC verbs).
func securityKnownProjectRoot(ctx context.Context, st *store.Store, dir string) (string, string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	root, ok := git.FindRoot(abs)
	if !ok {
		return "", "", fmt.Errorf("%s is not inside a git repository", abs)
	}
	checkout, ok := git.FindCheckoutRoot(abs)
	if !ok || checkout == "" {
		checkout = root
	}
	roots, err := st.ProjectRoots(ctx)
	if err != nil {
		return "", "", err
	}
	if !slices.Contains(roots, root) {
		return "", "", fmt.Errorf("%s is not a project Observer knows (open it with an AI tool Observer watches first)", root)
	}
	return root, checkout, nil
}
