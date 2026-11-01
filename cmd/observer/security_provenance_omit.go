//go:build sbo_omit_security

package main

import (
	"context"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/commitscan"
)

// security_provenance_omit.go: a build without the security module has no
// change records; the commit scanner's per-commit seam stays nil.

func newProvenanceOnCommit(*slog.Logger) func(context.Context, commitscan.Root, commitlog.Commit) {
	return nil
}

// newProvenanceOnBoxCommit is nil: no box ref is walked without the
// security module.
func newProvenanceOnBoxCommit(*slog.Logger) func(context.Context, commitscan.Root, commitlog.Commit) bool {
	return nil
}

// provenanceRunning is false without the security module.
func provenanceRunning() bool { return false }

// provenanceAgentCommitAllowed is a no-op: no trailer marker without the
// security module.
func provenanceAgentCommitAllowed() {}
