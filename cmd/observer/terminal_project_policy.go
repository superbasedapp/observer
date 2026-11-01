package main

import (
	"context"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// terminal_project_policy.go is the cmd-side seam behind the New Terminal
// dialog's "project policy" line (security plan section 7.11 hard case "New
// Terminal shows project policy: not matched", lane sec-p2b). It READS the
// daemon's match record for the directory's identity root (P1's core match
// file, written by project_audience.go) and, with no current record, matches
// the directory's own identity hashes against the org-signed mapping:
// projectmatch.Decide, the same decision the guard's project layer makes.
// File reads only (no git exec); it writes nothing.

// projectPolicyStateLine maps projectmatch's decision states onto the line.
var projectPolicyStateLine = map[string]dashapi.ProjectPolicyLine{
	projectmatch.StateMatched:   {Shown: true, State: dashapi.ProjectPolicyMatched},
	projectmatch.StateUnmatched: {Shown: true, State: dashapi.ProjectPolicyNotMatched},
	projectmatch.StateUnknown:   {Shown: true, State: dashapi.ProjectPolicyUnknown},
	// StateNone (no project delivery held) is absent: shown=false.
}

// terminalProjectPolicySeam returns the dashboard's ProjectPolicy seam for
// this node (nil without an org bundle cache path: nothing to read).
func terminalProjectPolicySeam(cfg config.Config, st *store.Store) func(dir string) dashapi.ProjectPolicyLine {
	bundlePath := orgBundleCachePath(cfg)
	if bundlePath == "" {
		return nil
	}
	return func(dir string) dashapi.ProjectPolicyLine {
		return projectPolicyLineFor(context.Background(), bundlePath, st, dir, time.Now())
	}
}

// projectPolicyLineFor decides the line for dir at now.
func projectPolicyLineFor(ctx context.Context, bundlePath string, st *store.Store, dir string, now time.Time) dashapi.ProjectPolicyLine {
	pb, version := composedProjectBinding(bundlePath)
	if pb == nil {
		return dashapi.ProjectPolicyLine{}
	}
	layout := projectmatch.LayoutFor(bundlePath)
	sig, sigErr := projectmatch.SignalsFor(dir, "")
	if sigErr == nil && st != nil && sig.Root != "" {
		if sha, err := st.CachedRootCommit(ctx, sig.Root); err == nil && sha != "" {
			sig.RootCommitHash = projectmatch.Hash(sha)
		}
	}
	in := projectmatch.DecideInput{
		Composed: pb, ComposedVersion: version, Now: now,
		LoadMapping: func() *projectmatch.MappingFile {
			raw, err := os.ReadFile(layout.MappingPath())
			if err != nil {
				return nil
			}
			mf, derr := projectmatch.DecodeMappingFile(raw)
			if derr != nil {
				return nil
			}
			return &mf
		},
		Signals: func() (projectmatch.Signals, error) { return sig, sigErr },
	}
	if sigErr == nil && sig.Root != "" {
		if raw, err := os.ReadFile(layout.MatchPath(projectmatch.RootHash(sig.Root))); err == nil {
			if rec, derr := projectmatch.DecodeMatchFile(raw); derr == nil {
				in.Record = &rec
			}
		}
	}
	dec := projectmatch.Decide(in)
	line, ok := projectPolicyStateLine[dec.State]
	if !ok {
		return dashapi.ProjectPolicyLine{}
	}
	if dec.State == projectmatch.StateMatched {
		line.Projects = len(dec.IDs)
	}
	return line
}
