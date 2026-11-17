//go:build !sbo_omit_security

package dashboard

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// security_assess_fingerprint.go is the content-fingerprint stage of the
// boundary audit's git snapshot (review finding M3). The status line of a file
// that was already dirty does not change when it is edited again, so each
// entry that counts under the kind's policy also gets a short fingerprint of its
// content. The decisions (what to do with a path, the batches, the reading of
// the output) are the pure tables in internal/secassess/fingerprint.go; this
// file only examines files and runs `git hash-object --no-filters` through the
// same read-only seam as every other snapshot command. No new subprocess
// primitive, and nothing is written: hash-object without -w stores no object.

// securityAssessFingerprintBudget bounds the whole stage; the snapshot's own
// budget (securityAssessSnapshotBudget) covers the status and ref commands. An
// entry the stage did not reach keeps no fingerprint, which reads as not
// compared, never as unchanged.
const securityAssessFingerprintBudget = 6 * time.Second

// securityAssessRunGit runs one read-only git command for the stage.
type securityAssessRunGit func(args ...string) ([]byte, error)

// securityAssessFingerprint fills in the Fp of the entries that count under the
// policy. It never fails: whatever it cannot fingerprint is left empty.
func securityAssessFingerprint(ctx context.Context, root string, entries []secassess.TreeEntry, policy secassess.TreePolicy) {
	counted := 0
	for _, e := range entries {
		if policy.Counts(e) {
			counted++
		}
	}
	if counted == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, securityAssessFingerprintBudget)
	defer cancel()
	runIn := func(dir string) securityAssessRunGit {
		return func(args ...string) ([]byte, error) {
			out, _, err := gitview.RunReadOnlyTimeout(ctx, dir, securityAssessSmallMax, securityAssessGitTimeout, args...)
			return out, err
		}
	}
	// Status paths are relative to the repository's top level, which is not the
	// project root when the project is a folder inside a repository.
	topOut, err := runIn(root)("rev-parse", "--show-toplevel")
	top := strings.TrimSpace(string(topOut))
	if err != nil || top == "" {
		return
	}
	if fi, err := os.Stat(top); err != nil || !fi.IsDir() {
		return
	}
	run := runIn(top)
	var items []secassess.HashItem
	var owner []int // the entry index of each item
	for i := range entries {
		e := &entries[i]
		if !policy.Counts(*e) {
			continue
		}
		kind, size, target := securityAssessExamine(top, *e)
		switch secassess.FingerprintAction(*e, kind, size) {
		case secassess.FpSetAbsent:
			e.Fp = secassess.FpAbsent
		case secassess.FpSetLink:
			e.Fp = secassess.LinkFingerprint(target)
		case secassess.FpHash:
			items = append(items, secassess.HashItem{Path: e.Path, Size: size})
			owner = append(owner, i)
		case secassess.FpSkip:
		}
	}
	for _, batch := range secassess.PlanHashBatches(items) {
		paths := make([]string, len(batch))
		for j, idx := range batch {
			paths[j] = items[idx].Path
		}
		for j, fp := range securityAssessHashPaths(ctx, run, paths) {
			entries[owner[batch[j]]].Fp = fp
		}
	}
}

// securityAssessExamine looks at the path of one entry under the top level
// without following a link. For a link it also returns the target text.
func securityAssessExamine(top string, e secassess.TreeEntry) (kind secassess.FileKind, size int64, target string) {
	path := filepath.Join(top, filepath.FromSlash(e.Path))
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return secassess.FileAbsent, 0, ""
	case err != nil:
		return secassess.FileOther, 0, ""
	case fi.Mode()&os.ModeSymlink != 0:
		t, err := os.Readlink(path)
		if err != nil {
			return secassess.FileOther, 0, ""
		}
		return secassess.FileSymlink, 0, t
	case fi.Mode().IsRegular():
		return secassess.FileRegular, fi.Size(), ""
	}
	return secassess.FileOther, 0, ""
}

// securityAssessHashPaths hashes the paths (relative to the directory run works
// in) with one hash-object command and returns the fingerprints in order, "" for
// a path that was not hashed. When the command fails it halves the batch, so a
// single unreadable file costs only itself and not the whole batch. A git that
// is missing or refused, or an expired budget, stops the descent.
func securityAssessHashPaths(ctx context.Context, run securityAssessRunGit, paths []string) []string {
	fps := make([]string, len(paths))
	if len(paths) == 0 || ctx.Err() != nil {
		return fps
	}
	out, err := run(secassess.HashObjectArgs(paths)...)
	if err == nil {
		if got, ok := secassess.ParseHashOutput(out, len(paths)); ok {
			return got
		}
	}
	if len(paths) == 1 || errors.Is(err, gitview.ErrGitUnavailable) || errors.Is(err, gitview.ErrHostGitRefused) {
		return fps
	}
	mid := len(paths) / 2
	copy(fps, securityAssessHashPaths(ctx, run, paths[:mid]))
	copy(fps[mid:], securityAssessHashPaths(ctx, run, paths[mid:]))
	return fps
}

// securityAssessWholeRecords cuts out at its last NUL. When the status output
// hit its byte cap the final record may be a path cut in the middle, and a
// half-path must not be read as a path.
func securityAssessWholeRecords(out []byte) []byte {
	if i := bytes.LastIndexByte(out, 0); i >= 0 {
		return out[:i+1]
	}
	return nil
}
