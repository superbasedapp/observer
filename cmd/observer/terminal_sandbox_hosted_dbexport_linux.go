//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// terminal_sandbox_hosted_dbexport_linux.go is the hosted rows' in-box
// database export (lane LEFT-SBX, ledger SBX-BE-10 amendment): at teardown,
// before the box is deleted, the guest db-copy one-shot (`observer
// sandbox-guest db-copy`, the same verb the oci-runsc init runs) makes a
// consistent copy of every SQLite store under the tool's state directories
// in the box, with the store's own locks, and the host pulls only the
// copies: names the one-shot makes, a SQLite header on each, at most
// sandbox.DBCopyMaxFiles files of at most sandbox.DBCopyMaxBytes each and
// hostedDBExportMaxTotal in all, written fresh and owner-only into a
// host-private directory and kept only after a read-only quick_check with
// trusted_schema off. The box is hostile: nothing is read from it but the
// manifest and the copies by their expected names, nothing written home
// follows a link, and a store that fails a rule is skipped and named.

// hostedDBExportMaxTotal caps all the copies one run brings home.
const hostedDBExportMaxTotal = 1 << 30

// hostedDBExportDir is where a run's copies are kept on the host.
func hostedDBExportDir(observerDir, runID string) string {
	return filepath.Join(hostedStateDir(observerDir), "dbcopies", runID)
}

// hostedSweepDBExports removes the exported copies of earlier hosted runs
// (dbcopies/<run>) whose newest write is older than the workspace retention
// in days (ruling P-141; 0 keeps them, like the workspaces). The current
// run's copies are never swept, a symlinked entry is skipped and nothing is
// followed. It returns how many runs' copies it removed.
func hostedSweepDBExports(observerDir, currentRun string, now time.Time, retentionDays int) (int, error) {
	if retentionDays <= 0 || observerDir == "" {
		return 0, nil
	}
	root := filepath.Join(hostedStateDir(observerDir), "dbcopies")
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	horizon := now.Add(-time.Duration(retentionDays) * 24 * time.Hour)
	n := 0
	var errs []error
	for _, e := range entries {
		if e.Name() == currentRun || !e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
			continue
		}
		dir := filepath.Join(root, e.Name())
		var newest time.Time
		_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if fi, ierr := d.Info(); ierr == nil && fi.ModTime().After(newest) {
				newest = fi.ModTime()
			}
			return nil
		})
		if newest.After(horizon) {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

// hostedDBExportRoots are the box paths of the tool's state directories
// (the registry's StateRW rows under the box's home), each with the
// one-shot's output directory under the run's own box directory.
func hostedDBExportRoots(tool string, layout sandboxremote.BoxLayout) [][2]string {
	spec, _ := integration.For(tool)
	var out [][2]string
	for i, rel := range spec.Sandbox.StateRW {
		out = append(out, [2]string{path.Join(layout.Home, rel), path.Join(layout.RunDir, "dbcopy-"+strconv.Itoa(i))})
	}
	return out
}

// exportBoxDatabases runs the export (see the file comment) and says on the
// terminal how many stores came home and what was skipped. It never fails
// the teardown.
func (r *hostedRun) exportBoxDatabases(ctx context.Context) {
	dest := hostedDBExportDir(r.plan.ObserverDir, r.plan.RunID)
	kept, total := 0, int64(0)
	var errs []error
	for i, rt := range hostedDBExportRoots(r.plan.Tool, r.layout) {
		_, code, err := hostedExecOutputIn(ctx, r.client, r.rec.VendorID, sandboxremote.ExecSpec{
			Argv: sandbox.DBCopyArgv(r.layout.Binary, rt[0], rt[1]), Env: r.boxEnv(),
		}, 64<<10)
		if err != nil || code != 0 {
			continue // no such directory in the box, or nothing it could copy
		}
		n, size, err := hostedPullDBCopies(ctx, r.client, r.rec.VendorID, rt[1], filepath.Join(dest, strconv.Itoa(i)), hostedDBExportMaxTotal-total)
		kept += n
		total += size
		if err != nil {
			errs = append(errs, err)
		}
	}
	switch {
	case kept > 0 && len(errs) == 0:
		r.say("%d SQLite store(s) of the box were copied home to %s", kept, dest)
	case kept > 0 || len(errs) > 0:
		r.say("%d SQLite store(s) of the box were copied home to %s; skipped: %v", kept, dest, errors.Join(errs...))
	}
}

// hostedPullDBCopies reads one db-copy output directory from the box into
// dest: the manifest, then each listed copy by the name the one-shot makes,
// header-checked, capped, written fresh owner-only, kept after
// checkGuestDBCopy. budget is what the run may still bring home. It returns
// the number kept and their size.
func hostedPullDBCopies(ctx context.Context, c sandboxremote.Client, boxID, boxOut, dest string, budget int64) (int, int64, error) {
	raw, err := c.ReadFile(ctx, boxID, path.Join(boxOut, sandbox.DBCopyManifestName), sandbox.DBCopyMaxManifest)
	if err != nil {
		return 0, 0, nil // the one-shot found nothing to copy
	}
	m, err := sandbox.ParseDBCopyManifest(raw)
	if err != nil {
		return 0, 0, fmt.Errorf("the db-copy manifest of %s: %w", boxOut, err)
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return 0, 0, err
	}
	var errs []error
	kept, size := 0, int64(0)
	for i, e := range m.Files {
		if i >= sandbox.DBCopyMaxFiles {
			errs = append(errs, fmt.Errorf("more than %d copies listed; the rest were not read", sandbox.DBCopyMaxFiles))
			break
		}
		if !sandbox.ValidDBCopyName(e.Name) || e.Name != sandbox.DBCopyName(e.Rel) {
			errs = append(errs, fmt.Errorf("copy %q is not a name the one-shot makes", e.Name))
			continue
		}
		limit := int64(sandbox.DBCopyMaxBytes)
		if budget-size < limit {
			limit = budget - size
		}
		if limit <= 0 {
			errs = append(errs, fmt.Errorf("the export cap of %d bytes is reached; %s and the rest were not read", hostedDBExportMaxTotal, e.Name))
			break
		}
		b, err := c.ReadFile(ctx, boxID, path.Join(boxOut, e.Name), limit)
		if err != nil {
			errs = append(errs, fmt.Errorf("copy %s: %w", e.Name, err))
			continue
		}
		if int64(len(b)) > limit || !bytes.HasPrefix(b, []byte(sandbox.SQLiteHeader)) {
			errs = append(errs, fmt.Errorf("copy %s is not a SQLite file under the cap", e.Name))
			continue
		}
		out := filepath.Join(dest, e.Name)
		if err := hostedWriteFresh(out, b); err != nil {
			errs = append(errs, fmt.Errorf("copy %s: %w", e.Name, err))
			continue
		}
		if err := checkGuestDBCopy(out); err != nil {
			_ = os.Remove(out)
			errs = append(errs, fmt.Errorf("copy %s: %w", e.Name, err))
			continue
		}
		kept++
		size += int64(len(b))
	}
	return kept, size, errors.Join(errs...)
}

// hostedWriteFresh writes b to a path that must not exist (O_EXCL, no
// link followed), owner-only.
func hostedWriteFresh(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: a fixed digest name in a host-private dir
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(p)
	}
	return werr
}
