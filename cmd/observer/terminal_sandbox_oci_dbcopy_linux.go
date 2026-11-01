//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// terminal_sandbox_oci_dbcopy_linux.go is the host read of the guest's
// db-copy one-shot (sandbox plan section 5.4, ledger SBX-BE-10; lane
// SBX-P3B). A projected state directory is guest-writable host space, so
// everything the guest left there is hostile input: the copies are reached
// through descriptors opened no-follow from the projection directory the
// host itself created (never through a path the guest could have turned
// into a link), only names the one-shot can produce are read, each must be
// a regular file under the size cap, and each copy is written fresh into a
// host-private directory and opened read-only with trusted_schema off and
// query_only on before it is kept. Nothing opens a guest-written store
// live.

// collectGuestDBCopies reads the copies under projDir/.observer-dbcopy into
// dest (created 0700) and returns the number kept. A copy that fails a rule
// is skipped and named in the returned error; the others are kept.
func collectGuestDBCopies(projDir, dest string) (int, error) {
	pfd, err := unix.Open(projDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("open the projected state dir: %w", err)
	}
	defer func() { _ = unix.Close(pfd) }()
	dfd, err := unix.Openat(pfd, sandboxoci.DBCopyDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open %s no-follow: %w", sandboxoci.DBCopyDirName, err)
	}
	defer func() { _ = unix.Close(dfd) }()
	raw, err := readAtNoFollow(dfd, sandbox.DBCopyManifestName, sandbox.DBCopyMaxManifest)
	if err != nil {
		return 0, fmt.Errorf("the db-copy manifest: %w", err)
	}
	var m sandbox.DBCopyManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0, fmt.Errorf("the db-copy manifest: %w", err)
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return 0, err
	}
	var errs []error
	kept := 0
	for i, e := range m.Files {
		if i >= sandbox.DBCopyMaxFiles {
			errs = append(errs, fmt.Errorf("more than %d copies listed; the rest were not read", sandbox.DBCopyMaxFiles))
			break
		}
		if !sandbox.ValidDBCopyName(e.Name) || e.Name != sandbox.DBCopyName(e.Rel) {
			errs = append(errs, fmt.Errorf("copy %q is not a name the one-shot makes", e.Name))
			continue
		}
		out := filepath.Join(dest, e.Name)
		if err := copyAtNoFollow(dfd, e.Name, out, sandbox.DBCopyMaxBytes); err != nil {
			errs = append(errs, fmt.Errorf("copy %s: %w", e.Name, err))
			continue
		}
		if err := checkGuestDBCopy(out); err != nil {
			_ = os.Remove(out)
			errs = append(errs, fmt.Errorf("copy %s: %w", e.Name, err))
			continue
		}
		kept++
	}
	return kept, errors.Join(errs...)
}

// readAtNoFollow reads one small regular file under dirfd, no-follow.
func readAtNoFollow(dirfd int, name string, limit int64) ([]byte, error) {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", name, limit)
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// copyAtNoFollow copies one regular file under dirfd (no-follow, at most
// limit bytes) to out, created fresh (0600, never over an existing path).
func copyAtNoFollow(dirfd int, name, out string, limit int64) error {
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	src := os.NewFile(uintptr(fd), name)
	defer func() { _ = src.Close() }()
	fi, err := src.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return fmt.Errorf("not a regular file of at most %d bytes", limit)
	}
	dst, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600) //nolint:gosec // G304: a fixed digest name in a host-private dir
	if err != nil {
		return err
	}
	n, err := io.Copy(dst, io.LimitReader(src, limit+1))
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("grew past %d bytes while it was copied", limit)
	}
	if err != nil {
		_ = os.Remove(out)
	}
	return err
}
