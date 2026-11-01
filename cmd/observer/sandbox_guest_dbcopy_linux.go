//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// sandbox_guest_dbcopy_linux.go is the guest helper's db-copy one-shot
// (sandbox plan section 5.4, ledger SBX-BE-10; lane SBX-P3B): `observer
// sandbox-guest db-copy --root <dir> --out <dir>` runs INSIDE the box,
// where a tool's SQLite store keeps its own locks, and makes a consistent
// copy of every SQLite file under --root with VACUUM INTO, through the
// observer binary's own pure-Go SQLite. The oci-runsc init runs it for each
// projected state directory when the agent has exited, so the host never
// opens a guest-written store live; it reads only the copies
// (collectGuestDBCopies).

// runGuestDBCopy is the one-shot's entry.
func runGuestDBCopy(args []string) int {
	req, ok := sandbox.ParseDBCopyArgs(args)
	if !ok {
		return helperFail("observer sandbox-guest %s: usage: %s %s <dir> %s <dir> (absolute, different, --out not above --root)",
			sandbox.GuestDBCopy, sandbox.GuestDBCopy, sandbox.DBCopyRootFlag, sandbox.DBCopyOutFlag)
	}
	n, err := guestDBCopy(req)
	if err != nil {
		return helperFail("observer sandbox-guest %s: %v", sandbox.GuestDBCopy, err)
	}
	fmt.Fprintf(os.Stderr, "observer sandbox-guest %s: %d SQLite store(s) copied\n", sandbox.GuestDBCopy, n)
	return 0
}

// guestDBCopy walks req.Root without following a link (and never into
// req.Out), copies each SQLite file it finds (by its header, up to the
// one-shot's bounds) into req.Out with VACUUM INTO, and writes the
// manifest. A store that cannot be copied is skipped; the others still are.
func guestDBCopy(req sandbox.DBCopyRequest) (int, error) {
	if err := os.MkdirAll(req.Out, 0o700); err != nil {
		return 0, err
	}
	var found []string
	root := filepath.Clean(req.Root)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if p == root {
				return werr
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		if d.IsDir() {
			if p == filepath.Clean(req.Out) || strings.Count(rel, string(filepath.Separator)) >= sandbox.DBCopyMaxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || len(found) >= sandbox.DBCopyMaxFiles {
			return nil
		}
		if guestIsSQLite(p) {
			found = append(found, rel)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	var m sandbox.DBCopyManifest
	for _, rel := range found {
		name := sandbox.DBCopyName(filepath.ToSlash(rel))
		dst := filepath.Join(req.Out, name)
		if err := os.Remove(dst); err != nil && !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := vacuumInto(filepath.Join(root, rel), dst); err != nil {
			_ = os.Remove(dst)
			continue
		}
		m.Files = append(m.Files, sandbox.DBCopyEntry{Rel: filepath.ToSlash(rel), Name: name})
	}
	b, err := json.Marshal(m)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(req.Out, sandbox.DBCopyManifestName), b, 0o600); err != nil {
		return 0, err
	}
	return len(m.Files), nil
}

// guestIsSQLite reports whether p is a regular file no larger than the
// one-shot's cap that starts with the SQLite header.
func guestIsSQLite(p string) bool {
	f, err := os.Open(p) //nolint:gosec // G304: a file the walk found under the projected state dir, inside the box
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > sandbox.DBCopyMaxBytes {
		return false
	}
	head := make([]byte, len(sandbox.SQLiteHeader))
	if _, err := io.ReadFull(f, head); err != nil {
		return false
	}
	return bytes.Equal(head, []byte(sandbox.SQLiteHeader))
}

// vacuumInto copies the store src into dst with VACUUM INTO over a
// read-only connection (SQLite allows VACUUM INTO on a read-only
// database): the copy is a single consistent snapshot taken under the
// store's own locks.
func vacuumInto(src, dst string) error {
	db, err := sql.Open("sqlite", "file:"+src+"?mode=ro")
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	_, err = db.Exec("VACUUM INTO ?", dst)
	return err
}
