package secimage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// DirDigest is a directory input's image identity: "dir:" and the sha256
// of its absolute path (a directory has no manifest, and its path is the
// only stable name the developer gives it).
func DirDigest(abs string) string {
	s := sha256.Sum256([]byte(abs))
	return "dir:" + hex.EncodeToString(s[:])
}

// ReadRoot reads the allow-list from a root filesystem directory (a
// `docker export` unpacked by the developer, a CI job's build output) into
// dst: no flattening, no whiteouts. src must implement fs.ReadLinkFS
// (os.Root.FS and os.DirFS do): every path and each of its parent
// directories is checked with Lstat, and a symlink is never followed. A
// file under a symlinked directory is not read (its real path is read when
// it is on the allow-list); a package database that is itself a link is
// reported in Result.RefusedWanted. Result.Digest is left to the caller
// (DirDigest).
func ReadRoot(src fs.FS, dst Sink, lim Limits) (Result, error) {
	res := Result{Format: "dir", Compression: map[string]int{}}
	lfs, ok := src.(fs.ReadLinkFS)
	if !ok {
		return res, refuse(ReasonNotADirectory, "the directory reader needs Lstat")
	}
	if fi, err := lfs.Lstat("."); err != nil || !fi.IsDir() {
		return res, refuse(ReasonNotADirectory, "the root is not a directory")
	}
	var candidates []string
	for p := range wantExact {
		candidates = append(candidates, p)
	}
	for _, d := range rpmDirs {
		for n := range rpmNames {
			candidates = append(candidates, d+"/"+n)
		}
	}
	for _, d := range wantDirAny {
		if !realDir(lfs, d) {
			continue
		}
		entries, err := fs.ReadDir(src, d)
		if err != nil {
			continue
		}
		if lim.MaxEntries > 0 && len(entries) > lim.MaxEntries {
			return res, refuse(ReasonCapExceeded, "%s holds %d entries, cap %d", d, len(entries), lim.MaxEntries)
		}
		for _, e := range entries {
			candidates = append(candidates, d+"/"+e.Name())
		}
	}
	sort.Strings(candidates)
	have := map[string]bool{}
	refused := map[string]bool{}
	var written int64
	for _, p := range candidates {
		if !Wanted(p) || (lim.MaxPathLen > 0 && len(p) > lim.MaxPathLen) {
			continue
		}
		res.EntriesWalked++
		if !realDir(lfs, path.Dir(p)) {
			continue
		}
		fi, err := lfs.Lstat(p)
		if err != nil {
			continue
		}
		if !fi.Mode().IsRegular() {
			if isPackageDB(p) {
				refused[p] = true
			}
			continue
		}
		size := fi.Size()
		if lim.MaxEntryBytes > 0 && size > lim.MaxEntryBytes {
			return res, refuse(ReasonCapExceeded, "%s is %d bytes, cap %d", p, size, lim.MaxEntryBytes)
		}
		if lim.MaxOutputBytes > 0 && written+size > lim.MaxOutputBytes {
			return res, refuse(ReasonCapExceeded, "extracted files passed %d bytes", lim.MaxOutputBytes)
		}
		n, err := copyFromFS(src, p, dst, size)
		if err != nil {
			return res, err
		}
		written += n
		have[p] = true
	}
	if err := finishOSRelease(dst, have, &res); err != nil {
		return res, err
	}
	for k := range have {
		res.Files = append(res.Files, k)
	}
	sort.Strings(res.Files)
	for k := range refused {
		res.RefusedWanted = append(res.RefusedWanted, k)
	}
	sort.Strings(res.RefusedWanted)
	return res, nil
}

// realDir reports whether dir and each of its parents is a directory, not
// a link to one.
func realDir(lfs fs.ReadLinkFS, dir string) bool {
	if dir == "." || dir == "" {
		return true
	}
	cur := ""
	for _, seg := range strings.Split(dir, "/") {
		cur = path.Join(cur, seg)
		fi, err := lfs.Lstat(cur)
		if err != nil || !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 {
			return false
		}
	}
	return true
}

// copyFromFS copies one regular file of at most size bytes (it may have
// shrunk since Lstat; a file that grew is cut at size and refused).
func copyFromFS(src fs.FS, p string, dst Sink, size int64) (int64, error) {
	f, err := src.Open(p)
	if err != nil {
		return 0, refuse(ReasonOutputFailed, "%s: %v", p, err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return 0, refuse(ReasonOutputFailed, "%s changed while it was read", p)
	}
	w, err := dst.Create(p)
	if err != nil {
		return 0, refuse(ReasonOutputFailed, "%s: %v", p, err)
	}
	n, err := io.Copy(w, io.LimitReader(f, size+1))
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return n, refuse(ReasonOutputFailed, "%s: %v", p, err)
	}
	if n > size {
		return n, refuse(ReasonCapExceeded, "%s grew while it was read", p)
	}
	return n, nil
}
