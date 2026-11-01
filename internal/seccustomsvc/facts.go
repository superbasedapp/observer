//go:build !sbo_omit_security

package seccustomsvc

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/seccustom"
)

// goos is the host OS (a var so a test can pin it).
var goos = func() string { return runtime.GOOS }

// ioReadFull is io.ReadFull.
var ioReadFull = io.ReadFull

// pathElems reads every element of p, the file first, then each parent up
// to the root, with Lstat (never following a link).
func pathElems(p string) []seccustom.PathElem {
	var out []seccustom.PathElem
	cur := filepath.Clean(p)
	for {
		e := seccustom.PathElem{Path: cur}
		if fi, err := os.Lstat(cur); err == nil {
			m := fi.Mode()
			e.Exists = true
			e.Symlink = m&os.ModeSymlink != 0
			e.Dir = m.IsDir()
			e.Regular = m.IsRegular()
			e.Perm = uint32(m.Perm())
			e.Sticky = m&os.ModeSticky != 0
		}
		out = append(out, e)
		next := filepath.Dir(cur)
		if next == cur {
			return out
		}
		cur = next
	}
}

// checkExecutable runs the pure executable table over p's elements.
func checkExecutable(p string) seccustom.ExecCheck {
	return seccustom.CheckExecutable(goos(), pathElems(p))
}

// hashFile returns the lowercase hex sha256 of the file at p.
func hashFile(p string) (string, error) {
	f, err := os.Open(p) //nolint:gosec // G304: an executable path the import discovered and checked
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readHead returns the first bytes of the file at p (for its "#!" line).
func readHead(p string) []byte {
	f, err := os.Open(p) //nolint:gosec // G304: an executable path the import discovered and checked
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, 256)
	n, _ := io.ReadFull(f, b)
	return b[:n]
}

// realPath returns p with every symlink resolved, or p when it cannot be.
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// checkInterpreter runs the pure interpreter table over the executable at
// p and its companions (nil: none declared yet).
func checkInterpreter(p string, companions []seccustom.Companion) seccustom.Interpreter {
	return seccustom.CheckInterpreter(readHead(p), realPath, readHead, companions)
}

// goBuildVersion is the Go release the executable at p was built with
// ("go1.27.2"), or "" when it is not a Go program or cannot be read.
func goBuildVersion(p string) string {
	bi, err := buildinfo.ReadFile(p)
	if err != nil {
		return ""
	}
	return bi.GoVersion
}
