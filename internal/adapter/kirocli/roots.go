package kirocli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// allHomesFunc is the test seam over crossmount.AllHomes — tests
// override it to assert foreign-mount detection without depending on
// the host's filesystem layout. Same shape as clinecli.allHomesFunc.
var allHomesFunc = crossmount.AllHomes

// sessionsSubpath is the PARENT session directory shared by BOTH
// file-backed layouts, identical on every OS (Windows uses
// C:\Users\<u>\.kiro\sessions — NOT %LOCALAPPDATA%):
//
//	<home>/.kiro/sessions/cli/<uuid>.{json,jsonl}          CLI flat bundle
//	<home>/.kiro/sessions/<bucket>/<sid>/messages.jsonl    Kiro IDE
//
// Watching the PARENT (not `.../sessions/cli`) is what brings the IDE
// subtree in: adapter.UnderAnyWatchRoot is a path-PREFIX test, so the
// flat bundles keep matching unchanged, and one root avoids the nested
// duplicate-watch a `cli` + `sessions` pair would create.
var sessionsSubpath = filepath.Join(".kiro", "sessions")

// defaultRoots returns the two watch roots per cross-mount-resolved
// home: the session dir (`<home>/.kiro/sessions`, identical on every
// OS, covering both the CLI flat bundles and the Kiro IDE subtree) and
// the SQLite data dir, whose location is OS-shaped:
//
//	linux/darwin home → <home>/.local/share/kiro-cli
//	windows home      → <home>/AppData/Local/Kiro-Cli
//
// The OS is the LOGICAL OS of the home (crossmount.HomeRoot.OS), not
// runtime.GOOS — so a WSL2 observer reaches a Windows-side store at
// /mnt/c/Users/<u>/AppData/Local/Kiro-Cli and a Windows observer
// reaches a WSL store at \\wsl.localhost\<distro>\home\<u>\.local\share
// \kiro-cli.
func defaultRoots() []string {
	var roots []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}

	for _, h := range allHomesFunc() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(h.Path, sessionsSubpath))
		add(filepath.Join(append([]string{h.Path}, sqliteDataSubdir(h.OS)...)...))
	}
	return roots
}

// sqliteDataSubdir returns the path segments of the kiro-cli SQLite
// data directory for a home following the given logical OS.
func sqliteDataSubdir(homeOS string) []string {
	if homeOS == crossmount.OSWindows {
		return []string{"AppData", "Local", "Kiro-Cli"}
	}
	return []string{".local", "share", "kiro-cli"}
}

// stageMirrorIfForeign returns srcDB unchanged when it's native. For a
// foreign-mount source (e.g. /mnt/c/Users/<u>/AppData/Local/Kiro-Cli/
// data.sqlite3 read by a WSL2 observer) it stages a local mirror —
// copying the SQLite trio (.db + -wal + -shm) into a per-source cache
// dir and returning the mirrored .db path. modernc.org/sqlite hits
// SQLITE_IOERR against /mnt/c paths while the Kiro process holds the
// WAL open; the mirror avoids the DrvFs bridge by reading bytes once
// via os.ReadFile (which DOES work) then opening the in-tmp copy. Same
// pattern clinecli / opencode adopt. Native paths pass through with no
// overhead.
func stageMirrorIfForeign(srcDB string) (string, error) {
	if !isForeignMountPath(srcDB) {
		return srcDB, nil
	}
	base, err := mirrorbase.Base()
	if err != nil || base == "" {
		base = filepath.Join(os.TempDir(), "superbased-observer")
	}
	sum := sha256.Sum256([]byte(srcDB))
	mirrorDir := filepath.Join(base, "kirocli-mirror", hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(mirrorDir, 0o700); err != nil {
		return "", fmt.Errorf("kirocli.stageMirror: mkdir %s: %w", mirrorDir, err)
	}
	dstDB := filepath.Join(mirrorDir, "data.sqlite3")
	if mirrorUpToDate(srcDB, dstDB) {
		return dstDB, nil
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src := srcDB + suffix
		dst := dstDB + suffix
		data, err := os.ReadFile(src) //nolint:gosec // src derives from validated watch roots
		if err != nil {
			if os.IsNotExist(err) {
				_ = os.Remove(dst)
				continue
			}
			return "", fmt.Errorf("kirocli.stageMirror: read %s: %w", src, err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return "", fmt.Errorf("kirocli.stageMirror: write %s: %w", dst, err)
		}
	}
	return dstDB, nil
}

// mirrorUpToDate reports whether the mirror trio is at least as fresh
// as the source. Uses (size, mtime) per sibling; the size guard catches
// an in-flight truncate/realloc that mtime alone misses. Returns false
// on any stat error so a fresh copy gets attempted.
func mirrorUpToDate(srcDB, dstDB string) bool {
	if !filesMatch(srcDB, dstDB) {
		return false
	}
	if sw, err := os.Stat(srcDB + "-wal"); err == nil {
		if !filesMatchInfo(sw, dstDB+"-wal") {
			return false
		}
	}
	return true
}

func filesMatch(src, dst string) bool {
	s, err := os.Stat(src)
	if err != nil {
		return false
	}
	return filesMatchInfo(s, dst)
}

func filesMatchInfo(srcInfo os.FileInfo, dst string) bool {
	d, err := os.Stat(dst)
	if err != nil {
		return false
	}
	if srcInfo.Size() != d.Size() {
		return false
	}
	return !srcInfo.ModTime().After(d.ModTime())
}

// isForeignMountPath reports whether path lives under a crossmount-
// detected non-native home. Both bridge directions are covered.
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" {
			continue
		}
		sep := string(filepath.Separator)
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}
