package stakpak

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Stakpak's local store records no version (verified on 0.3.88: neither
// sessions nor checkpoints carry one, and ~/.stakpak holds only config,
// cache and the store). The one place the running build names itself is the
// installed binary, whose `--version` banner is compiled in as
// "stakpak v<semver> (https://github.com/stakpak/agent)". This file reads
// that string straight out of the binary the installer drops next to the
// store's home (no exec, no vendor config), and the result is an
// INSTALL-level version: every session this parse touches is stamped with
// the build installed when the session was first ingested (operator ruling
// 2026-10-21: stamp every session, install-level when nothing finer exists).

// versionRe matches the compiled-in banner. The semver core is mandatory; a
// pre-release/build tail is tolerated.
var versionRe = regexp.MustCompile(`stakpak v(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]{1,40})?) \(https://github\.com/stakpak/agent\)`)

const (
	// scanChunk is the read size of the binary scan; scanOverlap is carried
	// between chunks so a banner straddling a boundary still matches.
	scanChunk   = 4 << 20
	scanOverlap = 128
	// scanLimit bounds how much of a binary is read (the banner sits ~50 MB
	// into a ~75-85 MB build).
	scanLimit = 256 << 20
)

// binaryRelPaths are the home-relative locations the vendor's installer
// (https://stakpak.dev/install.sh) and `cargo install` put the CLI.
var binaryRelPaths = [][]string{
	{".local", "bin", "stakpak"},
	{".local", "bin", "stakpak.exe"},
	{".cargo", "bin", "stakpak"},
	{".cargo", "bin", "stakpak.exe"},
}

// versionCache memoizes the scan per binary, keyed by (path, size, mtime) so
// a reinstalled or upgraded binary is re-read once and the 50 MB scan never
// repeats per parse.
var versionCache = struct {
	sync.Mutex
	m map[string]versionEntry
}{m: map[string]versionEntry{}}

type versionEntry struct {
	size    int64
	modNano int64
	version string
}

// storeHome returns the home directory that owns dbPath
// (<home>/.stakpak/data/local.db), or "" when the path does not have that
// shape.
func storeHome(dbPath string) string {
	dir := filepath.Dir(dbPath)
	if !strings.EqualFold(filepath.Base(dir), "data") {
		return ""
	}
	dir = filepath.Dir(dir)
	if !strings.EqualFold(filepath.Base(dir), ".stakpak") {
		return ""
	}
	return filepath.Dir(dir)
}

// installedVersion returns the version of the stakpak binary installed in
// the home that owns dbPath, "" when none is found.
func installedVersion(dbPath string) string {
	home := storeHome(dbPath)
	if home == "" {
		return ""
	}
	for _, rel := range binaryRelPaths {
		p := filepath.Join(append([]string{home}, rel...)...)
		if v := binaryVersion(p); v != "" {
			return v
		}
	}
	return ""
}

// binaryVersion extracts the banner version from one binary, memoized.
func binaryVersion(path string) string {
	st, err := os.Stat(path) //nolint:gosec // G703: stat of the vendor binary, read only
	if err != nil || st.IsDir() {
		return ""
	}
	versionCache.Lock()
	if e, ok := versionCache.m[path]; ok && e.size == st.Size() && e.modNano == st.ModTime().UnixNano() {
		versionCache.Unlock()
		return e.version
	}
	versionCache.Unlock()

	v := scanVersion(path)
	versionCache.Lock()
	versionCache.m[path] = versionEntry{size: st.Size(), modNano: st.ModTime().UnixNano(), version: v}
	versionCache.Unlock()
	return v
}

// scanVersion streams path in chunks and returns the first banner version.
func scanVersion(path string) string {
	f, err := os.Open(path) //nolint:gosec // G304: a fixed home-relative install path
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, scanChunk+scanOverlap)
	carry := 0
	var read int64
	for read < scanLimit {
		n, err := io.ReadFull(f, buf[carry:carry+scanChunk])
		window := buf[:carry+n]
		if m := versionRe.FindSubmatch(window); m != nil {
			return string(m[1])
		}
		read += int64(n)
		if err != nil { // EOF / short read: the whole file was scanned
			return ""
		}
		keep := scanOverlap
		if len(window) < keep {
			keep = len(window)
		}
		// `bytes.Equal`-free move: copy the tail to the front.
		copy(buf, window[len(window)-keep:])
		carry = keep
	}
	return ""
}

// sessionToolVersions stamps the install-level version onto every session the
// parse saw, in session-id order so the output is deterministic. The store
// write is first-wins-unless-empty, so a later upgrade never rewrites an
// earlier session's stamp.
func (a *Adapter) sessionToolVersions(dbPath string, sessions map[string]sessionCtx) []models.SessionToolVersion {
	if len(sessions) == 0 {
		return nil
	}
	v := installedVersion(dbPath)
	if v == "" {
		return nil
	}
	ids := make([]string, 0, len(sessions))
	for id := range sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]models.SessionToolVersion, 0, len(ids))
	for _, id := range ids {
		out = append(out, models.SessionToolVersion{SessionID: id, Version: v})
	}
	return out
}
