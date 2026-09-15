package crossmount

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// OS tags emitted on HomeRoot.
const (
	OSWindows = "windows"
	OSLinux   = "linux"
	OSDarwin  = "darwin"
)

// HomeRoot is one candidate $HOME-equivalent directory.
type HomeRoot struct {
	// Path is the absolute filesystem path to the home directory, in
	// whatever form is reachable from the running process (e.g.
	// "/mnt/c/Users/auzy_" on WSL2, `\\wsl.localhost\Ubuntu\home\me` on
	// Windows).
	Path string
	// OS tags whose conventions the home follows: "windows", "linux", or
	// "darwin". This is the LOGICAL OS of the home — not necessarily
	// the same as runtime.GOOS. A native home on a Linux host has
	// OS=="linux"; a /mnt/c/Users/<u> entry on the same host has
	// OS=="windows".
	OS string
	// Origin describes where this candidate came from for diagnostic
	// logging: "native", "wsl-mnt:<user>", or "wslhost:<distro>/<user>".
	Origin string
}

// detector is the test seam — production code uses defaultDetector(),
// tests construct one with fakes for runtimeOS / nativeHome / statDir /
// readDir / exists / getenv to exercise both bridge directions on any
// host.
//
// exists and getenv are nil-tolerant: a detector literal that omits
// them falls back to the real os.Stat / os.Getenv, so the pre-existing
// test literals keep compiling and only the tests that care about the
// Windows-profile filter have to stage them.
type detector struct {
	runtimeOS  string
	nativeHome func() (string, error)
	statDir    func(path string) bool
	readDir    func(path string) ([]string, error)
	exists     func(path string) bool
	getenv     func(name string) string
}

func defaultDetector() *detector {
	return &detector{
		runtimeOS:  runtime.GOOS,
		nativeHome: os.UserHomeDir,
		statDir:    isExistingDir,
		readDir:    readDirNames,
		exists:     fileExists,
		getenv:     os.Getenv,
	}
}

// The cross-mount scan behind ExtraHomes enumerates and stats a
// foreign-OS mount (/mnt/c/Users over 9P on WSL2, \\wsl.localhost\ on
// Windows) — tens of milliseconds per call, and every adapter's
// WatchPaths/IsSessionFile recomputes it. Hot paths multiply that:
// the watcher runs IsSessionFile per fsnotify event, and the
// watcher-health endpoint resolved cursor semantics for ~5k rows,
// each re-scanning the mount — minutes of 9P round-trips per request
// (the 2026-08-29 goroutine dump named this exact stack). Home
// directories effectively never change while the daemon runs, so the
// package entry points serve a short-TTL cache; a genuinely new
// foreign-OS user home is picked up within extrasCacheTTL. The
// detector methods themselves stay uncached — tests construct their
// own detectors and must observe every injected-fs call.
const extrasCacheTTL = 30 * time.Second

var extrasCache struct {
	mu      sync.Mutex
	val     []HomeRoot
	expires time.Time
}

// extrasScan is the cache's refill seam; tests stub it to count scans.
var extrasScan = func() []HomeRoot { return defaultDetector().extraHomes() }

func cachedExtraHomes() []HomeRoot {
	extrasCache.mu.Lock()
	defer extrasCache.mu.Unlock()
	if time.Now().After(extrasCache.expires) {
		extrasCache.val = extrasScan()
		extrasCache.expires = time.Now().Add(extrasCacheTTL)
	}
	// Copy: callers append to and re-slice the result (WatchPaths
	// composition); aliasing the cached backing array would let one
	// caller corrupt every later caller's view.
	out := make([]HomeRoot, len(extrasCache.val))
	copy(out, extrasCache.val)
	return out
}

// resetExtrasCacheForTest empties the cache so a test observes a fresh
// scan. Test-only; never called from production code.
func resetExtrasCacheForTest() {
	extrasCache.mu.Lock()
	defer extrasCache.mu.Unlock()
	extrasCache.val = nil
	extrasCache.expires = time.Time{}
}

// AllHomes returns the native home (when resolvable) plus every
// auto-detected cross-mount home. Order: native first, then extras in
// directory-listing order (which on most filesystems is creation
// order, sometimes alphabetical — callers must not rely on it).
//
// Safe to call on any platform; never errors. The cross-mount extras
// are served from a short-TTL cache (see extrasCacheTTL); the native
// home is resolved fresh on every call.
func AllHomes() []HomeRoot {
	var all []HomeRoot
	d := defaultDetector()
	if home, err := d.nativeHome(); err == nil && home != "" {
		all = append(all, HomeRoot{
			Path:   home,
			OS:     d.runtimeOS,
			Origin: "native",
		})
	}
	return append(all, cachedExtraHomes()...)
}

// ExtraHomes returns only the auto-detected cross-mount homes,
// excluding the native home. Useful for diagnostic logging that
// surfaces what the bridge picked up. Served from the same short-TTL
// cache as AllHomes.
func ExtraHomes() []HomeRoot {
	return cachedExtraHomes()
}

func (d *detector) allHomes() []HomeRoot {
	var all []HomeRoot
	if home, err := d.nativeHome(); err == nil && home != "" {
		all = append(all, HomeRoot{
			Path:   home,
			OS:     d.runtimeOS,
			Origin: "native",
		})
	}
	all = append(all, d.extraHomes()...)
	return all
}

func (d *detector) extraHomes() []HomeRoot {
	switch d.runtimeOS {
	case OSLinux:
		return d.wslWindowsHomes()
	case OSWindows:
		return d.windowsWSLHomes()
	}
	return nil
}

// wslWindowsHomes enumerates Windows user homes reachable from a WSL2
// host via the /mnt/c bind. Returns nil when /mnt/c/Users is not a
// directory (pure Linux host, or WSL2 instance without the C: mount).
//
// Four gates, applied in this order (see windowsprofiles.go for the
// tables and the reasoning behind each):
//
//  1. The candidate must itself be a DIRECTORY, so entries like
//     desktop.ini are skipped (filepath.WalkDir would error on them
//     downstream otherwise).
//  2. Its name must not be a well-known non-user entry — Default,
//     Default User, Public, All Users, and the service/template
//     profiles alongside them.
//  3. It must carry a real-profile marker: an NTUSER.DAT hive or an
//     AppData tree. A directory with neither has never held an AI
//     tool's session store.
//  4. Case-insensitive de-duplication, because the underlying
//     filesystem is case-insensitive and two spellings of one profile
//     would otherwise fan out into two full sets of watch roots.
//
// The original design deliberately did NO name filtering, on the
// theory that the watcher's existence check turns an inert home into a
// no-op. That is true of the DATA path but not of the operational one:
// on the 2026-09-03 dev box the daemon composed, registered and logged
// a full set of watch roots for Default, Default User, Public, All
// Users and WsiAccount — none of which can ever exist — cluttering the
// journal and the doctor output, and paying per-tick re-detection cost
// on DrvFs for each. Filtering the enumeration is the one-owner fix.
//
// Set EnvAllWindowsProfiles to restore the unfiltered behaviour.
func (d *detector) wslWindowsHomes() []HomeRoot {
	const root = "/mnt/c/Users"
	if !d.statDir(root) {
		return nil
	}
	names, err := d.readDir(root)
	if err != nil {
		return nil
	}
	unfiltered := d.allProfilesForced()
	var out []HomeRoot
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		path := filepath.Join(root, name)
		if !d.statDir(path) {
			continue
		}
		if !unfiltered {
			if isNonUserProfileName(name) {
				continue
			}
			if !d.hasUserProfileMarker(path) {
				continue
			}
		}
		key := strings.ToLower(name)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, HomeRoot{
			Path:   path,
			OS:     OSWindows,
			Origin: "wsl-mnt:" + name,
		})
	}
	return out
}

// windowsWSLHomes enumerates Linux user homes reachable from a Windows
// host via \\wsl.localhost\<distro>\home\<user>. Returns nil when
// \\wsl.localhost\ is not enumerable (no WSL installed, or no distros
// running). Best-effort: distros are typically reachable only when the
// distro is running or recently used; that's an acceptable limitation.
func (d *detector) windowsWSLHomes() []HomeRoot {
	const root = `\\wsl.localhost\`
	if !d.statDir(root) {
		return nil
	}
	distros, err := d.readDir(root)
	if err != nil {
		return nil
	}
	var out []HomeRoot
	for _, distro := range distros {
		homeDir := filepath.Join(root, distro, "home")
		if !d.statDir(homeDir) {
			continue
		}
		users, err := d.readDir(homeDir)
		if err != nil {
			continue
		}
		for _, user := range users {
			userPath := filepath.Join(homeDir, user)
			if !d.statDir(userPath) {
				continue
			}
			out = append(out, HomeRoot{
				Path:   userPath,
				OS:     OSLinux,
				Origin: "wslhost:" + distro + "/" + user,
			})
		}
	}
	return out
}

// IsWSL reports whether this process runs inside WSL2 with Windows interop —
// the environment where a Linux daemon can reach Windows-installed tools over
// the /mnt bind and, conversely, where a native tool binary may be shadowed by
// a Windows npm interop shim on PATH. It returns true when the binfmt interop
// registration (/proc/sys/fs/binfmt_misc/WSLInterop) exists OR /proc/version
// names a Microsoft kernel (case-insensitive). Safe on any platform: on a
// non-WSL host both probes miss and it returns false.
//
// TODO(consolidation): internal/processobs/bridge.isWSL and internal/launch's
// inline WSL probe (launch.Detect) implement the same check; a follow-up should
// route both through this exported detector so there is one owner.
func IsWSL() bool {
	return isWSL(fileExists, os.ReadFile)
}

// isWSL is the injectable core of IsWSL: exists reports whether a path exists,
// readFile reads a file's bytes. Split out so a test can stage /proc contents
// without touching the host.
func isWSL(exists func(string) bool, readFile func(string) ([]byte, error)) bool {
	if exists("/proc/sys/fs/binfmt_misc/WSLInterop") {
		return true
	}
	if b, err := readFile("/proc/version"); err == nil {
		return strings.Contains(strings.ToLower(string(b)), "microsoft")
	}
	return false
}

// fileExists reports whether path exists (of any type).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isExistingDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func readDirNames(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
