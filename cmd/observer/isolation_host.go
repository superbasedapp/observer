//go:build !sbo_omit_isolation

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// isolation_host.go holds the host facts every bwrap plan needs, terminal or
// one-shot: the host socket masks, the socket sweeps, the resolver keep and
// the foreign-OS mount roots. It belongs to the isolation component
// (sandbox plan v2 section 11.1, roadmap F0-11), which owns internal/sandbox;
// terminal_sandbox.go (component terminals.sandbox, which Requires
// isolation) reads them from here, and isolation_wire.go builds the one-shot
// runs with them. Moved out of terminal_sandbox.go unchanged.

// hostSocketMasks resolves sandbox.HostSocketPaths for uid into hide_dir
// overlays: each path resolved through symlinks, kept only when it exists and
// is a directory (socket FILES are dropped by socketSweeps instead).
func hostSocketMasks(uid int) ([]sandbox.Overlay, error) {
	var out []sandbox.Overlay
	seen := map[string]bool{}
	for _, p := range sandbox.ExpandHostSocketPaths(uid) {
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}
			return nil, fmt.Errorf("terminal_sandbox: cannot resolve host socket path %s: %w", p, err)
		}
		if seen[real] {
			continue
		}
		fi, err := os.Stat(real)
		if err != nil {
			return nil, fmt.Errorf("terminal_sandbox: cannot inspect host socket path %s: %w", real, err)
		}
		if !fi.IsDir() {
			continue
		}
		seen[real] = true
		out = append(out, sandbox.Overlay{Path: real, Kind: sandbox.OverlayHideDir})
	}
	return out, nil
}

// socketSweeps lists each existing, non-symlink sandbox.SocketSweepDirs
// directory with the entries to put back: directories and regular files are
// re-bound, symlinks are recreated unless they resolve to a socket, FIFO or
// device, and every socket, FIFO or device is dropped. An entry whose name
// could not be passed to bwrap safely is dropped too (hidden, never an
// error).
func socketSweeps() ([]sandbox.DirRebuild, error) {
	var out []sandbox.DirRebuild
	for _, dir := range sandbox.SocketSweepDirs {
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() {
			continue
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("terminal_sandbox: cannot list %s to drop its sockets: %w", dir, err)
		}
		d := sandbox.DirRebuild{Path: dir}
		for _, e := range ents {
			name := e.Name()
			if badSweepName(name) {
				continue
			}
			full := filepath.Join(dir, name)
			lfi, err := os.Lstat(full)
			if err != nil {
				continue // vanished since the listing
			}
			switch mode := lfi.Mode(); {
			case mode.IsDir(), mode.IsRegular():
				d.Keep = append(d.Keep, sandbox.RebuildEntry{Name: name})
			case mode&os.ModeSymlink != 0:
				target, err := os.Readlink(full)
				if err != nil || badSweepName(strings.ReplaceAll(target, "/", "x")) || strings.HasPrefix(target, "-") {
					continue
				}
				if tfi, err := os.Stat(full); err == nil && tfi.Mode()&(os.ModeSocket|os.ModeNamedPipe|os.ModeDevice|os.ModeCharDevice) != 0 {
					continue
				}
				d.Keep = append(d.Keep, sandbox.RebuildEntry{Name: name, Symlink: target})
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// badSweepName reports a directory entry name that is not a plain single
// component safe to hand to bwrap.
func badSweepName(name string) bool {
	if name == "" || name == "." || name == ".." || strings.HasPrefix(name, "-") || strings.Contains(name, "/") {
		return true
	}
	for _, r := range name {
		if r <= ' ' || r == 0x7f {
			return true
		}
	}
	return false
}

// hostMaskKeep returns the files a host mask would hide that the sandboxed
// process still needs read-only: today the resolver config, which WSL points
// into /mnt/wsl.
func hostMaskKeep(masks []sandbox.Overlay) []string {
	real, err := filepath.EvalSymlinks("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	for _, m := range masks {
		if withinAny(real, []string{m.Path}) && real != m.Path {
			return []string{real}
		}
	}
	return nil
}

// withinAny reports whether p equals or lies under any root, by this host's
// path rules (pathUnder: its separator, case-insensitive on Windows).
func withinAny(p string, roots []string) bool {
	p = filepath.Clean(p)
	for _, r := range roots {
		if r != "" && pathUnder(p, filepath.Clean(r), filepath.Separator, hostPathsFold) {
			return true
		}
	}
	return false
}

// hostPathsFold reports whether this host compares paths case-insensitively
// (Windows).
const hostPathsFold = runtime.GOOS == "windows"

// pathUnder reports whether the cleaned path p equals or lies under the
// cleaned root, where sep is the path separator and fold makes the
// comparison case-insensitive (Windows paths). A root that ends in sep (a
// filesystem or volume root: "/" or `C:\`) holds every path that starts
// with it. It is pure, so the Windows rules are tested on any host: the
// prefix test used to append "/" whatever the host, so on Windows the
// placeholder `<cwd>\.git` was refused as outside the run's only writable
// root <cwd> (Windows 11 Pro live run 2026-10-22).
func pathUnder(p, root string, sep byte, fold bool) bool {
	if root == "" || p == "" {
		return false
	}
	if pathSame(p, root, fold) {
		return true
	}
	prefix := root
	if prefix[len(prefix)-1] != sep {
		prefix += string(sep)
	}
	return len(p) > len(prefix) && pathSame(p[:len(prefix)], prefix, fold)
}

// pathSame compares two cleaned paths, case-insensitively when fold is set.
func pathSame(a, b string, fold bool) bool {
	if fold {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// hostMountTablePaths are the host mount tables foreignMountRoots reads, in
// the order tried: /proc/self/mountinfo first, /proc/mounts when it cannot
// be read or is empty.
var hostMountTablePaths = []string{"/proc/self/mountinfo", "/proc/mounts"}

// readHostMountTable reads the host's mount table. It is a variable so a test
// feeds a recorded table without a real /proc.
var readHostMountTable = func() ([]byte, error) {
	var errs []error
	for _, p := range hostMountTablePaths {
		b, err := os.ReadFile(p) //nolint:gosec // G304: a fixed procfs path from hostMountTablePaths
		if err == nil && len(strings.TrimSpace(string(b))) > 0 {
			return b, nil
		}
		if err == nil {
			err = errors.New("empty")
		}
		errs = append(errs, fmt.Errorf("%s: %w", p, err))
	}
	return nil, errors.Join(errs...)
}

// foreignMountRoots returns the foreign-OS mount roots every box must hide:
// the Windows drives `--ro-bind / /` would otherwise leave readable. Two
// sources are united (sandbox.BuildMaskRoots: de-duplicated, a root inside
// another dropped, sorted so the argv is deterministic):
//
//   - the host's own mount table (sandbox.ForeignDriveRoots): every drvfs
//     mount, wherever it is mounted, whether or not a foreign AI-tool home
//     sits on it. The home-derived set alone left a drive with no detected
//     home, and every drive when HOME is a scratch home (crossmount detects
//     nothing there), unmasked (ledger SBX-BE-24);
//   - the `/mnt/<drive>` prefix of each foreign AI-tool home crossmount
//     detects (a non-native home, e.g. a Windows home on a WSL host; the
//     native home is never masked).
//
// It fails closed: a Linux host whose mount table cannot be read, or whose
// table cannot be understood (sandbox.ForeignDriveRoots), is an error and the
// launch is refused, never a silently empty mask list. A host that is not
// Linux has no such table and contributes the home-derived roots only (a
// bwrap box exists on Linux alone). On a Linux host with no Windows drive and
// no foreign home the result is empty, so its argv is unchanged.
func foreignMountRoots() ([]string, error) {
	var fromHomes []string
	for _, h := range crossmount.ExtraHomes() {
		if h.OS == crossmount.OSLinux && runtime.GOOS == "linux" {
			continue // a same-OS extra home is not a foreign mount
		}
		if root := mntDriveRoot(h.Path); root != "" {
			fromHomes = append(fromHomes, root)
		}
	}
	if runtime.GOOS != "linux" {
		return sandbox.BuildMaskRoots(fromHomes), nil
	}
	table, err := readHostMountTable()
	if err != nil {
		return nil, fmt.Errorf("sandbox: the host mount table could not be read, so the Windows drives to hide from the box cannot be found (%w); the launch is refused rather than run with a drive possibly showing", err)
	}
	roots, err := sandbox.ForeignDriveRoots(table, fromHomes)
	if err != nil {
		return nil, fmt.Errorf("%w; the launch is refused rather than run with a drive possibly showing", err)
	}
	return roots, nil
}

// mntDriveRoot extracts the `/mnt/<drive>` prefix of a WSL foreign-home path
// (e.g. "/mnt/c/Users/me" → "/mnt/c"), or "" when the path is not under /mnt.
func mntDriveRoot(p string) string {
	const prefix = "/mnt/"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	rest := p[len(prefix):]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		rest = rest[:slash]
	}
	if rest == "" {
		return ""
	}
	return prefix + rest
}
