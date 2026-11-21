//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetupnet"
)

// sandbox_setup_download.go is the pinned-download seam of sandbox setup
// (sandbox installation lifecycle plan sections 3.5, 3.6 and 6). It fetches
// (through the internal/sandboxsetupnet lane) or verifies (a from_file path)
// one pinned sandbox host tool, checks its sha256 and size against the
// compiled pin, and places it in the user-owned tools directory
// (sandboxsetup.ToolsRoot): streamed into an owner-only temporary file in
// the target directory while hashing, checked, chmodded and renamed into
// place, so a half-written file is never at the final path. It writes no
// config: the runner (lane daemon) writes the config key for the placed
// path from the result.
//
// The gate in front of it is the runner's (the module, allow_install, the
// plan fingerprint and the consent echo); this seam adds what only it can
// know: one download at a time per machine (a dblease lease), the pin's
// status, the managed-node rule (decision O3: downloads there come from the
// org mirror only, and no mirror kind for sandbox host tools exists yet, so
// only a from_file step can place a tool on a managed node), and the
// placement rules.

// sandboxDownloadRequest asks for one pinned file.
type sandboxDownloadRequest struct {
	// Pin is the pin id (internal/sandboxsetup's pin table).
	Pin string
	// FromFile is "" to fetch, else a local file to verify and place.
	FromFile string
	// Managed: a managed node, so the org mirror is the only source.
	Managed  bool
	Progress func(done, total int64)
}

// sandboxDownloadResult is what was placed.
type sandboxDownloadResult struct {
	Path, SHA256, Source, Version string
	Bytes                         int64
}

// The result's Source when the bytes came from a local file rather than a
// download (the record's source column).
const sandboxSourceFromFile = "from_file"

// sandboxDownloadLeaseName holds one sandbox tool download at a time per
// machine (the codeInstallLeaseName pattern).
const sandboxDownloadLeaseName = "sandbox-setup-download"

// sandboxMirrorKind is the org mirror content kind a managed node would
// download sandbox host tools from. It does not exist yet (plan section 6:
// a follow-up of server and vendorsign work), which is why a managed
// download is refused.
const sandboxMirrorKind = "sandbox.host_tool"

// Errors, matched with errors.Is.
var (
	// errSandboxDownloadNotBuilt was the core stub's answer; kept for any
	// caller written against the stub.
	errSandboxDownloadNotBuilt = errors.New("sandbox setup downloads are not built yet")
	// errSandboxDownloadManaged is a fetch refused on a managed node.
	errSandboxDownloadManaged = fmt.Errorf("a managed node downloads sandbox tools only from its organization's mirror, and the org mirror has no %s kind yet: use a file already on this machine (from_file) instead", sandboxMirrorKind)
	// errSandboxDownloadBusy is another download holding the lease.
	errSandboxDownloadBusy = errors.New("another sandbox tool download is running")
	// errSandboxDownloadMismatch is bytes whose sha256 or size is not the pin's.
	errSandboxDownloadMismatch = errors.New("the file does not match the pinned sha256 and size")
	// errSandboxDownloadOwed is a pin that is not grounded.
	errSandboxDownloadOwed = errors.New("no verified download is pinned for this tool yet")
	// errSandboxDownloadNoPin is a pin id with no row for this platform.
	errSandboxDownloadNoPin = errors.New("no pinned download for this tool on this platform")
	// errSandboxDownloadPlaced is a placed file that fails its re-check.
	errSandboxDownloadPlaced = errors.New("the placed file failed its check")
)

// sandboxFetcher is the network lane's download, injected for tests.
type sandboxFetcher interface {
	Download(ctx context.Context, raw string, limit int64, w io.Writer) (int64, string, error)
}

// The seams the tests replace. Production: the compiled pin table, the
// sandboxsetupnet lane, the process environment and home.
var (
	sandboxDownloadPinFor  = sandboxsetup.PinFor
	sandboxDownloadFetcher = func() sandboxFetcher { return sandboxsetupnet.New(sandboxsetupnet.Options{}) }
	sandboxDownloadGetenv  = os.Getenv
	sandboxDownloadHome    = os.UserHomeDir
)

// sandboxSetupDownload fetches (or verifies) and places one pinned file.
func sandboxSetupDownload(ctx context.Context, req sandboxDownloadRequest) (sandboxDownloadResult, error) {
	if err := ctx.Err(); err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	pin, ok := sandboxDownloadPinFor(req.Pin)
	if !ok {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %q on %s/%s: %w", req.Pin, runtime.GOOS, runtime.GOARCH, errSandboxDownloadNoPin)
	}
	if pin.Status != sandboxsetup.PinGrounded {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %s %s: %w", pin.ID, pin.Version, errSandboxDownloadOwed)
	}
	if req.FromFile == "" && req.Managed {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", errSandboxDownloadManaged)
	}
	home, err := sandboxDownloadHome()
	if err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: no home directory: %w", err)
	}
	root, err := sandboxsetup.ToolsRoot(sandboxDownloadGetenv, home)
	if err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	dir, err := sandboxsetup.PinDir(root, pin)
	if err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	final, err := sandboxsetup.PinPath(root, pin)
	if err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	if err := sandboxsetup.CheckPlacement(dir, home, nil); err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}

	if err := os.MkdirAll(root, sandboxsetup.PlacedDirMode); err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	release, acquired, lerr := dblease.TryAcquire(root, sandboxDownloadLeaseName)
	if lerr == nil && !acquired {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", errSandboxDownloadBusy)
	}
	defer release()

	if err := sandboxOwnerOnlyDir(dir); err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	tmp, err := fsatomic.CreateTempOwnerOnly(dir, ".download-*")
	if err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	tmpName := tmp.Name()
	placed := false
	defer func() {
		_ = tmp.Close()
		if !placed {
			_ = os.Remove(tmpName)
		}
	}()

	w := &sandboxProgressWriter{w: tmp, total: pin.Size, fn: req.Progress}
	var (
		n      int64
		digest string
		source string
	)
	if req.FromFile != "" {
		source = sandboxSourceFromFile
		n, digest, err = sandboxCopyFromFile(ctx, req.FromFile, pin, w)
	} else {
		source = sandboxsetup.SourceVendorRelease
		n, digest, err = sandboxDownloadFetcher().Download(ctx, pin.URL, pin.Size, w)
	}
	if err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	if digest != pin.SHA256 || n != pin.Size {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: got %d bytes sha256 %s, pinned %d bytes sha256 %s: %w", n, digest, pin.Size, pin.SHA256, errSandboxDownloadMismatch)
	}
	if err := os.Chmod(tmpName, sandboxsetup.PlacedFileMode); err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	placed = true
	if err := sandboxVerifyPlaced(dir, final, pin); err != nil {
		_ = os.Remove(final) // a file this call placed and could not vouch for
		return sandboxDownloadResult{}, fmt.Errorf("sandboxSetupDownload: %w", err)
	}
	if req.Progress != nil {
		req.Progress(n, pin.Size)
	}
	return sandboxDownloadResult{Path: final, SHA256: digest, Source: source, Version: pin.Version, Bytes: n}, nil
}

// sandboxOwnerOnlyDir creates dir (and its parents) as the user's own,
// tightens it to the placed directory mode and refuses it unless it is a
// real directory (not a symlink) owned by this user with no group or other
// access, so no other account can swap the file between placing and use.
func sandboxOwnerOnlyDir(dir string) error {
	if err := os.MkdirAll(dir, sandboxsetup.PlacedDirMode); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if fi.Mode().Perm() != sandboxsetup.PlacedDirMode {
		if err := os.Chmod(dir, sandboxsetup.PlacedDirMode); err != nil {
			return err
		}
	}
	return sandboxDirIsOwnerOnly(dir)
}

// sandboxDirIsOwnerOnly judges dir from its own open handle (fsatomic).
func sandboxDirIsOwnerOnly(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: Observer's own tools directory.
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	ok, err := fsatomic.FileIsOwnerOnly(d)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s is not owned by this user alone", dir)
	}
	return nil
}

// sandboxVerifyPlaced re-checks the placed file from disk, not from what the
// writer believed: a regular file (not a symlink) with the placed mode, in
// an owner-only directory, whose sha256 and size are still the pin's.
func sandboxVerifyPlaced(dir, final string, pin sandboxsetup.Pin) error {
	if err := sandboxDirIsOwnerOnly(dir); err != nil {
		return fmt.Errorf("%w: %w", errSandboxDownloadPlaced, err)
	}
	fi, err := os.Lstat(final)
	if err != nil {
		return fmt.Errorf("%w: %w", errSandboxDownloadPlaced, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", errSandboxDownloadPlaced, final)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != sandboxsetup.PlacedFileMode {
		return fmt.Errorf("%w: %s has mode %o", errSandboxDownloadPlaced, final, fi.Mode().Perm())
	}
	f, err := os.Open(final) //nolint:gosec // G304: the file this call just placed.
	if err != nil {
		return fmt.Errorf("%w: %w", errSandboxDownloadPlaced, err)
	}
	defer func() { _ = f.Close() }()
	if got, err := f.Stat(); err != nil || !os.SameFile(fi, got) {
		return fmt.Errorf("%w: %s changed while it was being checked", errSandboxDownloadPlaced, final)
	}
	h := newSandboxHasher(io.Discard)
	n, err := io.Copy(h, io.LimitReader(f, pin.Size+1))
	if err != nil {
		return fmt.Errorf("%w: %w", errSandboxDownloadPlaced, err)
	}
	digest := h.sum()
	if digest != pin.SHA256 || n != pin.Size {
		return fmt.Errorf("%w: %w", errSandboxDownloadPlaced, errSandboxDownloadMismatch)
	}
	return nil
}

// sandboxCopyFromFile copies a local file the person named into w while
// hashing it, at most pin.Size bytes. The path must pass
// sandboxsetup.CheckFromFile on an Lstat, and the file opened must be the
// file judged (a swap between the two is refused).
func sandboxCopyFromFile(ctx context.Context, path string, pin sandboxsetup.Pin, w io.Writer) (int64, string, error) {
	fi, err := os.Lstat(path) //nolint:gosec // G703: a metadata read of the person's own local path.
	if err != nil {
		return 0, "", err
	}
	if err := sandboxsetup.CheckFromFile(path, fi, pin); err != nil {
		return 0, "", err
	}
	f, err := os.Open(path) //nolint:gosec // G304: the person's own local file, read with their own rights.
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = f.Close() }()
	got, err := f.Stat()
	if err != nil {
		return 0, "", err
	}
	if !os.SameFile(fi, got) {
		return 0, "", fmt.Errorf("%s changed while it was being opened", path)
	}
	h := newSandboxHasher(w)
	n, err := io.Copy(h, io.LimitReader(sandboxCtxReader{ctx: ctx, r: f}, pin.Size+1))
	if err != nil {
		return n, "", err
	}
	if n > pin.Size {
		return n, "", fmt.Errorf("%s is over the pin's %d bytes: %w", path, pin.Size, sandboxsetup.ErrFromFileSize)
	}
	return n, h.sum(), nil
}

// sandboxCtxReader stops a copy once its context ends.
type sandboxCtxReader struct {
	ctx context.Context
	r   io.Reader
}

// Read implements io.Reader.
func (c sandboxCtxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// sandboxProgressWriter reports bytes written to fn.
type sandboxProgressWriter struct {
	w     io.Writer
	done  int64
	total int64
	fn    func(done, total int64)
}

// Write implements io.Writer.
func (p *sandboxProgressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.done += int64(n)
	if p.fn != nil && n > 0 {
		p.fn(p.done, p.total)
	}
	return n, err
}

// sandboxHasher writes through to w while hashing.
type sandboxHasher struct {
	w io.Writer
	h hash.Hash
}

func newSandboxHasher(w io.Writer) *sandboxHasher { return &sandboxHasher{w: w, h: sha256.New()} }

// Write implements io.Writer.
func (s *sandboxHasher) Write(b []byte) (int, error) {
	n, err := s.w.Write(b)
	s.h.Write(b[:n])
	return n, err
}

// sum is the lowercase hex sha256 of what was written.
func (s *sandboxHasher) sum() string { return hex.EncodeToString(s.h.Sum(nil)) }

// Referenced until lane daemon calls them.
var (
	_ = sandboxSetupDownload
	_ = errSandboxDownloadNotBuilt
)
