//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandbox_content_import.go is `observer sandbox content import <dir>` (lane
// SBX-P4 decision 2): the offline install of the sandbox kinds, for an
// air-gapped node, a managed node whose org mirror does not carry a kind
// (the microVM image set), and the live checks. <dir> holds one directory
// per kind, the layout scripts/vendorsign writes:
//
//	<dir>/<kind>/manifest.json      the signed envelope
//	<dir>/<kind>/<entry name>       each covered artifact
//
// Every kind found is verified first (the vendor signature against the
// compiled key set, the store's high-water mark, every file's exact size
// and sha256, streamed under its cap), and only when all of them pass is
// anything installed, through contentchan's InstallFiles. The install is
// all or nothing: each kind's current files are kept aside (hard links in
// the staging dir) before it is installed, and when a later kind is
// refused every kind installed before it is put back, so a refusal leaves
// every kind's last-known-good in place. The user's directory is never
// changed: each file is copied into a staging directory beside the store
// first. It is a user action and needs no network.

// sandboxImportMaxEntry caps one imported artifact (the guest rootfs is the
// largest entry, at most 4 GiB).
const sandboxImportMaxEntry = 4 << 30

// sandboxImportKinds are the kinds the verb takes: every sandbox kind.
func sandboxImportKinds() []content.Kind {
	out := make([]content.Kind, 0, len(orgclient.SandboxContentKinds))
	for _, r := range orgclient.SandboxContentKinds {
		out = append(out, r.Kind)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// sandboxImportStaged is one kind ready to install.
type sandboxImportStaged struct {
	kind     content.Kind
	envelope []byte
	files    map[string]string
	version  int64
}

// sandboxContentImport verifies every kind under dir, then installs them.
// It returns what was installed; on any refusal nothing is.
func sandboxContentImport(store contentchan.Store, keys []ed25519.PublicKey, dir string) ([]sandboxImportStaged, error) {
	return sandboxContentImportWith(store, keys, dir, nil)
}

// sandboxContentImportWith is sandboxContentImport with an optional debug
// key (R-016): non-nil only when the operator gave both --debug-set and
// --debug-key. The import then verifies against that key alone (never the
// vendor keys), takes only a debug microVM image set, and records the key
// so the driver's load can verify the set; without it a debug set is
// refused, whoever signed it.
func sandboxContentImportWith(store contentchan.Store, keys []ed25519.PublicKey, dir string, debugKey ed25519.PublicKey) ([]sandboxImportStaged, error) {
	if debugKey != nil {
		keys = []ed25519.PublicKey{debugKey}
	}
	if len(keys) == 0 {
		return nil, errors.New("sandbox content import: this build carries no vendor key, so nothing can verify (artifact_unverified)")
	}
	tr := contentchan.Trust{VendorKeys: keys}
	if err := os.MkdirAll(store.Root, 0o700); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(store.Root, ".import-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	var staged []sandboxImportStaged
	for _, kind := range sandboxImportKinds() {
		kdir := filepath.Join(dir, string(kind))
		if fi, err := os.Lstat(kdir); err != nil || !fi.IsDir() {
			continue
		}
		s, err := sandboxImportStage(store, tr, kind, kdir, filepath.Join(staging, string(kind)))
		if err != nil {
			return nil, err
		}
		staged = append(staged, s)
	}
	if len(staged) == 0 {
		return nil, fmt.Errorf("sandbox content import: %s holds no sandbox kind directory (%v)", dir, sandboxImportKinds())
	}
	rootfsStaged, err := sandboxImportDebugGate(staged, debugKey != nil)
	if err != nil {
		return nil, err
	}
	if err := sandboxImportImageGate(staged); err != nil {
		return nil, err
	}
	aside := filepath.Join(staging, ".before")
	var installed []sandboxImportBackup
	for _, s := range staged {
		b, err := sandboxImportBackupKind(store, s.kind, aside)
		if err != nil {
			return nil, fmt.Errorf("sandbox content import: %s: its last-known-good could not be kept aside (%w); %s", s.kind, err, sandboxImportRollBack(installed))
		}
		if _, err := store.InstallFiles(s.kind, s.envelope, s.files, tr); err != nil {
			return nil, fmt.Errorf("sandbox content import: %s: %w; %s", s.kind, err, sandboxImportRollBack(installed))
		}
		installed = append(installed, b)
	}
	// The debug key is recorded only beside a debug set it verified, and a
	// release image set imported later removes it.
	switch {
	case debugKey != nil:
		if err := writeSandboxDebugKey(store.Root, debugKey); err != nil {
			return nil, fmt.Errorf("sandbox content import: the debug set is installed but its debug key could not be recorded (%w); the set will not boot until it is", err)
		}
	case rootfsStaged:
		if err := os.Remove(filepath.Join(store.Root, sandboxDebugKeyFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("sandbox content import: remove the earlier debug key: %w", err)
		}
	}
	return staged, nil
}

// sandboxDebugKeyFile is the store-root file a debug import records its key
// in (the microVM driver's loader reads it, terminal_sandbox_vm_imageset.go).
const sandboxDebugKeyFile = "debug-image-set.key"

// sandboxImportDebugGate is the debug image set's import rule (R-016): a
// debug import takes only the microVM kinds and a rootfs whose signed
// descriptor says debug; a release import refuses a debug descriptor. It
// reports whether a rootfs is staged.
func sandboxImportDebugGate(staged []sandboxImportStaged, debug bool) (bool, error) {
	var rootfs *sandboxImportStaged
	for i := range staged {
		k := staged[i].kind
		if k == content.SandboxRootfs {
			rootfs = &staged[i]
		}
		if debug && k != content.SandboxRootfs && k != content.SandboxGuest {
			return false, fmt.Errorf("sandbox content import: a debug import takes only the microVM image set (sandbox.rootfs and sandbox.guest_binary), not %s", k)
		}
	}
	if rootfs == nil {
		if debug {
			return false, errors.New("sandbox content import: a debug import needs the debug image set's sandbox.rootfs")
		}
		return false, nil
	}
	p, ok := rootfs.files[sandboximage.VMDescriptorName]
	if !ok {
		return true, fmt.Errorf("sandbox content import: sandbox.rootfs has no %s", sandboximage.VMDescriptorName)
	}
	b, err := sandboxImportRead(p, 1<<20)
	if err != nil {
		return true, fmt.Errorf("sandbox content import: read the image set's descriptor: %w", err)
	}
	d, err := sandboximage.ParseVMDescriptor(b)
	if err != nil {
		return true, fmt.Errorf("sandbox content import: %w", err)
	}
	switch {
	case d.Debug && !debug:
		return true, fmt.Errorf("sandbox content import: %s (%s): the image set %s is a debug set (never shipped); it is imported only with both --debug-set and --debug-key", sandboximage.VerdictArtifactUnverified, sandboximage.ReasonDebugSet, d.Version)
	case !d.Debug && debug:
		return true, fmt.Errorf("sandbox content import: %s (%s): --debug-set imports only a debug image set, and %s is a release set", sandboximage.VerdictArtifactUnverified, sandboximage.ReasonDebugSet, d.Version)
	}
	return true, nil
}

// sandboxImportImageGate checks a staged sandbox.image descriptor before
// anything is installed (R-038): it must parse under the node's own rules,
// so a declared size_bytes past sandboximage.MaxSizeBytes (or negative) is
// refused here rather than at the next launch. A descriptor that declares
// no size still imports; the pull then says "size not declared" and applies
// the 8 GB bound.
func sandboxImportImageGate(staged []sandboxImportStaged) error {
	for _, s := range staged {
		if s.kind != content.SandboxImage {
			continue
		}
		p, ok := s.files[sandboximage.DescriptorName]
		if !ok {
			return fmt.Errorf("sandbox content import: sandbox.image has no %s", sandboximage.DescriptorName)
		}
		b, err := sandboxImportRead(p, 1<<20)
		if err != nil {
			return fmt.Errorf("sandbox content import: read the image descriptor: %w", err)
		}
		if _, err := sandboximage.ParseDescriptor(b); err != nil {
			return fmt.Errorf("sandbox content import: %s: %w", sandboximage.VerdictArtifactUnverified, err)
		}
	}
	return nil
}

// writeSandboxDebugKey records the debug key, owner-only, atomically. The
// file is created through fsatomic.CreateOwnerOnly: mode 0600 on POSIX and,
// on Windows, a protected DACL for this user and SYSTEM, which the loader's
// owner-only check (vmDebugKeyOwnerOnly) reads back. Before, os.WriteFile's
// 0600 means nothing on Windows (the file reads back as 0666), so the
// loader never trusted the key there and every debug set failed with
// "no accepted vendor key verifies the signature" (RERUN2 D6).
func writeSandboxDebugKey(root string, k ed25519.PublicKey) error {
	p := filepath.Join(root, sandboxDebugKeyFile)
	tmp := p + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := fsatomic.CreateOwnerOnly(tmp)
	if err != nil {
		return err
	}
	_, werr := f.Write([]byte(hex.EncodeToString(k) + "\n"))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	return os.Rename(tmp, p)
}

// parseDebugPublicKey reads a debug key file's text: one ed25519 public key
// as 64 hex characters (what vendorsign -debug writes as debug-key.pub).
func parseDebugPublicKey(text string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(text))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("the debug key is not one ed25519 public key in 64 hex characters")
	}
	return ed25519.PublicKey(b), nil
}

// sandboxImportBackup is one kind's files as they were before the import.
type sandboxImportBackup struct {
	kind    content.Kind
	dir     string
	saved   string
	existed bool
}

// sandboxImportBackupKind keeps a kind's current regular files aside under
// root: a hard link each (the store and the staging dir share a
// filesystem; InstallFiles replaces a file by rename, so the link keeps the
// old bytes), a copy where a link cannot be made.
func sandboxImportBackupKind(store contentchan.Store, kind content.Kind, root string) (sandboxImportBackup, error) {
	dir, err := store.KindDir(kind)
	if err != nil {
		return sandboxImportBackup{}, err
	}
	b := sandboxImportBackup{kind: kind, dir: dir, saved: filepath.Join(root, string(kind))}
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return b, nil
	}
	if err != nil {
		return b, err
	}
	b.existed = true
	if err := os.MkdirAll(b.saved, 0o700); err != nil {
		return b, err
	}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		src, dst := filepath.Join(dir, e.Name()), filepath.Join(b.saved, e.Name())
		if err := os.Link(src, dst); err != nil {
			if err := sandboxImportCopy(src, dst, sandboxImportMaxEntry); err != nil {
				return b, err
			}
		}
	}
	return b, nil
}

// restore puts the kind back as it was: every regular file now in its dir
// is removed and every kept one renamed back (a kind that did not exist is
// removed again).
func (b sandboxImportBackup) restore() error {
	ents, err := os.ReadDir(b.dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, e := range ents {
		if e.Type().IsRegular() {
			if err := os.Remove(filepath.Join(b.dir, e.Name())); err != nil {
				return err
			}
		}
	}
	if !b.existed {
		_ = os.Remove(b.dir)
		return nil
	}
	saved, err := os.ReadDir(b.saved)
	if err != nil {
		return err
	}
	for _, e := range saved {
		if err := os.Rename(filepath.Join(b.saved, e.Name()), filepath.Join(b.dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// sandboxImportRollBack restores the kinds installed so far, last first,
// and says what that left.
func sandboxImportRollBack(installed []sandboxImportBackup) string {
	var failed []string
	for i := len(installed) - 1; i >= 0; i-- {
		if err := installed[i].restore(); err != nil {
			failed = append(failed, fmt.Sprintf("%s (%v)", installed[i].kind, err))
		}
	}
	if len(failed) > 0 {
		return "nothing more was installed, but these kinds could not be put back to their last-known-good: " + strings.Join(failed, ", ") + "; run the import again"
	}
	return "nothing was installed: every kind keeps its last-known-good"
}

// sandboxImportStage verifies one kind and copies its files into stage.
func sandboxImportStage(store contentchan.Store, tr contentchan.Trust, kind content.Kind, kdir, stage string) (sandboxImportStaged, error) {
	fail := func(err error) (sandboxImportStaged, error) {
		return sandboxImportStaged{}, fmt.Errorf("sandbox content import: %s: %w", kind, err)
	}
	env, err := sandboxImportRead(filepath.Join(kdir, contentchan.ManifestFile), content.MaxEnvelopeBytes)
	if err != nil {
		return fail(err)
	}
	prev, err := store.State(kind)
	if err != nil {
		return fail(err)
	}
	res, err := content.Verify(content.VerifyInput{Envelope: env, Kind: kind, VendorKeys: tr.VendorKeys, Accepted: prev.Accepted, Now: storeNow(store)})
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return fail(err)
	}
	files := map[string]string{}
	for _, e := range res.Manifest.Entries {
		if _, dup := files[e.Name]; dup {
			continue
		}
		src := filepath.Join(kdir, e.Name)
		if _, err := os.Lstat(src); errors.Is(err, os.ErrNotExist) {
			continue // another platform's entry; InstallFiles refuses a missing one of ours
		}
		dst := filepath.Join(stage, e.Name)
		if err := sandboxImportCopy(src, dst, sandboxImportCap(res.Manifest, e.Name)); err != nil {
			return fail(fmt.Errorf("%s: %w", e.Name, err))
		}
		files[e.Name] = dst
	}
	return sandboxImportStaged{kind: kind, envelope: env, files: files, version: res.Manifest.ManifestVersion}, nil
}

// sandboxImportCap is the largest size the manifest lists under name.
func sandboxImportCap(m content.Manifest, name string) int64 {
	var c int64
	for _, e := range m.Entries {
		if e.Name == name && e.SizeBytes > c {
			c = e.SizeBytes
		}
	}
	if c > sandboxImportMaxEntry {
		c = sandboxImportMaxEntry
	}
	return c
}

// sandboxImportRead reads a small file without following a link.
func sandboxImportRead(p string, limit int64) ([]byte, error) {
	f, err := openNoFollowAny(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", filepath.Base(p), limit)
	}
	return b, nil
}

// sandboxImportCopy copies a regular file, never a link, streamed under
// limit bytes.
func sandboxImportCopy(src, dst string, limit int64) error {
	in, err := openNoFollowAny(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if fi, err := in.Stat(); err != nil || !fi.Mode().IsRegular() || fi.Size() > limit {
		return fmt.Errorf("not a regular file of at most %d bytes", limit)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fixed name in the fresh staging dir
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(in, limit+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("grew past %d bytes while copied", limit)
	}
	return err
}

// storeNow is the store's clock.
func storeNow(s contentchan.Store) time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// openNoFollowAny opens a regular file and refuses a link at the final
// element on every OS: a no-follow stat, an open, and the same file on both.
func openNoFollowAny(p string) (*os.File, error) {
	before, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(p))
	}
	f, err := os.Open(p) //nolint:gosec // G304: a path under the directory the user named
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = f.Close()
		return nil, fmt.Errorf("%s changed while it was opened", filepath.Base(p))
	}
	return f, nil
}

func newSandboxContentImportCmd() *cobra.Command {
	var (
		cfgPath      string
		debugSet     bool
		debugKeyPath string
	)
	cmd := &cobra.Command{
		Use:   "import <dir>",
		Short: "Install signed sandbox kinds from a directory (offline; verified before anything is installed)",
		Long: "Installs the sandbox kinds found under <dir>, one directory per kind\n" +
			"(<dir>/<kind>/manifest.json and its artifacts, the layout vendorsign writes):\n" +
			"sandbox.image, sandbox.native_files, sandbox.rootfs and sandbox.guest_binary.\n" +
			"Each is verified against the vendor key compiled into this agent, the\n" +
			"store's last accepted version and every file's size and sha256 before any\n" +
			"is installed; a refusal keeps the last-known-good. No network is used.\n\n" +
			"A debug microVM image set (built with deploy/sandbox-vm-image/build.sh --debug,\n" +
			"never shipped) is refused unless both --debug-set and --debug-key name it; it\n" +
			"is then verified against that key alone and boots only under it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, path, err := sandboxContentLoad(cfgPath)
			if err != nil {
				return err
			}
			env := sandboxContentEnvFor(cfg, path)
			debugKey, err := sandboxImportDebugKeyFlag(debugSet, debugKeyPath)
			if err != nil {
				return err
			}
			got, err := sandboxContentImportWith(env.store, env.trust.VendorKeys, args[0], debugKey)
			if err != nil {
				return err
			}
			for _, s := range got {
				fmt.Fprintf(cmd.OutOrStdout(), "%s: installed manifest version %d\n", s.kind, s.version)
				fmt.Fprintln(cmd.OutOrStdout(), "  "+sandboxContentStatusLine(env.store, env.trust, s.kind))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&debugSet, "debug-set", false, "import a debug microVM image set (never shipped; needs --debug-key)")
	cmd.Flags().StringVar(&debugKeyPath, "debug-key", "", "the debug set's public key file (debug-key.pub from vendorsign -debug; needs --debug-set)")
	return cmd
}

// sandboxImportDebugKeyFlag resolves the two debug flags: both or neither.
func sandboxImportDebugKeyFlag(debugSet bool, keyPath string) (ed25519.PublicKey, error) {
	switch {
	case !debugSet && keyPath == "":
		return nil, nil
	case debugSet && keyPath == "":
		return nil, errors.New("sandbox content import: --debug-set needs --debug-key, the debug set's public key")
	case !debugSet:
		return nil, errors.New("sandbox content import: --debug-key is read only with --debug-set")
	}
	b, err := sandboxImportRead(keyPath, 256)
	if err != nil {
		return nil, fmt.Errorf("sandbox content import: read --debug-key: %w", err)
	}
	k, err := parseDebugPublicKey(string(b))
	if err != nil {
		return nil, fmt.Errorf("sandbox content import: --debug-key: %w", err)
	}
	return k, nil
}
