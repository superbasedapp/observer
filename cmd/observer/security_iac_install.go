//go:build !sbo_omit_security

package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_iac_install.go is the IaC engines' guided install (lane
// GATES-SEC decision 3, the Opengrep install's shape): on an individual
// node it downloads the pinned release archive and its sigstore bundle from
// the vendor's GitHub release (the engine's own egress lane) only after the
// developer's one-time size consent for that pin, given on the dashboard or
// the CLI and never by an agent (guard rule R-165); on a managed node it
// installs only from the org mirror's security.engine kind and asks
// nothing. Then: the archive's sha256 against the pin, the signature
// pre-check (Trivy), the one executable extracted from the archive within a
// cap, its digest against the pin when the pin states it, a copy beside the
// install path and a rename, so a half-written binary is never at the
// install path. KICS publishes no release binaries, so its plan is always
// blocked (no_vendor_release).

// iacConsentRecord is the developer's consent file for one engine.
func iacConsentPath(secDir string, id seciac.EngineID) string {
	return filepath.Join(secDir, fmt.Sprintf(iacConsentFileFmt, id))
}

// readIaCConsent reads and verifies the consent record; anything missing,
// unreadable, unsigned or changed reads as not given.
func readIaCConsent(secDir string, id seciac.EngineID) seciac.InstallConsent {
	b, err := iacReadCapped(iacConsentPath(secDir, id), iacMaxRecordBytes)
	if err != nil {
		return seciac.InstallConsent{}
	}
	var c seciac.InstallConsent
	if json.Unmarshal(b, &c) != nil {
		return seciac.InstallConsent{}
	}
	key, err := guardposture.ReadKey(iacRecordKeyPath(secDir))
	if err != nil {
		return c
	}
	c.Verified = guardposture.VerifyRecordMAC(iacConsentDomain, c.Canonical(), key, c.MAC)
	return c
}

// recordIaCConsent signs and writes the consent record.
func recordIaCConsent(secDir string, c seciac.InstallConsent) error {
	key, err := guardposture.LoadOrCreateKey(iacRecordKeyPath(secDir))
	if err != nil {
		return fmt.Errorf("the consent cannot be signed: %w", err)
	}
	c.MAC = guardposture.RecordMAC(iacConsentDomain, c.Canonical(), key)
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return iacWriteFile(iacConsentPath(secDir, c.Engine), b)
}

// iacFulcioRoots overrides the bundle pre-check's trust anchors (tests
// only); nil uses the embedded Sigstore Fulcio pair.
var iacFulcioRoots func() (root, intermediate []byte)

// iacMirror is the org client's mirror fetch (a test seam).
type iacMirror interface {
	InstallSecurityContent(ctx context.Context, st contentchan.Store, kind content.Kind, tr contentchan.Trust) (orgclient.SecurityContentResult, error)
}

// iacOrgMirror opens the org client for a mirror fetch; tests swap it.
var iacOrgMirror = func(ctx context.Context, configPath string) (iacMirror, func(), error) {
	c, cleanup, _, err := buildOrgClient(ctx, configPath)
	if err != nil {
		return nil, nil, err
	}
	return c, cleanup, nil
}

// iacMirrorNamed reports whether the managed pull in force names the org
// mirror (scanner_source = org_mirror), from the verified store; a test
// seam.
var iacMirrorNamed = func(ctx context.Context, cfg config.Config, st *store.Store) bool {
	s, err := securityManagedPersisted(ctx, cfg, st, securityManagedConsent(ctx, st, time.Now()))
	return err == nil && s.Policy != nil && s.Policy.ScannerSource == string(seciac.SourceOrgMirror)
}

// installInput gathers the plan's facts.
func (e *iacEnv) installInput(ctx context.Context) seciac.InstallInput {
	in := seciac.InstallInput{Engine: e.id, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Managed: e.managed, Manifest: e.manifest}
	if allowed := securityFloorsApplied(e.cfg.Security).Deps.ScannerSources; allowed != nil {
		in.SourceAllowed = func(s seciac.InstallSource) bool { return slices.Contains(allowed, string(s)) }
	}
	if e.managed && e.st != nil {
		in.MirrorNamed = iacMirrorNamed(ctx, e.cfg, e.st)
	}
	if st, err := (iacStateStore{path: e.statePath()}).Load(); err == nil {
		in.Revoked = st.Revoked
	}
	if rec := readIaCInstallRecord(e.secDir, e.id); rec != nil {
		if sum, _, err := iacHashRegular(iacInstalledPath(e.id), seciac.MaxBinaryBytes); err == nil && sum == rec.BinarySHA256 {
			in.InstalledArchive = rec.ArchiveSHA256
		}
	}
	return in
}

// errIaCConsentNeeded is an install waiting for the developer.
var errIaCConsentNeeded = errors.New("the engine download waits for your one-time consent")

// installIaCEngine is the one install seam both surfaces call. consent true
// records the developer's consent for the plan's pin (given on surface)
// before the download; false installs only under a consent already given.
func (e *iacEnv) installIaCEngine(ctx context.Context, surface string, consent bool) (seciac.InstallPlan, error) {
	release, ok, err := dblease.TryAcquire(e.secDir, iacInstallLease)
	if err == nil && !ok {
		return seciac.InstallPlan{}, errors.New("another engine install is running")
	}
	defer release()
	if e.managed {
		return e.installFromMirror(ctx)
	}
	plan := seciac.PlanInstall(e.installInput(ctx))
	switch {
	case plan.Blocked != "":
		return plan, fmt.Errorf("the install is blocked: %s", seciac.BlockedWords(e.id, plan.Blocked, runtime.GOOS, runtime.GOARCH))
	case plan.Installed:
		return plan, nil
	}
	if !readIaCConsent(e.secDir, e.id).Covers(plan) {
		if !consent {
			return plan, errIaCConsentNeeded
		}
		c, err := seciac.NewInstallConsent(plan, surface, iacLocalAccount(), time.Now())
		if err != nil {
			return plan, err
		}
		if err := recordIaCConsent(e.secDir, c); err != nil {
			return plan, err
		}
	}
	b, ok := iacBindings[e.id]
	if !ok || b.downloader == nil {
		return plan, errors.New("this engine has no guided download")
	}
	dir := filepath.Dir(iacInstalledPath(e.id))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return plan, err
	}
	archive, err := iacDownloadTo(ctx, b.downloader(), dir, plan.URL, plan.CapBytes, func(digest string, n int64) error {
		return seciac.VerifyArchive(plan, digest, n)
	})
	if err != nil {
		return plan, err
	}
	defer func() { _ = os.Remove(archive) }()
	if eng, _ := seciac.Lookup(e.id); eng.Signature == seciac.SigCosignKeylessBundle {
		var buf limitedBuffer
		buf.limit = seciac.MaxBundleBytes
		if _, _, err := b.downloader().Download(ctx, plan.Bundle, seciac.MaxBundleBytes, &buf); err != nil {
			return plan, fmt.Errorf("the signature bundle download failed: %w", err)
		}
		in := seciac.BundleInput{Engine: e.id, Version: plan.Pin.Version, Digest: plan.Pin.AssetSHA256, Bundle: buf.b}
		if iacFulcioRoots != nil {
			in.RootPEM, in.IntermediatePEM = iacFulcioRoots()
		}
		if _, err := seciac.PrecheckBundle(in); err != nil {
			return plan, err
		}
	}
	return plan, e.placeFromArchive(plan, archive, string(plan.Source))
}

// installFromMirror installs on a managed node: the security.engine kind
// from the org mirror into the content store (a failure keeps the last
// verified one and installs nothing from anywhere else), then that kind's
// archive for this platform, checked, extracted and renamed into place.
func (e *iacEnv) installFromMirror(ctx context.Context) (seciac.InstallPlan, error) {
	in := e.installInput(ctx)
	plan := seciac.PlanInstall(in)
	if plan.Blocked == seciac.BlockManagedNoMirror || plan.Blocked == seciac.BlockSourceNotAllowed {
		return plan, fmt.Errorf("the install is blocked: %s", seciac.BlockedWords(e.id, plan.Blocked, runtime.GOOS, runtime.GOARCH))
	}
	cs := iacContentStore(e.resolved)
	c, cleanup, err := iacOrgMirror(ctx, e.configPath)
	if err != nil {
		return plan, fmt.Errorf("the install is refused: the org mirror could not be reached for the engine, and nothing is installed from any other place: %w", err)
	}
	defer cleanup()
	if _, err := c.InstallSecurityContent(ctx, cs, content.Engine, iacTrust()); err != nil {
		return plan, fmt.Errorf("the install is refused: the org mirror's engine manifest did not install: %w", err)
	}
	e.manifest = loadIaCManifest(cs, iacTrust(), e.id)
	in.Manifest = e.manifest
	plan = seciac.PlanInstall(in)
	switch {
	case plan.Blocked != "":
		return plan, fmt.Errorf("the install is blocked: %s", seciac.BlockedWords(e.id, plan.Blocked, runtime.GOOS, runtime.GOARCH))
	case plan.Installed:
		return plan, nil
	case plan.PinFrom != "manifest":
		return plan, errors.New("the org mirror holds no engine archive for this platform")
	}
	l, err := cs.Load(content.Engine, iacTrust(), 0)
	if err != nil {
		return plan, err
	}
	src, _, err := l.ArtifactPath(plan.Pin.Asset)
	if err != nil {
		return plan, err
	}
	dir := filepath.Dir(iacInstalledPath(e.id))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return plan, err
	}
	f, err := os.Open(src)
	if err != nil {
		return plan, err
	}
	archive, err := iacCopyTo(f, dir, plan.CapBytes, func(digest string, n int64) error { return seciac.VerifyArchive(plan, digest, n) })
	_ = f.Close()
	if err != nil {
		return plan, err
	}
	defer func() { _ = os.Remove(archive) }()
	return plan, e.placeFromArchive(plan, archive, string(plan.Source))
}

// placeFromArchive extracts the pin's executable from a verified archive,
// checks it, places it by rename and records the install.
func (e *iacEnv) placeFromArchive(plan seciac.InstallPlan, archive, source string) error {
	dir := filepath.Dir(iacInstalledPath(e.id))
	bin, digest, n, err := iacExtractMember(archive, plan.Pin.Format, plan.Pin.Member, dir)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(bin) }()
	if err := seciac.VerifyBinary(plan, digest, n); err != nil {
		return err
	}
	if err := os.Chmod(bin, 0o700); err != nil {
		return err
	}
	if err := os.Rename(bin, iacInstalledPath(e.id)); err != nil {
		return err
	}
	return writeIaCInstallRecord(e.secDir, iacInstallFile{
		Engine: string(e.id), Version: plan.Pin.Version, ArchiveSHA256: plan.Pin.AssetSHA256, BinarySHA256: digest, Source: source, At: time.Now().UTC(),
	})
}

// limitedBuffer collects at most limit bytes.
type limitedBuffer struct {
	b     []byte
	limit int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if len(l.b)+len(p) > l.limit {
		return 0, errors.New("over the cap")
	}
	l.b = append(l.b, p...)
	return len(p), nil
}

// iacDownloadTo downloads url into a new temporary file in dir, checks it
// with verify, and returns its path; a failed or refused download leaves
// nothing behind.
func iacDownloadTo(ctx context.Context, d iacDownloader, dir, url string, limit int64, verify func(digest string, n int64) error) (string, error) {
	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	n, digest, derr := d.Download(ctx, url, limit, tmp)
	if cerr := tmp.Close(); derr == nil {
		derr = cerr
	}
	if derr == nil {
		derr = verify(digest, n)
	}
	if derr != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("the download is refused: %w", derr)
	}
	return name, nil
}

// iacCopyTo copies r into a new temporary file in dir while hashing it, at
// most limit bytes, and checks it with verify.
func iacCopyTo(r io.Reader, dir string, limit int64, verify func(digest string, n int64) error) (string, error) {
	tmp, err := os.CreateTemp(dir, ".copy-*")
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, limit+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("over its %d byte cap", limit)
	}
	if err == nil {
		err = verify(hex.EncodeToString(h.Sum(nil)), n)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// iacExtractMember writes the one regular file named member at the
// archive's top level into a new temporary file in dir, at most
// seciac.MaxBinaryBytes, and returns its path, digest and size. A symlink,
// a link or a nested path never counts as the member.
func iacExtractMember(archive, format, member, dir string) (string, string, int64, error) {
	open := func() (io.Reader, func(), error) {
		switch format {
		case seciac.ArchiveTarGz:
			f, err := os.Open(archive)
			if err != nil {
				return nil, nil, err
			}
			gz, err := gzip.NewReader(f)
			if err != nil {
				_ = f.Close()
				return nil, nil, err
			}
			tr := tar.NewReader(gz)
			for {
				h, err := tr.Next()
				if err != nil {
					_ = f.Close()
					return nil, nil, fmt.Errorf("the archive holds no %s", member)
				}
				if h.Name == member && h.Typeflag == tar.TypeReg {
					return tr, func() { _ = f.Close() }, nil
				}
			}
		case seciac.ArchiveZip:
			zr, err := zip.OpenReader(archive)
			if err != nil {
				return nil, nil, err
			}
			for _, zf := range zr.File {
				if zf.Name == member && zf.Mode().IsRegular() {
					rc, err := zf.Open()
					if err != nil {
						_ = zr.Close()
						return nil, nil, err
					}
					return rc, func() { _ = rc.Close(); _ = zr.Close() }, nil
				}
			}
			_ = zr.Close()
			return nil, nil, fmt.Errorf("the archive holds no %s", member)
		}
		return nil, nil, fmt.Errorf("unknown archive format %q", format)
	}
	r, closeFn, err := open()
	if err != nil {
		return "", "", 0, err
	}
	defer closeFn()
	tmp, err := os.CreateTemp(dir, ".extract-*")
	if err != nil {
		return "", "", 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, seciac.MaxBinaryBytes+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > seciac.MaxBinaryBytes {
		err = fmt.Errorf("the extracted %s is over its cap", member)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", "", 0, err
	}
	return tmp.Name(), hex.EncodeToString(h.Sum(nil)), n, nil
}

// iacHashRegular hashes a regular file (never through a symlink) of at
// most limit bytes.
func iacHashRegular(path string, limit int64) (string, int64, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return "", 0, fmt.Errorf("%s is not a regular file within %d bytes", path, limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// iacLocalAccount names the local account a consent is recorded under.
func iacLocalAccount() string {
	for _, k := range []string{"USER", "USERNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
