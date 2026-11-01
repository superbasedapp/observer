//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
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
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep/opengrepnet"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_opengrep_install.go is the guided install of the Opengrep engine
// (security pillar plan section 8.1, lane SEC-G2 milestone 1): the one seam
// both the dashboard's install dialog and `observer security code install`
// call. On an individual node it downloads the pinned release from the
// vendor's GitHub release (the opengrepnet egress lane) only after the
// developer's one-time size consent for that pin, given on one of those two
// surfaces and never by an agent (guard rule R-165); a pin change asks
// again. On a managed node it installs only from the org mirror's
// security.engine kind, never from the public release (case X19), and asks
// nothing. Either way: the sha256 against the pin, then secengine's
// decision table, then a copy into the scanner directory and a rename, so
// a half-written binary is never at the install path.

// The guided install's files.
const (
	// codeInstallConsentFile is the developer's consent record (security
	// directory), signed under the posture key.
	codeInstallConsentFile = "opengrep-install-consent.json"
	// codeInstallStateFile records the last install (security directory).
	codeInstallStateFile = "opengrep-install.json"
	// codeInstallLeaseName holds one install at a time per machine.
	codeInstallLeaseName = "code-install"
	// codeInstallConsentDomain separates the record's MAC from every other
	// use of the posture key.
	codeInstallConsentDomain = "sbo-opengrep-install-consent-v1"
)

// codeBinDir is the guided install's directory: beside the engine's own
// cache, outside ~/.observer (the isolation engine never binds it).
func codeBinDir() (string, error) {
	root, err := codeScanRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "bin"), nil
}

// codeInstalledPath is where the guided install puts the engine.
func codeInstalledPath() string {
	dir, err := codeBinDir()
	if err != nil {
		return ""
	}
	name := "opengrep"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(dir, name)
}

// codeRecordKeyPath is the posture key beside the global config, the
// security directory's parent (the key the scanners' accept records use).
func codeRecordKeyPath(secDir string) string {
	return filepath.Join(filepath.Dir(secDir), guardposture.KeyFilename)
}

// readCodeInstallConsent reads and verifies the consent record; anything
// missing, unreadable, unsigned or changed reads as not given.
func readCodeInstallConsent(secDir string) secengine.InstallConsent {
	b, err := readCappedFile(filepath.Join(secDir, codeInstallConsentFile), 4096)
	if err != nil {
		return secengine.InstallConsent{}
	}
	var c secengine.InstallConsent
	if json.Unmarshal(b, &c) != nil {
		return secengine.InstallConsent{}
	}
	key, err := guardposture.ReadKey(codeRecordKeyPath(secDir))
	if err != nil {
		return c
	}
	c.Verified = guardposture.VerifyRecordMAC(codeInstallConsentDomain, c.Canonical(), key, c.MAC)
	return c
}

// recordCodeInstallConsent signs and writes the consent record atomically.
func recordCodeInstallConsent(secDir string, c secengine.InstallConsent) (secengine.InstallConsent, error) {
	key, err := guardposture.LoadOrCreateKey(codeRecordKeyPath(secDir))
	if err != nil {
		return c, fmt.Errorf("the consent cannot be signed: %w", err)
	}
	c.MAC = guardposture.RecordMAC(codeInstallConsentDomain, c.Canonical(), key)
	b, err := json.Marshal(c)
	if err != nil {
		return c, err
	}
	if err := writeCodeFile(filepath.Join(secDir, codeInstallConsentFile), b); err != nil {
		return c, err
	}
	c.Verified = true
	return c, nil
}

// writeCodeFile writes a node-local file of the code rules atomically, 0600.
func writeCodeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-code-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, 0o600)
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		_ = os.Remove(name)
	}
	return werr
}

// codeInstallState is the last install's record.
type codeInstallState struct {
	Version string    `json:"version"`
	SHA256  string    `json:"sha256"`
	Source  string    `json:"source"`
	At      time.Time `json:"at"`
}

func readCodeInstallState(secDir string) (codeInstallState, bool) {
	var s codeInstallState
	b, err := readCappedFile(filepath.Join(secDir, codeInstallStateFile), 4096)
	if err != nil || json.Unmarshal(b, &s) != nil {
		return codeInstallState{}, false
	}
	return s, true
}

// codeDownloader is the release download of the egress lane (a test seam).
type codeDownloader interface {
	Download(ctx context.Context, url string, limit int64, w io.Writer) (int64, string, error)
}

// codeInstallNet returns the release download client; tests swap it.
var codeInstallNet = func() codeDownloader { return opengrepnet.New(opengrepnet.Options{}) }

// codeMirrorInstaller is the org client's mirror fetch (a test seam).
type codeMirrorInstaller interface {
	InstallSecurityContent(ctx context.Context, st contentchan.Store, kind content.Kind, tr contentchan.Trust) (orgclient.SecurityContentResult, error)
}

// codeOrgMirror opens the org client for a mirror fetch; tests swap it.
var codeOrgMirror = func(ctx context.Context, configPath string) (codeMirrorInstaller, func(), error) {
	c, cleanup, _, err := buildOrgClient(ctx, configPath)
	if err != nil {
		return nil, nil, err
	}
	return c, cleanup, nil
}

// codeMirrorNamedFor reports whether the managed pull in force names the
// org mirror (scanner_source = org_mirror), read from the verified store.
var codeMirrorNamedFor = func(ctx context.Context, cfg config.Config, st *store.Store) bool {
	s, err := securityManagedPersisted(ctx, cfg, st, securityManagedConsent(ctx, st, time.Now()))
	return err == nil && s.Policy != nil && s.Policy.ScannerSource == string(secengine.SourceOrgMirror)
}

// codeSourceAllowed reads the floors' allow.scanner_sources (no floor
// allows every source).
func codeSourceAllowed(sc config.SecurityConfig) func(secengine.InstallSource) bool {
	allowed := securityFloorsApplied(sc).Deps.ScannerSources
	if allowed == nil {
		return nil
	}
	return func(s secengine.InstallSource) bool { return slices.Contains(allowed, string(s)) }
}

// installInput gathers the plan's facts.
func (e *codeEnv) installInput(ctx context.Context) secengine.InstallInput {
	in := secengine.InstallInput{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Managed: e.managed, Manifest: e.manifest,
		SourceAllowed: codeSourceAllowed(e.cfg.Security), Pending: e.pendingEngine(),
	}
	if e.managed && e.st != nil {
		in.MirrorNamed = codeMirrorNamedFor(ctx, e.cfg, e.st)
	}
	if st, err := (codeStateStore{path: filepath.Join(e.secDir, codeStateFile)}).Load(); err == nil {
		in.Revoked = st.Revoked
	}
	if p := codeInstalledPath(); p != "" {
		if sum, err := cachedRegularFileDigest(p, secengine.MaxDownloadBytes); err == nil {
			in.InstalledDigest = sum
		}
	}
	return in
}

// hashRegularFile hashes a regular file (never through a symlink) of at
// most limit bytes.
func hashRegularFile(path string, limit int64) (string, int64, error) {
	fi, err := os.Lstat(path) //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
	if err != nil {
		return "", 0, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return "", 0, fmt.Errorf("%s is not a regular file within %d bytes", path, limit)
	}
	f, err := os.Open(path) //nolint:gosec // G703: reads the user's own local file with the user's own rights
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, limit+1))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// codeInstallJob is the daemon's one in-flight dashboard install (one owner
// of its state): the dialog starts it and the card polls it.
var codeInstallJob struct {
	mu      sync.Mutex
	running bool
	lastErr string
	doneAt  time.Time
}

// codeInstallSurface names the two places a consent may be given.
const (
	codeSurfaceCLI       = "cli"
	codeSurfaceDashboard = "dashboard"
)

// errCodeConsentNeeded is an install that waits for the developer.
var errCodeConsentNeeded = errors.New("the Opengrep download waits for your one-time consent")

// installEngine is the one install seam. consent true records the
// developer's consent for the plan's pin (given on surface) before the
// download; false installs only under a consent already given.
func (e *codeEnv) installEngine(ctx context.Context, surface string, consent bool) (secengine.InstallPlan, error) {
	release, ok, err := dblease.TryAcquire(e.secDir, codeInstallLeaseName)
	if err == nil && !ok {
		return secengine.InstallPlan{}, errors.New("another Opengrep install is running")
	}
	defer release()
	if e.managed {
		return e.installFromMirror(ctx)
	}
	plan := secengine.PlanInstall(e.installInput(ctx))
	switch {
	case plan.Blocked != "":
		return plan, fmt.Errorf("the install is blocked: %s", codeBlockedWords(plan.Blocked))
	case plan.Installed:
		return plan, nil
	}
	if !readCodeInstallConsent(e.secDir).Covers(plan) {
		if !consent {
			return plan, errCodeConsentNeeded
		}
		c, err := secengine.NewInstallConsent(plan, surface, depsLocalAccountName(), time.Now())
		if err != nil {
			return plan, err
		}
		if _, err := recordCodeInstallConsent(e.secDir, c); err != nil {
			return plan, err
		}
	}
	dir, err := codeBinDir()
	if err != nil {
		return plan, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return plan, err
	}
	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return plan, err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	n, digest, derr := codeInstallNet().Download(ctx, plan.URL, plan.CapBytes, tmp)
	if cerr := tmp.Close(); derr == nil {
		derr = cerr
	}
	if derr != nil {
		return plan, fmt.Errorf("the download failed: %w", derr)
	}
	if _, err := secengine.VerifyDownload(plan, digest, n, runtime.GOOS, runtime.GOARCH, false); err != nil {
		return plan, err
	}
	if err := e.acceptPendingEngine(plan, name); err != nil {
		return plan, err
	}
	if err := placeEngine(name, codeInstalledPath()); err != nil {
		return plan, err
	}
	e.recordInstall(plan, digest)
	return plan, nil
}

// installFromMirror installs on a managed node: the security.engine kind
// from the org mirror into the content channel (a failure keeps the last
// verified one), then that kind's artifact for this platform, copied out
// of the channel, checked and renamed into place.
func (e *codeEnv) installFromMirror(ctx context.Context) (secengine.InstallPlan, error) {
	in := e.installInput(ctx)
	plan := secengine.PlanInstall(in)
	if plan.Blocked == secengine.BlockManagedNoMirror || plan.Blocked == secengine.BlockSourceNotAllowed {
		return plan, fmt.Errorf("the install is blocked: %s", codeBlockedWords(plan.Blocked))
	}
	cs := codeRulesStore(e.resolved)
	if ferr := e.fetchMirror(ctx, cs, []content.Kind{content.Engine}); ferr != nil {
		// The engine comes from the mirror or not at all (case X19): a failed
		// fetch never falls back to an earlier manifest's bytes in the local
		// content store (lane SEC-G2 audit finding 6).
		plan.Blocked = codeBlockMirrorFetch
		return plan, errors.Join(fmt.Errorf("the install is refused: %s", codeBlockedWords(codeBlockMirrorFetch)), ferr)
	}
	e.manifest = loadEngineManifest(cs, codeRulesTrust())
	in.Manifest = e.manifest
	plan = secengine.PlanInstall(in)
	switch {
	case plan.Blocked != "":
		return plan, fmt.Errorf("the install is blocked: %s", codeBlockedWords(plan.Blocked))
	case plan.Installed:
		return plan, nil
	case plan.PinFrom != secengine.PinFromManifest:
		return plan, errors.New("the org mirror holds no Opengrep engine for this platform")
	}
	l, err := cs.Load(content.Engine, codeRulesTrust(), 0)
	if err != nil {
		return plan, err
	}
	src, _, err := l.ArtifactPath(plan.Pin.Asset)
	if err != nil {
		return plan, err
	}
	dir, err := codeBinDir()
	if err != nil {
		return plan, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return plan, err
	}
	tmp, n, digest, err := copyHashed(src, dir, plan.CapBytes)
	if err != nil {
		return plan, err
	}
	defer func() { _ = os.Remove(tmp) }()
	if _, err := secengine.VerifyDownload(plan, digest, n, runtime.GOOS, runtime.GOARCH, true); err != nil {
		return plan, err
	}
	if err := placeEngine(tmp, codeInstalledPath()); err != nil {
		return plan, err
	}
	e.recordInstall(plan, digest)
	return plan, nil
}

// fetchMirror installs kinds from the org mirror into cs; any failure
// keeps each kind's last-known-good and is returned.
func (e *codeEnv) fetchMirror(ctx context.Context, cs contentchan.Store, kinds []content.Kind) error {
	c, cleanup, err := codeOrgMirror(ctx, e.configPath)
	if err != nil {
		recordCodeFetch(e.secDir, kinds, "org_mirror", err)
		return fmt.Errorf("org mirror: %w", err)
	}
	defer cleanup()
	var errs []error
	for _, k := range kinds {
		_, err := c.InstallSecurityContent(ctx, cs, k, codeRulesTrust())
		recordCodeFetch(e.secDir, []content.Kind{k}, "org_mirror", err)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s from the org mirror: %w", k, err))
		}
	}
	return errors.Join(errs...)
}

// copyHashed copies src into a new temporary file in dir while hashing it,
// at most limit bytes.
func copyHashed(src, dir string, limit int64) (string, int64, string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", 0, "", err
	}
	defer func() { _ = in.Close() }()
	tmp, err := os.CreateTemp(dir, ".copy-*")
	if err != nil {
		return "", 0, "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(in, limit+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("%s is over its %d byte cap", src, limit)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", 0, "", err
	}
	return tmp.Name(), n, hex.EncodeToString(h.Sum(nil)), nil
}

// placeEngine makes the checked temporary file executable and renames it
// over the install path (same directory, so the rename is atomic).
func placeEngine(tmp, dst string) error {
	if dst == "" {
		return errors.New("no install path")
	}
	if err := os.Chmod(tmp, 0o700); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// recordInstall writes the last install's record (best effort: the driver
// decides on the binary's own digest at every run).
func (e *codeEnv) recordInstall(plan secengine.InstallPlan, digest string) {
	b, err := json.Marshal(codeInstallState{Version: plan.Pin.Version, SHA256: digest, Source: string(plan.Source), At: time.Now().UTC()})
	if err == nil {
		_ = writeCodeFile(filepath.Join(e.secDir, codeInstallStateFile), b)
	}
}

// codeBlockMirrorFetch is a managed install refused because the org
// mirror's fetch failed (the cmd layer's own reason beside secengine's).
const codeBlockMirrorFetch = "mirror_fetch_failed"

// codeBlockedWords is the plain sentence of a blocked reason.
func codeBlockedWords(reason string) string {
	switch reason {
	case codeBlockMirrorFetch:
		return "this is a managed node and its org mirror could not be reached for the engine; nothing is installed from any other place (" + reason + ")"
	case secengine.BlockManagedNoMirror:
		return "this is a managed node: its engine comes only from the org mirror, and the managed pull in force does not name it (" + reason + ")"
	case secengine.BlockSourceNotAllowed:
		return "the org's floors do not allow this source for scanners (" + reason + ")"
	case secengine.BlockPinOwed:
		return "no verified pin exists for " + runtime.GOOS + "/" + runtime.GOARCH + " yet (" + reason + "); install Opengrep yourself, it then runs labelled unverified on an individual node"
	case secengine.BlockRevoked:
		return "the pinned engine was revoked (" + reason + ")"
	}
	return reason
}

// depsLocalAccountName names the local account a consent is recorded
// under ("" when unknown); the same reading as the scanners' accept.
func depsLocalAccountName() string {
	for _, k := range []string{"USER", "USERNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
