//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_scan_scalibr && !sbo_omit_security_scan_os

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secimage"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
)

// security_scan_image.go is `observer security scan image` (component
// security.scan.os, phase OS-2 route A, plan sections 6.2, 6.3 and 6.6.1):
// a container image's OS packages, from a `docker save` or OCI-layout tar
// or a root filesystem directory, matched against the image's release
// database in the capped scan child. Manual only: no daemon loop.
//
// One run, in order: hold the dependency scan lease; extract the image's
// allow-listed files with internal/secimage into a run directory OUTSIDE
// ~/.observer (the isolation engine never binds it); map its os-release
// onto a release row (osvdb.ReleaseFor); make the release's database
// available (osReleaseEnsure, lane N1's seam); link it into the run
// directory as osv-scalibr/<Base>/all.zip (osvdb.Store.LinkOSInto); start
// the scan child with depscan.KindOSImage under the child's memory and
// wall caps (depdriver.ScalibrLimits), isolated when a provider exists;
// record the run through secsvc.RecordRun (the one writer); close the open
// findings of the same image a full scan no longer reports; remember the
// image's package inventory by digest (image-scan-inventory.json).
//
// An image's findings live under the project key "image:<digest>", so only
// a full scan of the same image digest by the same driver closes them (the
// secscan.Coverage.Scanned rule); the location is the Dockerfile's last
// FROM line when --dockerfile names it, else the image file.

// imageComponent is the image scan's component.
const imageComponent = "security.scan.os"

// imageInventoryFile is the node-local record of scanned images' OS
// package inventories (plan 6.3 "Rescans on new data"), beside
// deps-scan-last.json.
const imageInventoryFile = "image-scan-inventory.json"

// Bounds of the inventory record.
const (
	imageInventoryMaxImages   = 64
	imageInventoryMaxPackages = 20_000
)

// osReleaseEnsure makes a release's database available and returns its
// epoch, or a fixed reason (depscan.ReasonDBNotAccepted, ReasonNoDatabase,
// ReasonFeedUnavailable, ReasonReleaseNotPublished): lane N1's fetch,
// ensureOSRelease. A test swaps it.
var osReleaseEnsure = ensureOSRelease

// imageChildRun starts the scan child (a test swaps it for the in-process
// child: a test binary is not observer).
var imageChildRun = func(ctx context.Context, runner *extrun.Runner, req extrun.Request) extrun.Result {
	return runner.Run(ctx, req)
}

// newSecurityScanImageCmd is `observer security scan image`.
func newSecurityScanImageCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "image <tar|dir>",
		Short: "Scan a container image's OS packages for known vulnerabilities (component security.scan.os)",
		Long: "Reads a container image's OS packages (dpkg, apk, rpm) from a `docker save` or OCI-layout tar, or\n" +
			"from a root filesystem directory, with no daemon and no registry, and matches them in the scan child\n" +
			"against the image's release database (Debian, Ubuntu LTS, Alpine, Red Hat, Rocky). A release with no\n" +
			"database, no self-test or a failed self-test is reported \"not scanned\", never clean. Kernel packages\n" +
			"are left out (a container does not run its own kernel) and named.\n\n" + OSVAttribution,
		Args: cobra.ExactArgs(1),
		RunE: runSecurityScanImageCmd,
	}
	c.Flags().String("dockerfile", "", "the Dockerfile that built the image: findings point at its FROM line")
	c.Flags().Bool("json", false, "print the result as JSON")
	return c
}

func runSecurityScanImageCmd(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	dockerfile, _ := cmd.Flags().GetString("dockerfile")
	asJSON, _ := cmd.Flags().GetBool("json")
	in, err := filepath.Abs(args[0])
	if err != nil {
		return err
	}
	if _, err := os.Stat(in); err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	ctx := cmd.Context()
	e, err := openDepsScanEnv(ctx, configPath)
	if err != nil {
		return err
	}
	defer e.cleanup()
	if err := requireImageScanSelected(e); err != nil {
		return err
	}
	rep, err := e.scanImage(ctx, in, dockerfile, func() {
		fmt.Fprintln(cmd.ErrOrStderr(), "waiting for another dependency scan (the daemon's or another command's) to finish...")
	})
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	if asJSON {
		return writeSecurityJSON(w, map[string]any{"results": []imageScanReport{rep}, "attribution": OSVAttribution})
	}
	writeImageScanReport(w, rep)
	fmt.Fprintf(w, "\n%s\n", OSVAttribution)
	return nil
}

// requireImageScanSelected refuses the verb when security.scan.os, or what
// it needs, is not selected.
func requireImageScanSelected(e *depsScanEnv) error {
	snap := componentSnapshotForConfig(e.cfg)
	for _, id := range []string{imageComponent, depscan.ScalibrComponent, securityDepsComponent} {
		if !securitySelected(snap, id) {
			return fmt.Errorf("%s is not selected: add %s (with %s and %s) under [components] in your config",
				id, imageComponent, depscan.ScalibrComponent, securityDepsComponent)
		}
	}
	return nil
}

// imageProjectKey is the project key an image's runs and findings live
// under: its digest, or, when the image could not be read far enough to
// have one, its path's hash.
func imageProjectKey(digest, abs string) string {
	if digest != "" {
		return "image:" + digest
	}
	return "image:" + secimage.DirDigest(abs)
}

// releaseForImage maps an image's os-release onto its release row, or a
// fixed reason it cannot.
func releaseForImage(osr map[string]string) (osvdb.OSRelease, string) {
	id := strings.ToLower(strings.TrimSpace(osr["ID"]))
	if id == "" {
		return osvdb.OSRelease{}, depscan.ReasonNoOSRelease
	}
	if r, ok := osvdb.ReleaseFor(id, osr["VERSION_ID"]); ok {
		return r, ""
	}
	for _, r := range osvdb.OSReleases {
		if r.Distro == id {
			return osvdb.OSRelease{}, depscan.ReasonReleaseNotSupported
		}
	}
	return osvdb.OSRelease{}, depscan.ReasonDistroNotSupported
}

// imageRun is one prepared run directory.
type imageRun struct {
	dir, root, db, out, cache string
}

func newImageRun() (imageRun, error) {
	base, err := depsScanCacheRoot()
	if err != nil {
		return imageRun{}, err
	}
	runs := filepath.Join(base, "runs")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		return imageRun{}, err
	}
	dir, err := os.MkdirTemp(runs, "image-")
	if err != nil {
		return imageRun{}, err
	}
	r := imageRun{dir: dir, root: filepath.Join(dir, "root"), db: filepath.Join(dir, "db"), out: filepath.Join(dir, "out"), cache: filepath.Join(dir, "cache")}
	for _, d := range []string{r.root, r.db, r.out, r.cache} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			_ = os.RemoveAll(dir)
			return imageRun{}, err
		}
	}
	return r, nil
}

// readImage extracts the allow-listed files of the image at in (a tar or
// a directory) into run.root.
func readImage(in string, run imageRun) (secimage.Result, error) {
	sink, err := secimage.NewDirSink(run.root)
	if err != nil {
		return secimage.Result{}, err
	}
	defer sink.Close()
	fi, err := os.Stat(in) //nolint:gosec // G703: the image path the user named on the command line
	if err != nil {
		return secimage.Result{}, err
	}
	if fi.IsDir() {
		r, err := os.OpenRoot(in)
		if err != nil {
			return secimage.Result{}, err
		}
		defer r.Close()
		res, err := secimage.ReadRoot(r.FS(), sink, secimage.DefaultLimits())
		res.Digest = secimage.DirDigest(in)
		return res, err
	}
	f, err := os.Open(in) //nolint:gosec // G703: the image path the user named on the command line; only read
	if err != nil {
		return secimage.Result{}, err
	}
	defer f.Close()
	return secimage.Flatten(f, fi.Size(), sink, secimage.DefaultLimits())
}

// scanImage runs one image scan and records it (file comment).
func (e *depsScanEnv) scanImage(ctx context.Context, in, dockerfile string, onWait func()) (imageScanReport, error) {
	rep := imageScanReport{Image: in, Component: imageComponent}
	loc, err := imageLocationFor(in, dockerfile)
	if err != nil {
		return rep, err
	}
	release, err := e.acquireDepsScan(ctx, true, onWait)
	if err != nil {
		return rep, err
	}
	defer release()
	started := time.Now()
	run, err := newImageRun()
	if err != nil {
		return rep, fmt.Errorf("security scan image: run directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(run.dir) }()
	engine := secscan.EngineIdentity{Name: depscan.ScalibrID, Version: depscan.SCALIBRVersion}
	img, rerr := readImage(in, run)
	rep.Digest = img.Digest
	t := secscan.Target{Scope: policy.FindingScopeManual, ProjectRoot: imageProjectKey(img.Digest, in)}
	notScanned := func(eco, reason string, failed bool, notes []string) secscan.Result {
		resp := depscan.ChildResponse{}
		if eco != "" {
			resp.Ecosystems = []depscan.EcoResult{{Ecosystem: eco, Outcome: depscan.EcoNotScanned, Reason: reason}}
		}
		return depdriver.Result(depdriver.Input{DriverID: depscan.ScalibrID, Target: t, Engine: engine, Response: resp, RunReason: reason, Failed: failed, Notes: notes})
	}
	var res secscan.Result
	var inv []depscan.Package
	var epoch string
	r, why := releaseForImage(img.OSRelease)
	switch {
	case rerr != nil:
		res = notScanned("", secimage.ReasonOf(rerr), false, nil)
	case why != "":
		res = notScanned("", why, false, nil)
	default:
		label := releaseLabel(r)
		rep.Release = label
		notes := depscan.OSReleaseNotes(r.FixedOnly, r.KnownGap)
		var reason string
		epoch, reason = osReleaseEnsure(ctx, e, r)
		if reason != "" {
			res = notScanned(label, reason, false, notes)
			break
		}
		if err := e.db.LinkOSInto(run.db, r); err != nil {
			res = notScanned(label, depscan.ReasonDatabaseLinkFailed, true, notes)
			break
		}
		res, inv = e.runImageChild(ctx, run, r, label, epoch, img, loc, t, engine, notes)
	}
	if res.Engine.Name == "" {
		res.Engine.Name = depscan.ScalibrID
	}
	if _, err := secsvc.RecordRun(ctx, e.st, t, res, started, time.Since(started), secsvc.Gone{}, securityRT.notify); err != nil {
		return rep, err
	}
	e.closeStaleImageFindings(ctx, t, res)
	if len(inv) > 0 && img.Digest != "" {
		if err := e.rememberImageInventory(img.Digest, rep.Release, r.Artifact, epoch, inv, time.Now()); err != nil {
			e.logger.Debug("security: could not record the image inventory", "err", err)
		}
	}
	rep.Result = res
	return rep, nil
}

// runImageChild runs the scan child over the extracted root and builds the
// result; it also returns the image's OS packages for the inventory.
func (e *depsScanEnv) runImageChild(ctx context.Context, run imageRun, r osvdb.OSRelease, label, epoch string, img secimage.Result, loc imageLocation, t secscan.Target, engine secscan.EngineIdentity, notes []string) (secscan.Result, []depscan.Package) {
	fail := func(reason string, extra []string) (secscan.Result, []depscan.Package) {
		return depdriver.Result(depdriver.Input{DriverID: depscan.ScalibrID, Target: t, Engine: engine, Failed: true, RunReason: reason, Notes: append(notes, extra...)}), nil
	}
	exe, err := depsSelfExecutable()
	if err != nil {
		return fail(depscan.ReasonEngineFailed, nil)
	}
	childRoot, dbDir := run.root, run.db
	if v, err := filepath.EvalSymlinks(childRoot); err == nil {
		childRoot = v
	}
	if v, err := filepath.EvalSymlinks(dbDir); err == nil {
		dbDir = v
	}
	child := depscan.ChildRequest{
		Version: depscan.ProtocolVersion, Kind: depscan.KindOSImage, Root: childRoot, DBDir: dbDir, GOOS: runtime.GOOS,
		OS: &depscan.OSImageRequest{Ecosystem: label, Base: r.Base, RPM: r.RPM, Epoch: epoch},
	}
	req, err := depdriver.ScalibrRequest(exe, childRoot, child)
	if err != nil {
		return fail(depscan.ReasonEngineFailed, nil)
	}
	runner, isoNotes, refused := e.imageRunner(run, childRoot, dbDir)
	if refused {
		return fail(depscan.ReasonIsolationRefused, nil)
	}
	out := imageChildRun(ctx, runner, req)
	if out.Outcome == extrun.OutcomeRefused && out.Reason == extrun.RefuseIsolationFailed {
		return fail(depscan.ReasonIsolationRefused, nil)
	}
	if out.Digests.Binary != "" {
		engine.Digest = out.Digests.Binary
	}
	notes = append(notes, isoNotes...)
	resp, perr := depdriver.ParseChild(out)
	if perr != nil {
		return fail(imageFailReason(out), nil)
	}
	if resp.Kind != depscan.KindOSImage {
		// A child that read the request as a project scan answered for
		// something else: nothing it said is about this image.
		return fail(depscan.ReasonEngineFailed, nil)
	}
	for i := range resp.Packages {
		resp.Packages[i].Path, resp.Packages[i].Line = loc.RelPath, loc.Line
	}
	for _, p := range img.RefusedWanted {
		resp.Gaps = append(resp.Gaps, depscan.Gap{Ecosystem: label, Path: p, Reason: depscan.ReasonImageEntryRefused})
	}
	runReason := ""
	if len(resp.Packages) == 0 && len(resp.Ecosystems) == 0 && len(resp.Gaps) == 0 {
		runReason = depscan.ReasonNoImagePackages
	}
	if n := depscan.KernelNote(resp.Packages); n != "" {
		notes = append(notes, n)
	}
	res := depdriver.Result(depdriver.Input{DriverID: depscan.ScalibrID, Target: t, Engine: engine, Response: resp, RunReason: runReason, Notes: notes})
	return res, depscan.SortedOSPackages(resp.Packages)
}

// imageRunner returns the runner for the image child: isolated when a
// provider exists (the run directory's root and database bound
// read-only), else plain with the SECP-8 note. refused: a provider exists
// but could not be built, and the scan does not fall back to an
// unisolated run.
func (e *depsScanEnv) imageRunner(run imageRun, root, db string) (*extrun.Runner, []string, bool) {
	plain := func() (*extrun.Runner, []string, bool) {
		return extrunhost.NewRunner(extrunhost.Options{}), []string{depscan.NotIsolatedPrefix + ": the scan child ran with network access (ledger SECP-8): no isolation provider is available on this host."}, false
	}
	factory := isolationFactoryFor(componentSnapshotForConfig(e.cfg), filepath.Dir(e.dir), nil)
	if factory == nil || !scanIsolationAvailable() {
		return plain()
	}
	prov, err := factory(extrun.OneShotDirs{Project: root, Output: run.out, Cache: run.cache, ProgramDirs: []string{db}})
	switch {
	case err != nil && isolationMissingOnHost(err):
		return plain()
	case err != nil:
		return nil, nil, true
	}
	return extrunhost.NewRunner(extrunhost.Options{Isolation: prov}), nil, false
}

// imageFailReason is the closed reason of a child that did not answer.
func imageFailReason(run extrun.Result) string {
	switch run.Outcome {
	case extrun.OutcomeTimeout, extrun.OutcomeOutputCap, extrun.OutcomeChildrenCap:
		return "budget_exceeded"
	case extrun.OutcomeRefused:
		return "driver_unverified"
	case extrun.OutcomeCanceled:
		return "canceled"
	}
	return depscan.ReasonEngineFailed
}

// closeStaleImageFindings closes the open findings of the same image that
// a full scan of its release no longer reports (hold-aware, like scanOne);
// a not-scanned or partial release closes nothing.
func (e *depsScanEnv) closeStaleImageFindings(ctx context.Context, t secscan.Target, res secscan.Result) {
	switch res.Coverage.Outcome {
	case secscan.OutcomeFindings, secscan.OutcomeClean, secscan.OutcomeUnknown:
	default:
		return
	}
	open, err := e.openDepFindings(ctx, secposture.ProjectRootHash(t.ProjectRoot))
	if err != nil {
		return
	}
	for _, id := range depscan.StaleFindings(open, depscan.ScalibrID, res.Findings, depscan.ScannedEcosystems(res.Coverage)) {
		_, _ = e.st.CloseSecFindingNotReproduced(ctx, id, time.Now())
	}
}

// imageInventory is one scanned image's OS package inventory: metadata
// about the developer's own image (release, package names and versions),
// never content, never on the org wire.
type imageInventory struct {
	At       time.Time         `json:"at"`
	Release  string            `json:"release"`
	Artifact string            `json:"artifact"`
	Epoch    string            `json:"epoch,omitempty"`
	Packages []depscan.Package `json:"packages"`
}

func (e *depsScanEnv) imageInventoryPath() string { return filepath.Join(e.dir, imageInventoryFile) }

// loadImageInventories reads the record; a missing or unreadable file is
// no record.
func (e *depsScanEnv) loadImageInventories() map[string]imageInventory {
	out := map[string]imageInventory{}
	b, err := os.ReadFile(e.imageInventoryPath())
	if err != nil || json.Unmarshal(b, &out) != nil {
		return map[string]imageInventory{}
	}
	return out
}

// rememberImageInventory records one image's inventory by digest, keeping
// the newest imageInventoryMaxImages images, and writes the file
// atomically. Its one writer, under the scan lease.
func (e *depsScanEnv) rememberImageInventory(digest, release, artifact, epoch string, pkgs []depscan.Package, now time.Time) error {
	if len(pkgs) > imageInventoryMaxPackages {
		pkgs = pkgs[:imageInventoryMaxPackages]
	}
	m := e.loadImageInventories()
	m[digest] = imageInventory{At: now.UTC(), Release: release, Artifact: artifact, Epoch: epoch, Packages: pkgs}
	if len(m) > imageInventoryMaxImages {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return m[keys[i]].At.After(m[keys[j]].At) })
		for _, k := range keys[imageInventoryMaxImages:] {
			delete(m, k)
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return err
	}
	tmp := e.imageInventoryPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, e.imageInventoryPath()); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
