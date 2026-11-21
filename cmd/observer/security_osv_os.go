//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvnet"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_osv_os.go is the node side of the OS release databases (OS and
// CI vulnerability scanning plan sections 6.4 and 6.6.1, phase OS-2 lane
// N1): the security.osv_os_export content kind, one stripped per-release
// export per row of osvdb.OSReleases, installed into the store's osv-os
// layout (osvdb osstore.go) where the image scan's matcher reads it.
//
// Unlike the language exports nothing is fetched until an image needs a
// release: ensureOSRelease, which the image scan calls before a scan, takes
// ONLY that release's artifacts (its base "<Artifact>.zip" and, when the
// publisher cut one, its cumulative delta "<Artifact>.delta.zip": the subset
// rule, osReleaseEntries), verifies them exactly as the content channel
// verifies a feed set (the manifest's signature, rollback, epoch and expiry
// against this kind's own high-water mark, then every artifact's exact size
// and digest), merges base and delta (osvdb.MergeExportZip, the record count
// checked against the signed entry) and installs the result
// (osvdb.Store.InstallOS). Where it comes from:
//
//   - a managed node takes the kind from its org mirror only, and only while
//     its managed pull names the mirror (the language rule, row 1 of
//     osvdb.SourcePlan);
//   - an individual node takes it from SuperBased's signed mirror on
//     superbased.app only, after the one OS accept (osvdb.OSConsent, ruling
//     Q1 (b)), through the security.scan.osv.db lane's client (osvnet, the
//     same host allow-list); there is no bucket fallback for OS databases
//     (section 6.6.1 change 2), and db_source = import or upstream fetches no
//     OS database at all.
//
// A release it cannot serve answers one fixed reason (osReason*), never an
// error's own text. The daemon's 6-hourly database refresh also refreshes
// the releases already installed (never a new one); a failed refresh keeps
// the last-known-good.

// osvOSKind is the OS release databases' content kind.
const osvOSKind = content.OSVOSExport

// The fixed reasons ensureOSRelease answers when it cannot serve a release.
const (
	// osReasonNotAccepted: an individual node whose developer has not given
	// the OS accept.
	osReasonNotAccepted = depscan.ReasonDBNotAccepted
	// osReasonMissing: no database here and none may be fetched (a managed
	// node whose pull does not name the mirror or whose mirror holds
	// nothing, a source the floors do not allow, db_source = import or
	// upstream).
	osReasonMissing = depscan.ReasonNoDatabase
	// osReasonFeedUnavailable: the signed mirror (or the org mirror) could
	// not be reached, or what it served did not verify.
	osReasonFeedUnavailable = "feed_unavailable"
	// osReasonNotPublished: the verified set does not carry this release.
	osReasonNotPublished = "release_not_published"
)

// osvOSMu holds one OS database operation at a time in this process.
var osvOSMu sync.Mutex

// osvOSDefaultFloor is the age floor of an OS release's data when the kind
// row carries none (the language exports' floor).
const osvOSDefaultFloor = 14 * 24 * time.Hour

// osSettingFetchesNothing reports a [security.deps] db_source under which no
// OS database is fetched: import fetches nothing, and upstream names the
// OSV bucket, which serves no OS release (section 6.6.1 change 2).
func osSettingFetchesNothing(setting string) bool {
	return setting == osvdb.SettingImport || setting == osvdb.SettingUpstream
}

// osFetchGate is the gate in front of an OS release fetch, walked top down;
// the first closed row's reason is the answer.
var osFetchGate = depsGate{
	{osReasonMissing, func(e *depsScanEnv) bool { return e.managed && !e.mirror }},
	{osReasonMissing, func(e *depsScanEnv) bool { return !depsScannerSourceAllowed(e.cfg.Security, e.dbSource()) }},
	{osReasonNotAccepted, func(e *depsScanEnv) bool { return !e.managed && !e.osConsent.Accepted() }},
	{osReasonMissing, func(e *depsScanEnv) bool { return !e.managed && osSettingFetchesNothing(e.dbSetting()) }},
	// The publisher signs the kind with the content-feed key only: with
	// none compiled in nothing can verify, so no request is made.
	{osReasonFeedUnavailable, func(e *depsScanEnv) bool { return !e.managed && len(depsTrust().FeedKeys) == 0 }},
}

// osBlocked returns the OS fetch gate's first closed reason, "" when a
// release may be fetched.
func (e *depsScanEnv) osBlocked() string { return osFetchGate.first(e) }

// ensureOSRelease makes release r's export available to the matcher and
// returns its epoch string (what a finding records), or a fixed reason
// (osReason*) when it cannot. An installed release whose data is within
// its age floor is answered from disk with no request; otherwise the
// release is fetched under the gate (osFetchGate) from the node's one
// source, its artifacts only.
func ensureOSRelease(ctx context.Context, e *depsScanEnv, r osvdb.OSRelease) (epoch string, reason string) {
	osvOSMu.Lock()
	defer osvOSMu.Unlock()
	now := time.Now()
	if ep, ok := e.db.OSInstalled(r); ok && e.osUsable(r, now) {
		return ep, ""
	}
	if why := e.osBlocked(); why != "" {
		return "", why
	}
	set, why := e.openOSSet(ctx, now)
	if why != "" {
		_ = e.db.RecordOSCheck(r, now, why)
		return "", why
	}
	if _, why := e.installOSRelease(ctx, set, r, now); why != "" {
		_ = e.db.RecordOSCheck(r, now, why)
		return "", why
	}
	ep, ok := e.db.OSInstalled(r)
	if !ok {
		return "", osReasonMissing
	}
	return ep, ""
}

// osFloor is the age floor of the OS data: the kind's own, or a stricter
// require.max_advisory_db_age_h in force.
func (e *depsScanEnv) osFloor() time.Duration {
	floor := osvOSDefaultFloor
	if spec, ok := content.KindOf(osvOSKind); ok && spec.AgeFloor > 0 {
		floor = spec.AgeFloor
	}
	if f := depsAdvisoryFloor(e.cfg.Security); f > 0 && f < floor {
		floor = f
	}
	return floor
}

// osUsable reports whether installed release r's data may still be matched
// against: the newest signed manifest that vouched for its bytes is within
// the age floor (data past it is unknown, never current).
func (e *depsScanEnv) osUsable(r osvdb.OSRelease, now time.Time) bool {
	sc, ok := readOSInstalledRecord(e.db, r)
	if !ok {
		return false
	}
	issued, err := time.Parse(time.RFC3339, sc.VouchedIssuedAt)
	return err == nil && now.Sub(issued) <= e.osFloor()
}

// osvOSSet is one verified security.osv_os_export manifest and the way to
// reach its artifacts.
type osvOSSet struct {
	m      content.Manifest
	source string
	// artifact returns a local file holding entry ent's bytes, verified
	// against its size and digest, and a cleanup for it; keep asks the feed
	// to keep a base for the next delta. The file is never renamed by the
	// caller (it may be the content store's own).
	artifact func(ctx context.Context, ent content.Entry, keep bool) (string, func(), error)
}

// openOSSet opens the node's one source of the kind: the org mirror on a
// managed node, the signed mirror on an individual one.
func (e *depsScanEnv) openOSSet(ctx context.Context, now time.Time) (osvOSSet, string) {
	if e.managed {
		return e.orgMirrorOSSet(ctx)
	}
	return e.feedOSSet(ctx, now)
}

// orgMirrorOSSet installs the kind from the org mirror into the content
// channel (a failure keeps the last-known-good) and presents what is
// installed.
func (e *depsScanEnv) orgMirrorOSSet(ctx context.Context) (osvOSSet, string) {
	st := depsContentStore(depsConfigPath(e.configPath))
	tr := depsTrust()
	if ferr := fetchFromOrgMirror(ctx, e.configPath, st, []content.Kind{osvOSKind}, tr); ferr != nil {
		e.logger.Warn("security: org mirror fetch of the OS release databases failed; the installed set stays in use", "err", ferr)
	}
	l, err := st.Load(osvOSKind, tr, e.osFloor())
	if err != nil || l.Freshness == content.Unknown {
		return osvOSSet{}, osReasonMissing
	}
	return osvOSSet{m: l.Manifest, source: osvdb.SourceOrgMirror, artifact: func(_ context.Context, ent content.Entry, _ bool) (string, func(), error) {
		p, _, err := l.ArtifactPath(ent.Name)
		if err != nil {
			return "", func() {}, err
		}
		if err := checkOSFile(p, ent); err != nil {
			return "", func() {}, err
		}
		return p, func() {}, nil
	}}, ""
}

// The OS feed's files in osvdb.Store.OSFeedDir.
const (
	osFeedManifestFile = "manifest.json"
	osFeedStateFile    = "state.json"
	osFeedETagFile     = "etag.json"
)

// osFeedFiles is the OS feed directory.
type osFeedFiles struct{ dir string }

func (f osFeedFiles) path(name string) string { return filepath.Join(f.dir, name) }

// state reads the kind's accepted high-water mark; none is the zero state.
func (f osFeedFiles) state() content.State {
	b, err := readDepsFile(f.path(osFeedStateFile), 64<<10)
	if err != nil {
		return content.State{Kind: osvOSKind}
	}
	var st content.State
	if json.Unmarshal(b, &st) != nil {
		return content.State{Kind: osvOSKind}
	}
	return st
}

func (f osFeedFiles) writeState(st content.State) {
	if b, err := json.Marshal(st); err == nil {
		_ = writeDepsFile(f.path(osFeedStateFile), b)
	}
}

func (f osFeedFiles) etag() string {
	b, err := readDepsFile(f.path(osFeedETagFile), 1024)
	if err != nil {
		return ""
	}
	var s string
	if json.Unmarshal(b, &s) != nil || len(s) > 256 {
		return ""
	}
	return s
}

func (f osFeedFiles) writeETag(tag string) {
	if len(tag) > 256 {
		tag = ""
	}
	if b, err := json.Marshal(tag); err == nil {
		_ = writeDepsFile(f.path(osFeedETagFile), b)
	}
}

// stored re-verifies the accepted manifest on disk (signature, structure
// and ordering against its own state; expiry judged by freshness) and
// refuses it past floor.
func (f osFeedFiles) stored(tr contentchan.Trust, now time.Time, floor time.Duration) (content.Manifest, error) {
	st := f.state()
	if st.Accepted == nil {
		return content.Manifest{}, contentchan.ErrNotInstalled
	}
	env, err := readDepsFile(f.path(osFeedManifestFile), content.MaxEnvelopeBytes)
	if err != nil {
		return content.Manifest{}, err
	}
	res, err := content.Verify(content.VerifyInput{
		Envelope: env, Kind: osvOSKind, VendorKeys: tr.VendorKeys, FeedKeys: tr.FeedKeys,
		Accepted: st.Accepted, Now: now, AllowExpired: true,
	})
	if err != nil {
		return content.Manifest{}, err
	}
	if res.Hash != st.Accepted.ManifestHash {
		return content.Manifest{}, &content.Refusal{Reason: content.ContentReasonFork, Detail: "the OS manifest on disk is not the accepted one"}
	}
	if content.FreshnessAt(res.Manifest, now, floor) == content.Unknown {
		return content.Manifest{}, errors.New("the accepted OS manifest is past its age floor")
	}
	return res.Manifest, nil
}

// feedOSManifest fetches the kind's manifest from the signed mirror (ETag
// revalidation), verifies it against the kind's high-water mark and
// accepts it; a fetch or a verification that fails falls back to the
// accepted manifest while its age floor allows (the last-known-good).
// notPublished reports a mirror that does not publish the kind.
func (e *depsScanEnv) feedOSManifest(ctx context.Context, now time.Time) (m content.Manifest, notPublished bool, err error) {
	f := osFeedFiles{dir: e.db.OSFeedDir()}
	tr := depsTrust()
	prev := f.state()
	etag := ""
	if prev.Accepted != nil {
		etag = f.etag()
	}
	env, tag, ferr := depsOSVFeed().FetchFeedFile(ctx, string(osvOSKind), contentchan.ManifestFile, etag)
	if errors.Is(ferr, osvnet.ErrFeedNotModified) {
		sm, serr := f.stored(tr, now, e.osFloor())
		return sm, false, serr
	}
	if ferr == nil {
		res, verr := content.Verify(content.VerifyInput{
			Envelope: env, Kind: osvOSKind, VendorKeys: tr.VendorKeys, FeedKeys: tr.FeedKeys,
			Accepted: prev.Accepted, Now: now,
		})
		if verr == nil {
			if prev.Accepted == nil || res.Hash != prev.Accepted.ManifestHash {
				if werr := writeDepsFile(f.path(osFeedManifestFile), env); werr != nil {
					return content.Manifest{}, false, werr
				}
				f.writeState(content.Apply(prev, res, nil, now))
			}
			f.writeETag(tag)
			return res.Manifest, false, nil
		}
		f.writeState(content.Apply(prev, content.Result{}, verr, now))
		ferr = verr
	}
	if sm, serr := f.stored(tr, now, e.osFloor()); serr == nil {
		e.logger.Warn("security: the signed OS release database manifest could not be fetched; the accepted one stays in use", "err", ferr)
		return sm, false, nil
	}
	return content.Manifest{}, errors.Is(ferr, osvnet.ErrFeedNotPublished), ferr
}

// feedOSSet opens the signed mirror's set.
func (e *depsScanEnv) feedOSSet(ctx context.Context, now time.Time) (osvOSSet, string) {
	m, notPublished, err := e.feedOSManifest(ctx, now)
	if err != nil {
		if notPublished {
			return osvOSSet{}, osReasonNotPublished
		}
		e.logger.Debug("security: the OS release databases' feed is unavailable", "err", err)
		return osvOSSet{}, osReasonFeedUnavailable
	}
	dir := e.db.OSFeedDir()
	return osvOSSet{m: m, source: osvdb.SourceFeed, artifact: func(ctx context.Context, ent content.Entry, keep bool) (string, func(), error) {
		return fetchOSFeedArtifact(ctx, dir, ent, keep)
	}}, ""
}

// fetchOSFeedArtifact returns a verified local copy of one feed artifact: a
// kept base already in dir whose bytes match the entry is reused; anything
// else is streamed from the mirror to a temporary file in dir and checked
// for its exact size and digest. A kept base is renamed to its own name in
// dir (no cleanup); anything else is removed by the cleanup.
func fetchOSFeedArtifact(ctx context.Context, dir string, ent content.Entry, keep bool) (string, func(), error) {
	none := func() {}
	if ent.Name == "" || ent.Name == "." || ent.Name == ".." || strings.ContainsAny(ent.Name, `/\`) || !strings.HasSuffix(ent.Name, ".zip") {
		return "", none, fmt.Errorf("artifact name %q is not a release export", ent.Name)
	}
	kept := filepath.Join(dir, ent.Name)
	if keep {
		if checkOSFile(kept, ent) == nil {
			return kept, none, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", none, err
	}
	tmp, err := os.CreateTemp(dir, ".part-*")
	if err != nil {
		return "", none, err
	}
	name := tmp.Name()
	drop := func() { _ = os.Remove(name) }
	ferr := depsOSVFeed().StreamFeedArtifact(ctx, string(osvOSKind), ent.Name, ent.SizeBytes, tmp)
	if cerr := tmp.Close(); ferr == nil {
		ferr = cerr
	}
	if ferr == nil {
		ferr = checkOSFile(name, ent)
	}
	if ferr != nil {
		drop()
		return "", none, ferr
	}
	if !keep {
		return name, drop, nil
	}
	if err := os.Rename(name, kept); err != nil {
		drop()
		return "", none, err
	}
	return kept, none, nil
}

// checkOSFile checks a file's exact size and sha256 against its signed
// entry.
func checkOSFile(path string, ent content.Entry) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || fi.Size() != ent.SizeBytes {
		return &content.Refusal{Reason: content.ContentReasonArtifact, Detail: ent.Name + " is not the size the manifest says"}
	}
	_, sum, err := fileCRC32CAndSHA256(path)
	if err != nil {
		return err
	}
	if sum != strings.ToLower(ent.SHA256) {
		return &content.Refusal{Reason: content.ContentReasonArtifact, Detail: ent.Name + " does not match its digest"}
	}
	return nil
}

// osReleaseEntries is the subset rule: of a verified manifest it takes
// ONLY release r's base and, when the set carries one over that base, its
// cumulative delta; every other release's artifacts are never fetched. A
// base the set does not list, or revokes, is "not published".
func osReleaseEntries(m content.Manifest, r osvdb.OSRelease) (base content.Entry, delta *content.Entry, reason string) {
	goos, goarch := content.PlatformFor(osvOSKind, runtime.GOOS, runtime.GOARCH)
	base, err := content.EntryFor(m, r.ExportArtifact(), goos, goarch)
	if err != nil {
		return content.Entry{}, nil, osReasonNotPublished
	}
	for _, ent := range m.Entries {
		if ent.Name != r.DeltaArtifact() || ent.Delta == nil || content.IsRevoked(m, ent.SHA256) || !content.EntryApplies(ent, goos, goarch) {
			continue
		}
		if ent.Delta.Base != base.Name || !strings.EqualFold(ent.Delta.BaseSHA256, base.SHA256) {
			continue
		}
		d := ent
		return base, &d, ""
	}
	return base, nil, ""
}

// osInstalledRecord says which signed bytes an installed release came from
// (in the OS feed directory, "<Artifact>.installed.json"), so a refresh
// whose manifest names the same bytes installs nothing, and the newest
// manifest that vouched for them (the age floor's clock).
type osInstalledRecord struct {
	V               int    `json:"v"`
	BaseSHA256      string `json:"base_sha256"`
	DeltaSHA256     string `json:"delta_sha256,omitempty"`
	Source          string `json:"source"`
	VouchedIssuedAt string `json:"vouched_issued_at"`
}

const osInstalledRecordV = 1

func osInstalledRecordPath(db osvdb.Store, r osvdb.OSRelease) string {
	return filepath.Join(db.OSFeedDir(), r.Artifact+".installed.json")
}

func readOSInstalledRecord(db osvdb.Store, r osvdb.OSRelease) (osInstalledRecord, bool) {
	b, err := readDepsFile(osInstalledRecordPath(db, r), 4096)
	if err != nil {
		return osInstalledRecord{}, false
	}
	var rec osInstalledRecord
	if json.Unmarshal(b, &rec) != nil || rec.V != osInstalledRecordV {
		return osInstalledRecord{}, false
	}
	return rec, true
}

func writeOSInstalledRecord(db osvdb.Store, r osvdb.OSRelease, rec osInstalledRecord) error {
	rec.V = osInstalledRecordV
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return writeDepsFile(osInstalledRecordPath(db, r), b)
}

// installOSRelease brings release r up to the set: unchanged bytes only
// move the check time and the vouching manifest; otherwise the base (and
// the delta, merged over it) are fetched, verified and installed. changed
// reports a new export; reason is a fixed osReason* on failure, and the
// installed export stays.
func (e *depsScanEnv) installOSRelease(ctx context.Context, set osvOSSet, r osvdb.OSRelease, now time.Time) (changed bool, reason string) {
	base, delta, why := osReleaseEntries(set.m, r)
	if why != "" {
		return false, why
	}
	rec := osInstalledRecord{BaseSHA256: strings.ToLower(base.SHA256), Source: set.source, VouchedIssuedAt: set.m.IssuedAt}
	if delta != nil {
		rec.DeltaSHA256 = strings.ToLower(delta.SHA256)
	}
	if _, ok := e.db.OSInstalled(r); ok {
		if prev, ok := readOSInstalledRecord(e.db, r); ok && prev.BaseSHA256 == rec.BaseSHA256 && prev.DeltaSHA256 == rec.DeltaSHA256 && prev.Source == rec.Source {
			if err := writeOSInstalledRecord(e.db, r, rec); err != nil {
				return false, osReasonFeedUnavailable
			}
			_ = e.db.RecordOSCheck(r, now, "")
			return false, ""
		}
	}
	tmp, err := e.buildOSExport(ctx, set, base, delta)
	if err != nil {
		e.logger.Warn("security: an OS release database could not be installed; the installed one stays", "release", r.Artifact, "err", err)
		return false, osReasonFeedUnavailable
	}
	if _, err := e.db.InstallOS(r, tmp, osvdb.OSInstall{IssuedAt: set.m.IssuedAt, Source: set.source}, now); err != nil {
		_ = os.Remove(tmp)
		e.logger.Warn("security: an OS release database could not be installed; the installed one stays", "release", r.Artifact, "err", err)
		return false, osReasonFeedUnavailable
	}
	if err := writeOSInstalledRecord(e.db, r, rec); err != nil {
		e.logger.Warn("security: the OS release database record could not be written", "release", r.Artifact, "err", err)
	}
	return true, ""
}

// buildOSExport puts the export to install under a temporary name in the OS
// feed directory: the merged base and delta, or the base itself (a hard
// link, a copy where refused).
func (e *depsScanEnv) buildOSExport(ctx context.Context, set osvOSSet, base content.Entry, delta *content.Entry) (string, error) {
	dir := e.db.OSFeedDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	bp, bclean, err := set.artifact(ctx, base, true)
	if err != nil {
		return "", fmt.Errorf("%s: %w", base.Name, err)
	}
	defer bclean()
	tmp, err := os.CreateTemp(dir, ".install-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	_ = tmp.Close()
	if delta == nil {
		_ = os.Remove(name)
		if err := osLinkOrCopy(bp, name); err != nil {
			_ = os.Remove(name)
			return "", err
		}
		return name, nil
	}
	dp, dclean, err := set.artifact(ctx, *delta, false)
	if err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("%s: %w", delta.Name, err)
	}
	defer dclean()
	if err := mergeOSExport(bp, dp, *delta, name); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

// mergeOSExport writes base plus its cumulative delta to out and checks the
// record count against the signed delta entry.
func mergeOSExport(basePath, deltaPath string, de content.Entry, out string) error {
	b, err := zip.OpenReader(basePath)
	if err != nil {
		return fmt.Errorf("the base is not a zip: %w", err)
	}
	defer func() { _ = b.Close() }()
	d, err := zip.OpenReader(deltaPath)
	if err != nil {
		return fmt.Errorf("the delta is not a zip: %w", err)
	}
	defer func() { _ = d.Close() }()
	drop := make(map[string]bool, len(de.Delta.Drop))
	for _, n := range de.Delta.Drop {
		drop[n] = true
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // G304: a temporary file of the store's own directory
	if err != nil {
		return err
	}
	stats, err := osvdb.MergeExportZip(&b.Reader, &d.Reader, drop, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("merge: %w", err)
	}
	if stats.Total != de.Delta.Records {
		return fmt.Errorf("the merged export has %d records, the signed entry says %d", stats.Total, de.Delta.Records)
	}
	return nil
}

// osLinkOrCopy puts src at dst: a hard link, or a copy where the
// filesystem refuses one.
func osLinkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src) //nolint:gosec // G304: a file of the store or the content channel
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: a temporary file of the store's own directory
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// osRefreshReport is what one refresh of the installed releases did.
type osRefreshReport struct {
	// Blocked is the gate's reason when nothing was asked.
	Blocked   string
	Changed   []string
	Unchanged []string
	// Failed maps a release's artifact name to its fixed reason; its
	// installed export stays.
	Failed map[string]string
}

// refreshOSReleases brings every INSTALLED release up to the node's source
// (never a new one: those come on demand through ensureOSRelease). No
// release installed makes no request.
func (e *depsScanEnv) refreshOSReleases(ctx context.Context, now time.Time) osRefreshReport {
	osvOSMu.Lock()
	defer osvOSMu.Unlock()
	rep := osRefreshReport{Failed: map[string]string{}}
	installed := e.db.OSReleasesInstalled()
	if len(installed) == 0 {
		return rep
	}
	if why := e.osBlocked(); why != "" {
		rep.Blocked = why
		return rep
	}
	set, why := e.openOSSet(ctx, now)
	for _, ir := range installed {
		r := ir.Release
		if why != "" {
			rep.Failed[r.Artifact] = why
			_ = e.db.RecordOSCheck(r, now, why)
			continue
		}
		changed, rwhy := e.installOSRelease(ctx, set, r, now)
		switch {
		case rwhy != "":
			rep.Failed[r.Artifact] = rwhy
			_ = e.db.RecordOSCheck(r, now, rwhy)
		case changed:
			rep.Changed = append(rep.Changed, r.Artifact)
		default:
			rep.Unchanged = append(rep.Unchanged, r.Artifact)
		}
	}
	return rep
}

// depsOSRefreshAt is each store's last OS refresh in this process (both
// driver loops share it, so the installed releases refresh once per
// depsDBEvery).
var depsOSRefreshAt sync.Map // store dir -> time.Time

// maybeRefreshOS refreshes the installed releases when depsDBEvery passed
// since the last refresh in this process.
func (e *depsScanEnv) maybeRefreshOS(ctx context.Context, now time.Time) {
	// The exploit kinds (security_exploit.go) ride the same pass and
	// cadence under the OSV database feed's gate.
	e.maybeRefreshExploit(ctx, now)
	if v, ok := depsOSRefreshAt.Load(e.db.Dir()); ok && now.Sub(v.(time.Time)) < depsDBEvery {
		return
	}
	if len(e.db.OSReleasesInstalled()) == 0 {
		return
	}
	depsOSRefreshAt.Store(e.db.Dir(), now)
	rep := e.refreshOSReleases(ctx, now)
	switch {
	case rep.Blocked != "":
		e.logger.Debug("security: OS release database refresh not allowed", "reason", rep.Blocked)
	case len(rep.Failed) > 0:
		e.logger.Warn("security: OS release database refresh failed for some releases; their installed databases stay", "failed", len(rep.Failed))
	}
}
