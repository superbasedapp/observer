//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvnet"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_osv_source.go walks the source order of the OSV databases
// (static feed mirroring plan section 7; the order itself is the pure rule
// table osvdb.SourcePlan): a managed node takes its org mirror only; an
// individual node takes, by [security.deps] db_source, the imported set,
// SuperBased's signed mirror on superbased.app (the security.osv_export
// content kind, base + cumulative delta per ecosystem, installed into the
// same content root as the install gate's index and verified with the
// vendor and content-feed keys), or the OSV bucket directly, the mirror
// falling back to the bucket when db_fallback_upstream allows it. Every
// refresh records which source served it and why an earlier one did not,
// for `observer security scan status`, the Scanners card and the log; the
// epoch the scan runs record names the source too (osvdb.Epoch.Source).

// depsOSVSourceFile records the last refresh's source in the security
// directory.
const depsOSVSourceFile = "osv-db-source.json"

// depsOSVSourceRecord is the last refresh's source.
type depsOSVSourceRecord struct {
	// Source is the osvdb.Source* value that served it; "" when none could.
	Source string    `json:"source"`
	At     time.Time `json:"at"`
	// Fallback says why each earlier source in the order did not serve
	// ("feed: not published; ..."), "" when the first one did.
	Fallback string `json:"fallback,omitempty"`
	// Error is the last source's failure when no source served.
	Error string `json:"error,omitempty"`
	// Sources maps each ecosystem a LATER source served (one the first
	// source did not hold, osvRemotes) to that source; empty when Source
	// served every ecosystem.
	Sources map[string]string `json:"sources,omitempty"`
}

// readDepsOSVSource reads the record; anything unreadable is none.
func readDepsOSVSource(dir string) (depsOSVSourceRecord, bool) {
	b, err := readDepsFile(filepath.Join(dir, depsOSVSourceFile), 8192)
	if err != nil {
		return depsOSVSourceRecord{}, false
	}
	var r depsOSVSourceRecord
	if json.Unmarshal(b, &r) != nil {
		return depsOSVSourceRecord{}, false
	}
	return r, true
}

// writeDepsOSVSource records the refresh's source (best effort).
func writeDepsOSVSource(dir string, r depsOSVSourceRecord) {
	for _, s := range []*string{&r.Fallback, &r.Error} {
		if len(*s) > 1024 {
			*s = (*s)[:1024]
		}
	}
	if b, err := json.Marshal(r); err == nil {
		_ = writeDepsFile(filepath.Join(dir, depsOSVSourceFile), b)
	}
}

// dbSetting is [security.deps] db_source ("" reads as auto).
func (e *depsScanEnv) dbSetting() string {
	if s := e.cfg.Security.Deps.DBSource; s != "" {
		return s
	}
	return osvdb.SettingAuto
}

// sourcePlan is this node's source order (osvdb.SourcePlan).
func (e *depsScanEnv) sourcePlan() []string {
	return osvdb.SourcePlan(osvdb.SourceInput{
		Managed: e.managed, Setting: e.dbSetting(), FallbackUpstream: e.cfg.Security.Deps.DBFallbackUpstream,
	})
}

// errOSVSourceUnusable is a source that yielded no usable set; the next one
// in the order is tried.
type errOSVSourceUnusable struct{ why string }

func (e errOSVSourceUnusable) Error() string { return e.why }

// depsOSVOpeners open each source of the order. last reports that no other
// source follows, so the source serves whatever it holds rather than
// passing to the next one.
var depsOSVOpeners = map[string]func(ctx context.Context, e *depsScanEnv, last bool) (osvdb.Remote, error){
	osvdb.SourceOrgMirror: func(ctx context.Context, e *depsScanEnv, _ bool) (osvdb.Remote, error) { return e.orgMirrorOSV(ctx) },
	osvdb.SourceImport:    func(_ context.Context, e *depsScanEnv, _ bool) (osvdb.Remote, error) { return e.importedOSV() },
	osvdb.SourceFeed: func(ctx context.Context, e *depsScanEnv, last bool) (osvdb.Remote, error) {
		return e.feedOSV(ctx, last)
	},
	osvdb.SourceUpstream: func(context.Context, *depsScanEnv, bool) (osvdb.Remote, error) { return depsOSVRemote(), nil },
}

// osvServed is one source of a refresh and the ecosystems it serves.
type osvServed struct {
	source string
	remote osvdb.Remote
	ecos   []string
}

// osvRemotes walks the source order PER ECOSYSTEM: each source that opens
// with a usable set serves the ecosystems it holds (osvdb.ServingRemote;
// the bucket holds every one) among those no earlier source served, and
// the rest fall through to the next source; the last source of the order
// takes whatever is left (an ecosystem it does not hold fails there and
// keeps its last-known-good export, osvdb.TakeServed). So a set published
// before an ecosystem joined the store (every feed manifest before GitHub
// Actions) serves the ecosystems it lists, and the new one alone takes the
// bucket under `auto`, or stays last-known-good (database_missing until
// one is installed) under `feed`, `import` or a managed node's org mirror.
// The record names the source that served first, and every ecosystem
// another one served. No usable source at all is an error: the databases
// on disk stay in use.
func (e *depsScanEnv) osvRemotes(ctx context.Context, ecos []string) ([]osvServed, depsOSVSourceRecord, error) {
	plan := e.sourcePlan()
	rec := depsOSVSourceRecord{At: time.Now().UTC()}
	var skipped []string
	var out []osvServed
	left := append([]string(nil), ecos...)
	for i, src := range plan {
		if len(left) == 0 {
			break
		}
		open, ok := depsOSVOpeners[src]
		if !ok {
			skipped = append(skipped, src+": no opener")
			continue
		}
		last := i == len(plan)-1
		r, err := open(ctx, e, last)
		if err != nil || r == nil {
			why := "unavailable"
			if err != nil {
				why = err.Error()
			}
			skipped = append(skipped, src+": "+why)
			continue
		}
		var serves func(string) bool
		if sr, ok := r.(osvdb.ServingRemote); ok {
			serves = sr.Serves
		}
		take, rest := osvdb.TakeServed(left, serves, last)
		if len(take) > 0 {
			out = append(out, osvServed{source: src, remote: r, ecos: take})
			if rec.Source == "" {
				rec.Source, rec.Fallback = src, strings.Join(skipped, "; ")
			} else {
				if rec.Sources == nil {
					rec.Sources = map[string]string{}
				}
				for _, eco := range take {
					rec.Sources[eco] = src
				}
			}
		}
		if len(rest) > 0 {
			skipped = append(skipped, src+": does not hold "+strings.Join(rest, ", "))
		}
		left = rest
	}
	if len(out) == 0 {
		rec.Error = strings.Join(skipped, "; ")
		return nil, rec, fmt.Errorf("no OSV database source could serve this refresh (%s); the databases on disk stay in use", rec.Error)
	}
	if len(rec.Sources) > 0 {
		rec.Fallback = strings.Join(skipped, "; ")
	}
	return out, rec, nil
}

// importedOSV is the imported set (row 2): no request; nothing imported is
// an error.
func (e *depsScanEnv) importedOSV() (osvdb.Remote, error) {
	st := depsContentStore(depsConfigPath(e.configPath))
	l, err := st.Load(content.OSVExport, depsTrust(), depsAdvisoryFloor(e.cfg.Security))
	if err != nil {
		return nil, fmt.Errorf("no imported OSV exports (`observer security scan db import <dir>`): %w", err)
	}
	return newOSVContentRemote(st, l, osvdb.SourceImport), nil
}

// osvFeedClient is the lane's feed side (osvnet.Client); a test swaps it.
type osvFeedClient interface {
	FetchFeedFile(ctx context.Context, kind, file, etag string) ([]byte, string, error)
	StreamFeedArtifact(ctx context.Context, kind, file string, size int64, w io.Writer) error
}

// depsOSVFeed is the signed mirror's network side: the same lane as the
// bucket (security.scan.osv.db, osvnet), FeedHost on its allow-list.
var depsOSVFeed = func() osvFeedClient { return osvnet.New(osvnet.Options{}) }

// osvFeedSource adapts the lane to contentchan.FetchInstall.
type osvFeedSource struct{ c osvFeedClient }

// FetchManifest implements contentchan.Source.
func (s osvFeedSource) FetchManifest(ctx context.Context, kind content.Kind, etag string) ([]byte, string, error) {
	b, tag, err := s.c.FetchFeedFile(ctx, string(kind), contentchan.ManifestFile, etag)
	if errors.Is(err, osvnet.ErrFeedNotModified) {
		return nil, etag, contentchan.ErrNotModified
	}
	return b, tag, err
}

// FetchArtifact implements contentchan.Source.
func (s osvFeedSource) FetchArtifact(ctx context.Context, kind content.Kind, e content.Entry, w io.Writer) error {
	return s.c.StreamFeedArtifact(ctx, string(kind), e.Name, e.SizeBytes, w)
}

// depsFeedFallbackRows decide, top down, whether the signed mirror serves
// this refresh after its fetch: the first row that matches gives the
// reason it does NOT (the next source is tried); none matching serves the
// installed set. A failed fetch still serves a fresh installed set (a
// transient outage does not flip the node to the bucket and back), and,
// as the last source in the order (db_source = feed), any set its age
// floor still allows (the last-known-good, the failure reported).
var depsFeedFallbackRows = []struct {
	reason string
	match  func(fetchErr error, l contentchan.Loaded, loadErr error, last bool) bool
}{
	{"nothing installed from it", func(_ error, _ contentchan.Loaded, loadErr error, _ bool) bool {
		return errors.Is(loadErr, contentchan.ErrNotInstalled)
	}},
	{"the installed set does not verify", func(_ error, _ contentchan.Loaded, loadErr error, _ bool) bool { return loadErr != nil }},
	{"the installed set is past its age floor", func(_ error, l contentchan.Loaded, _ error, _ bool) bool {
		return l.Freshness == content.Unknown
	}},
	{"the fetch failed and the installed set is not fresh", func(fetchErr error, l contentchan.Loaded, _ error, last bool) bool {
		return fetchErr != nil && !last && l.Freshness != content.Fresh
	}},
}

// feedOSV is the signed mirror (row 3): the security.osv_export kind
// fetched into the content root (ETag on the manifest, artifacts reused by
// digest), verified with the vendor and content-feed keys, presented
// through the content remote (base + delta merged).
func (e *depsScanEnv) feedOSV(ctx context.Context, last bool) (osvdb.Remote, error) {
	tr := depsTrust()
	if len(tr.FeedKeys) == 0 {
		// The publisher signs this kind with the content-feed key only:
		// with none compiled in nothing it publishes can verify, so no
		// request is made at all.
		return nil, errOSVSourceUnusable{"not verifiable: no content-feed key in this build"}
	}
	st := depsContentStore(depsConfigPath(e.configPath))
	tags := readDepsFeedETags(st)
	res, fetchErr := st.FetchInstall(ctx, content.OSVExport, tr, osvFeedSource{c: depsOSVFeed()}, tags[string(content.OSVExport)])
	if fetchErr == nil {
		writeDepsFeedETag(st, tags, content.OSVExport, res.ETag)
	}
	l, loadErr := st.Load(content.OSVExport, tr, depsAdvisoryFloor(e.cfg.Security))
	for _, r := range depsFeedFallbackRows {
		if r.match(fetchErr, l, loadErr, last) {
			why := r.reason
			if fetchErr != nil {
				why += " (" + feedFetchWords(fetchErr) + ")"
			}
			return nil, errOSVSourceUnusable{why}
		}
	}
	if fetchErr != nil {
		e.logger.Warn("security: the signed OSV mirror could not be fetched; its installed set stays in use", "err", fetchErr, "freshness", l.Freshness)
	}
	return newOSVContentRemote(st, l, osvdb.SourceFeed), nil
}

// feedFetchWords says why a fetch of the signed mirror failed.
func feedFetchWords(err error) string {
	switch {
	case errors.Is(err, osvnet.ErrFeedNotPublished):
		return "not published"
	case content.ReasonOf(err) != "":
		return "not verifiable: " + string(content.ReasonOf(err))
	}
	return err.Error()
}

// osvDirSource reads one kind's files from an import directory laid out
// as the org mirror's import is: <dir>/<kind>/manifest.json and the
// artifacts beside it.
type osvDirSource struct{ dir string }

// FetchManifest implements contentchan.Source.
func (s osvDirSource) FetchManifest(_ context.Context, kind content.Kind, _ string) ([]byte, string, error) {
	b, err := readDepsFile(filepath.Join(s.dir, string(kind), contentchan.ManifestFile), content.MaxEnvelopeBytes)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", kind, err)
	}
	return b, "", nil
}

// FetchArtifact implements contentchan.Source.
func (s osvDirSource) FetchArtifact(_ context.Context, kind content.Kind, e content.Entry, w io.Writer) error {
	if e.Name == "" || e.Name == "." || e.Name == ".." || strings.ContainsAny(e.Name, `/\`) {
		return fmt.Errorf("artifact name %q is not a plain file name", e.Name)
	}
	f, err := os.Open(filepath.Join(s.dir, string(kind), e.Name)) //nolint:gosec // G304: a file of the directory the user named
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(w, io.LimitReader(f, e.SizeBytes+1))
	return err
}

// importOSVSet installs the security.osv_export set under dir into the
// node's content root, verified exactly as the signed mirror's is.
func (e *depsScanEnv) importOSVSet(ctx context.Context, dir string) (contentchan.FetchResult, error) {
	st := depsContentStore(depsConfigPath(e.configPath))
	return st.FetchInstall(ctx, content.OSVExport, depsTrust(), osvDirSource{dir: dir}, "")
}

// writeDBSourceState prints the source order and the last refresh's
// source.
func writeDBSourceState(w io.Writer, e *depsScanEnv) {
	plan := e.sourcePlan()
	words := make([]string, 0, len(plan))
	for _, s := range plan {
		words = append(words, osvSourceName(s))
	}
	fmt.Fprintf(w, "database source: %s (%s)\n", e.dbSetting(), strings.Join(words, ", then "))
	rec, ok := readDepsOSVSource(e.dir)
	switch {
	case !ok:
		fmt.Fprintln(w, "  no refresh recorded yet")
	case rec.Source == "":
		fmt.Fprintf(w, "  last refresh %s: no source could serve it (%s); the databases on disk stay in use\n", rec.At.Local().Format(time.RFC3339), rec.Error)
	default:
		fmt.Fprintf(w, "  last refresh %s from %s", rec.At.Local().Format(time.RFC3339), osvSourceName(rec.Source))
		if rec.Fallback != "" {
			fmt.Fprintf(w, " (fell back: %s)", rec.Fallback)
		}
		fmt.Fprintln(w)
		for _, eco := range depscanSortedKeys(rec.Sources) {
			fmt.Fprintf(w, "  %s from %s\n", eco, osvSourceName(rec.Sources[eco]))
		}
	}
}

// depscanSortedKeys returns m's keys, sorted.
func depscanSortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// runDBImport is `observer security scan db import <dir>`.
func runDBImport(ctx context.Context, w io.Writer, e *depsScanEnv, dir string) error {
	if e.managed {
		return errors.New("this is a managed node: its OSV databases come from your organization's mirror only (an operator imports a set there with `observer-org security mirror import`)")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	fi, err := os.Stat(filepath.Join(abs, string(content.OSVExport)))
	hasOSV := err == nil && fi.IsDir()
	hasExploit := exploitImportPresent(abs)
	if !hasOSV && !hasExploit {
		return fmt.Errorf("%s has no %s directory (the layout is <dir>/%s/manifest.json and its artifacts; <dir>/%s/ and <dir>/%s/ carry the exploit data)", abs, content.OSVExport, content.OSVExport, content.KEV, content.EPSS)
	}
	if hasOSV {
		res, err := e.importOSVSet(ctx, abs)
		if err != nil {
			return fmt.Errorf("import refused, the installed set stays: %w", err)
		}
		switch {
		case res.Unchanged:
			fmt.Fprintln(w, "security.osv_export: already installed (the same signed set)")
		default:
			v := int64(0)
			if res.State.Accepted != nil {
				v = res.State.Accepted.ManifestVersion
			}
			fmt.Fprintf(w, "security.osv_export: version %d installed (%d artifact(s) copied, %d reused)\n", v, res.Fetched, res.Reused)
		}
	}
	// The exploit kinds beside it (security.kev, security.epss), each when
	// its directory is present, verified as the feed's are.
	if hasExploit {
		writeExploitRefresh(w, e.importExploitSets(ctx, abs, time.Now()))
	}
	if !hasOSV {
		return nil
	}
	if e.dbSetting() != osvdb.SettingImport {
		fmt.Fprintf(w, "note: [security.deps] db_source is %q, so the refresh may replace this set from the network; set it to \"import\" to use imported sets only\n", e.dbSetting())
		return nil
	}
	if e.downloadBlocked() != "" {
		return nil
	}
	return writeDBRefresh(ctx, w, e)
}

// osvImportOnly reports an individual node whose databases come only from
// imported sets (db_source = import): it fetches nothing, so the download
// accept does not hold it back.
func (e *depsScanEnv) osvImportOnly() bool {
	return !e.managed && e.dbSetting() == osvdb.SettingImport
}
