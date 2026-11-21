package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// secindex.go is the `vendorsign secindex` verb, the publisher of the
// install gate's two index kinds (security pillar plan sections 5.4 and
// 8.5, Phase D1; deploy/feed-publisher/publish.sh runs it daily). One run
// publishes ONE kind, named by -kind, so each kind keeps its own state
// directory, counters, validity and cadence, and a failure of one never
// touches the other:
//
//	security.malicious_packages  malicious.idx: the OSV MAL- reports (the
//	                             OpenSSF malicious-packages records OSV
//	                             imports into each ecosystem's export) of
//	                             every ecosystem the install gate checks,
//	                             read from the exports publish.sh mirrors
//	                             (-osv-export, each checked against its
//	                             source.json) or from loose records (-osv)
//	security.popular_names       popular.idx: one popular-name list for
//	                             every ecosystem the install gate checks
//	                             (-popular eco=FILE), each a line list or a
//	                             JSON array of names (the ranked lists
//	                             publish.sh fetches)
//
// Both lists must cover every ecosystem of secfeed's table: a node reads a
// missing ecosystem in a published list as "not listed" and "no near
// miss", never as unknown, so a partial list would silently switch a check
// off. It reads local files only (publish.sh fetches), checks the artifact
// the way a node will (secfeed.ValidateIndex) before anything is signed,
// and signs with the CONTENT-FEED key through the small-feed path
// (feedsingle.go): the state directory's counters, the unchanged and
// re-sign decision, every artifact before the manifest, the state last.
// Output, one directory per kind:
//
//	<out>/security.malicious_packages/malicious.idx + manifest.json
//	<out>/security.popular_names/popular.idx + manifest.json

const (
	// maliciousValidity and popularValidity are the kinds' manifest
	// lifetimes (docs/security.md SECP-22: 7 and 30 days), inside the kind
	// table's bounds (internal/update/content: MaxValidity 14 and 60 days;
	// age floors 30 and 180 days). The malicious list is published daily
	// and re-signed after 20 hours unchanged; the popular lists are fetched
	// weekly and re-signed after 7 days unchanged (publish.sh).
	maliciousValidity = 7 * 24 * time.Hour
	popularValidity   = 30 * 24 * time.Hour

	// maliciousSourceLabel and maliciousLicense describe malicious.idx:
	// only MAL- reports enter it, and those come from the OpenSSF
	// repository, licensed Apache-2.0.
	maliciousSourceLabel = "OSV MAL- reports (github.com/ossf/malicious-packages) from the osv.dev export bucket, compiled by SuperBased"
	maliciousLicense     = "Apache-2.0"
	// maliciousExportURL is the object recorded for -osv-export: the
	// bucket the exports are mirrored from (each export's object,
	// generation and checksums are in its source.json).
	maliciousExportURL = "https://osv-vulnerabilities.storage.googleapis.com/"
	// maliciousRecordsURL is the default object recorded for -osv.
	maliciousRecordsURL = "https://github.com/ossf/malicious-packages"

	// popularMaxInput caps one popular-name list file (a ranked list of
	// 10,000 names was 370 KB on 2026-11-06).
	popularMaxInput = 16 << 20
)

// secIndexOptions is one secindex publish.
type secIndexOptions struct {
	singleFeedOptions
	Kind content.Kind

	// The malicious kind: OSVExport (the publisher's mirror, one directory
	// per OSV ecosystem name holding all.zip and source.json) or OSVDir
	// (loose OSV records, *.json, walked), exactly one; MinReports refuses
	// a list built from fewer MAL- reports (a truncated input).
	OSVExport  string
	OSVDir     string
	MinReports int

	// The popular kind: one list file per ecosystem; MinNames refuses an
	// ecosystem with fewer names (a truncated or empty response).
	Popular  map[secfeed.Ecosystem]string
	MinNames int

	// Source and License describe the published bytes; SourceURL is the
	// upstream recorded in the manifest entry. The malicious kind has
	// defaults for all three; the popular kind requires them, since only
	// the caller knows where its lists came from.
	Source    string
	License   string
	SourceURL string
}

// secIndexResult is one publish's outcome.
type secIndexResult struct {
	singleFeedResult
	// Lines are the summary lines (what was read, per ecosystem).
	Lines []string
}

// popularFlags is the repeatable -popular eco=FILE flag.
type popularFlags map[secfeed.Ecosystem]string

func (p popularFlags) String() string { return fmt.Sprint(map[secfeed.Ecosystem]string(p)) }

func (p popularFlags) Set(v string) error {
	eco, file, ok := strings.Cut(v, "=")
	if !ok || file == "" {
		return fmt.Errorf("want eco=FILE, got %q", v)
	}
	if _, known := secfeed.EcosystemOf(secfeed.Ecosystem(eco)); !known {
		return fmt.Errorf("unknown ecosystem %q (known: %s)", eco, strings.Join(gateEcosystemIDs(), ", "))
	}
	if _, dup := p[secfeed.Ecosystem(eco)]; dup {
		return fmt.Errorf("ecosystem %q is named twice", eco)
	}
	p[secfeed.Ecosystem(eco)] = file
	return nil
}

func runSecIndex(args []string, out *os.File) error {
	fsx := flag.NewFlagSet("secindex", flag.ContinueOnError)
	kind := fsx.String("kind", "", "the one kind to publish: security.malicious_packages or security.popular_names")
	osvExport := fsx.String("osv-export", "", "malicious: the mirrored OSV exports, <dir>/<OSV ecosystem>/all.zip + source.json")
	osvDir := fsx.String("osv", "", "malicious: a directory of loose OSV records (*.json, walked)")
	minReports := fsx.Int("min-reports", 1, "malicious: refuse a list built from fewer MAL- reports")
	minNames := fsx.Int("min-names", 1, "popular: refuse an ecosystem list with fewer names")
	source := fsx.String("source", "", "the source label recorded in the manifest entry (popular: required)")
	license := fsx.String("license", "", "the SPDX license of the published bytes (popular: required)")
	sourceURL := fsx.String("source-url", "", "the https upstream recorded in the manifest entry (popular: required)")
	pop := popularFlags{}
	fsx.Var(pop, "popular", "popular: eco=FILE, one list per install-gate ecosystem (repeatable)")
	done := singleFeedFlags(fsx)
	if err := fsx.Parse(args); err != nil {
		return err
	}
	o, err := done("secindex")
	if err != nil {
		return err
	}
	res, err := buildSecIndex(secIndexOptions{
		singleFeedOptions: o, Kind: content.Kind(*kind),
		OSVExport: *osvExport, OSVDir: *osvDir, MinReports: *minReports,
		Popular: pop, MinNames: *minNames,
		Source: *source, License: *license, SourceURL: *sourceURL,
	})
	if err != nil {
		return err
	}
	printSingleFeed(out, "secindex", res.singleFeedResult, res.Lines)
	return nil
}

// buildSecIndex builds, checks and publishes one kind.
func buildSecIndex(o secIndexOptions) (secIndexResult, error) {
	switch o.Kind {
	case content.MaliciousPackages:
		if len(o.Popular) > 0 {
			return secIndexResult{}, errors.New("vendorsign secindex: -popular belongs to security.popular_names; publish each kind in its own run")
		}
		return buildMaliciousIndex(o)
	case content.PopularNames:
		if o.OSVExport != "" || o.OSVDir != "" {
			return secIndexResult{}, errors.New("vendorsign secindex: -osv and -osv-export belong to security.malicious_packages; publish each kind in its own run")
		}
		return buildPopularIndex(o)
	}
	return secIndexResult{}, fmt.Errorf("vendorsign secindex: -kind must be %s or %s, got %q", content.MaliciousPackages, content.PopularNames, o.Kind)
}

// buildMaliciousIndex reads the MAL- reports and publishes malicious.idx.
func buildMaliciousIndex(o secIndexOptions) (secIndexResult, error) {
	if (o.OSVExport == "") == (o.OSVDir == "") {
		return secIndexResult{}, errors.New("vendorsign secindex: security.malicious_packages needs exactly one of -osv-export DIR and -osv DIR")
	}
	if o.MinReports < 1 {
		return secIndexResult{}, errors.New("vendorsign secindex: -min-reports must be at least 1")
	}
	b := secfeed.NewMaliciousBuilder()
	var lines []string
	version := o.Now.UTC().Format("2006-01-02")
	object := maliciousRecordsURL
	if o.OSVExport != "" {
		newest, read, err := readMaliciousExports(o.OSVExport, b)
		if err != nil {
			return secIndexResult{}, err
		}
		lines, object = read, maliciousExportURL
		version = "osv " + newest
	} else if err := readMaliciousRecords(o.OSVDir, b); err != nil {
		return secIndexResult{}, err
	}
	if o.SourceURL != "" {
		object = o.SourceURL
	}
	entries, st := b.Entries()
	if st.Kept < o.MinReports {
		return secIndexResult{}, fmt.Errorf("vendorsign secindex: %d MAL- reports kept, under -min-reports %d; refusing to publish a truncated malicious list", st.Kept, o.MinReports)
	}
	data := secfeed.EncodeMalicious(entries)
	if err := secfeed.ValidateIndex(data, false); err != nil {
		return secIndexResult{}, fmt.Errorf("vendorsign secindex: the built malicious list fails the node's check, so nothing is signed: %w", err)
	}
	lines = append(lines, fmt.Sprintf("%d OSV records, %d MAL- reports kept (%d not MAL-, %d withdrawn, %d other ecosystems, %d malformed); %d packages, %s %d bytes",
		st.Records, st.Kept, st.NotMAL, st.Withdrawn, st.UnknownEco, st.Malformed, len(entries), secfeed.MaliciousArtifact, len(data)))
	return publishSecIndex(o, content.MaliciousPackages, maliciousValidity, singleFeedArtifact{
		name: secfeed.MaliciousArtifact, data: data, version: version,
		source: orDefault(o.Source, maliciousSourceLabel), license: orDefault(o.License, maliciousLicense), object: object,
	}, lines)
}

// readMaliciousExports feeds every record of each install-gate
// ecosystem's mirrored export to b, after checking the export against the
// checksums its source.json recorded. Every ecosystem of secfeed's table
// must be there. It returns the newest export's last-modified time and one
// summary line per ecosystem.
func readMaliciousExports(dir string, b *secfeed.MaliciousBuilder) (newest string, lines []string, err error) {
	for _, spec := range secfeed.Ecosystems() {
		in, err := checkOSVInput("secindex", filepath.Join(dir, spec.OSV), spec.OSV, "ecosystem")
		if err != nil {
			return "", nil, fmt.Errorf("%w (the malicious list needs the export of every ecosystem the install gate checks: %s)", err, strings.Join(gateEcosystemOSV(), ", "))
		}
		kept, listed := b.Stats().Kept, b.Len()
		n, err := addExportRecords(in.path, b)
		if err != nil {
			return "", nil, fmt.Errorf("vendorsign secindex: %s: %w", spec.OSV, err)
		}
		lines = append(lines, fmt.Sprintf("%s: generation %s, %d records, %d MAL- reports, +%d packages listed",
			spec.OSV, orDefault(in.src.Generation, "-"), n, b.Stats().Kept-kept, b.Len()-listed))
		if in.src.LastModified > newest {
			newest = in.src.LastModified
		}
	}
	return newest, lines, nil
}

// addExportRecords feeds every record of one OSV export zip to b. An entry
// is read up to one byte past the record cap, so an oversized record is
// counted malformed without being read whole.
func addExportRecords(path string, b *secfeed.MaliciousBuilder) (int, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return 0, fmt.Errorf("%s does not open as a zip: %w", filepath.Base(path), err)
	}
	defer func() { _ = r.Close() }()
	n := 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return n, fmt.Errorf("%s: %w", f.Name, err)
		}
		raw, err := io.ReadAll(io.LimitReader(rc, secfeed.MaxOSVRecordBytes+1))
		_ = rc.Close()
		if err != nil {
			return n, fmt.Errorf("%s: %w", f.Name, err)
		}
		b.Add(raw)
		n++
	}
	return n, nil
}

// readMaliciousRecords feeds every *.json record under dir to b.
func readMaliciousRecords(dir string, b *secfeed.MaliciousBuilder) error {
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		f, err := os.Open(p) //nolint:gosec // operator-supplied input tree
		if err != nil {
			return err
		}
		// One byte past the cap: an oversized record is counted malformed
		// (MaliciousBuilder.Add) without being read whole.
		raw, err := io.ReadAll(io.LimitReader(f, secfeed.MaxOSVRecordBytes+1))
		_ = f.Close()
		if err != nil {
			return err
		}
		b.Add(raw)
		return nil
	})
	if err != nil {
		return fmt.Errorf("vendorsign secindex: %w", err)
	}
	return nil
}

// buildPopularIndex reads one list per install-gate ecosystem and
// publishes popular.idx.
func buildPopularIndex(o secIndexOptions) (secIndexResult, error) {
	if o.Source == "" || o.License == "" || o.SourceURL == "" {
		return secIndexResult{}, errors.New("vendorsign secindex: security.popular_names needs -source, -license and -source-url (where the lists came from)")
	}
	if err := checkSourceURL("secindex", o.SourceURL); err != nil {
		return secIndexResult{}, err
	}
	if o.MinNames < 1 {
		return secIndexResult{}, errors.New("vendorsign secindex: -min-names must be at least 1")
	}
	var missing []string
	for _, spec := range secfeed.Ecosystems() {
		if _, ok := o.Popular[spec.Eco]; !ok {
			missing = append(missing, string(spec.Eco))
		}
	}
	if len(missing) > 0 {
		return secIndexResult{}, fmt.Errorf("vendorsign secindex: no -popular list for %s; every ecosystem the install gate checks needs one (a node reads a missing ecosystem as no near miss)", strings.Join(missing, ", "))
	}
	popular := map[secfeed.Ecosystem][]string{}
	var lines []string
	for _, spec := range secfeed.Ecosystems() {
		path := o.Popular[spec.Eco]
		raw, err := readInputFile("secindex", path, popularMaxInput)
		if err != nil {
			return secIndexResult{}, err
		}
		names, err := parsePopularList(spec.Eco, raw)
		if err != nil {
			return secIndexResult{}, fmt.Errorf("vendorsign secindex: %s (%s): %w", spec.Eco, path, err)
		}
		if len(names) < o.MinNames {
			return secIndexResult{}, fmt.Errorf("vendorsign secindex: %s (%s) lists %d names, under -min-names %d; refusing a truncated list", spec.Eco, path, len(names), o.MinNames)
		}
		popular[spec.Eco] = names
		lines = append(lines, fmt.Sprintf("%s: %d names", spec.Eco, len(names)))
	}
	data := secfeed.EncodePopular(popular)
	if err := secfeed.ValidateIndex(data, true); err != nil {
		return secIndexResult{}, fmt.Errorf("vendorsign secindex: the built popular list fails the node's check, so nothing is signed: %w", err)
	}
	lines = append(lines, fmt.Sprintf("%s %d bytes", secfeed.PopularArtifact, len(data)))
	return publishSecIndex(o, content.PopularNames, popularValidity, singleFeedArtifact{
		name: secfeed.PopularArtifact, data: data, version: o.Now.UTC().Format("2006-01-02"),
		source: o.Source, license: o.License, object: o.SourceURL,
	}, lines)
}

// parsePopularList reads one list: a JSON array of names (a ranked list as
// served, first non-blank byte '[') or one name per line.
func parsePopularList(eco secfeed.Ecosystem, raw []byte) ([]string, error) {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return secfeed.PopularFromList(eco, raw)
	}
	var names []string
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	if err := dec.Decode(&names); err != nil {
		return nil, fmt.Errorf("not a JSON array of names: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON array")
	}
	return secfeed.PopularFromNames(eco, names)
}

// publishSecIndex signs and writes one kind through the small-feed path.
func publishSecIndex(o secIndexOptions, kind content.Kind, validity time.Duration, art singleFeedArtifact, lines []string) (secIndexResult, error) {
	o.Validity = validity
	res, err := publishSingleFeed(o.singleFeedOptions, "secindex", kind, []singleFeedArtifact{art})
	if err != nil {
		return secIndexResult{}, err
	}
	return secIndexResult{singleFeedResult: res, Lines: lines}, nil
}

// gateEcosystemIDs and gateEcosystemOSV list the install gate's
// ecosystems, as the index and as OSV spell them.
func gateEcosystemIDs() []string {
	var out []string
	for _, s := range secfeed.Ecosystems() {
		out = append(out, string(s.Eco))
	}
	sort.Strings(out)
	return out
}

func gateEcosystemOSV() []string {
	var out []string
	for _, s := range secfeed.Ecosystems() {
		out = append(out, s.OSV)
	}
	return out
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
