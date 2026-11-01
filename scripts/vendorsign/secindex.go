package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// secindex.go is the `vendorsign secindex` verb, the install-index builder
// of security Phase D1 (security pillar plan sections 5.4 and 8.5): it
// turns a local copy of the OpenSSF malicious-packages OSV records and the
// per-ecosystem popular-name lists into the two index artifacts, and signs
// one content manifest per kind (the signed content channel, F0-6). It
// reads local files only: fetching the upstream data (a git clone of
// github.com/ossf/malicious-packages, the popular lists) is the release
// pipeline's step, so this tool has no network code.
//
// Output, one directory per kind, the layout a node's content store and
// the feed host both use:
//
//	<out>/security.malicious_packages/manifest.json + malicious.idx
//	<out>/security.popular_names/manifest.json + popular.idx

// secIndexOptions is one build.
type secIndexOptions struct {
	OSVDir          string
	Popular         map[secfeed.Ecosystem]string
	Out             string
	ManifestVersion int64
	Epoch           int64
	Issued          time.Time
	Key             ed25519.PrivateKey
}

// secIndexKind is one kind the build publishes.
type secIndexKind struct {
	kind    content.Kind
	name    string
	data    []byte
	source  string
	license string
	valid   time.Duration
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
		return fmt.Errorf("unknown ecosystem %q", eco)
	}
	p[secfeed.Ecosystem(eco)] = file
	return nil
}

func runSecIndex(args []string, out *os.File) error {
	fsx := flag.NewFlagSet("secindex", flag.ContinueOnError)
	keyPath := fsx.String("key", "", "vendor signing key file")
	osvDir := fsx.String("osv", "", "directory of OSV malicious-package records (*.json, walked)")
	outDir := fsx.String("out", "", "output directory")
	version := fsx.Int64("manifest-version", 0, "monotonic manifest version for both kinds")
	epoch := fsx.Int64("epoch", 1, "data epoch for both kinds")
	allowUnpinned := fsx.Bool("allow-unpinned-key", false, "sign with a key this tree's agents do not accept (rotation step 4 only)")
	pop := popularFlags{}
	fsx.Var(pop, "popular", "eco=FILE popular-name list, one name per line (repeatable)")
	if err := fsx.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *osvDir == "" || *outDir == "" || *version <= 0 {
		return errors.New("vendorsign secindex: -key, -osv, -out and a positive -manifest-version are required")
	}
	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	warn, err := checkKeyIsPinned(priv, *allowUnpinned)
	if err != nil {
		return err
	}
	if warn != "" {
		fmt.Fprintln(os.Stderr, warn)
	}
	st, err := buildSecIndex(secIndexOptions{
		OSVDir: *osvDir, Popular: pop, Out: *outDir, ManifestVersion: *version, Epoch: *epoch,
		Issued: time.Now().UTC(), Key: priv,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "secindex: %d OSV records, %d MAL- reports kept (%d not MAL-, %d withdrawn, %d other ecosystems, %d malformed)\n",
		st.Records, st.Kept, st.NotMAL, st.Withdrawn, st.UnknownEco, st.Malformed)
	return nil
}

// buildSecIndex builds, signs and writes both kinds.
func buildSecIndex(o secIndexOptions) (secfeed.BuildStats, error) {
	var records [][]byte
	err := filepath.WalkDir(o.OSVDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // operator-supplied input tree
		if err != nil {
			return err
		}
		records = append(records, b)
		return nil
	})
	if err != nil {
		return secfeed.BuildStats{}, fmt.Errorf("vendorsign secindex: %w", err)
	}
	entries, st := secfeed.MaliciousFromOSV(records)
	if st.Kept == 0 {
		return st, errors.New("vendorsign secindex: no MAL- report found; refusing to publish an empty malicious list")
	}
	popular := map[secfeed.Ecosystem][]string{}
	ecos := make([]string, 0, len(o.Popular))
	for eco := range o.Popular {
		ecos = append(ecos, string(eco))
	}
	sort.Strings(ecos)
	for _, e := range ecos {
		eco := secfeed.Ecosystem(e)
		b, err := os.ReadFile(o.Popular[eco])
		if err != nil {
			return st, fmt.Errorf("vendorsign secindex: %w", err)
		}
		names, err := secfeed.PopularFromList(eco, b)
		if err != nil {
			return st, err
		}
		popular[eco] = names
	}
	kinds := []secIndexKind{
		{content.MaliciousPackages, secfeed.MaliciousArtifact, secfeed.EncodeMalicious(entries), "osv:MAL (github.com/ossf/malicious-packages)", "Apache-2.0", 7 * 24 * time.Hour},
	}
	if len(popular) > 0 {
		kinds = append(kinds, secIndexKind{content.PopularNames, secfeed.PopularArtifact, secfeed.EncodePopular(popular), "observer:popular-names", "CC0-1.0", 30 * 24 * time.Hour})
	}
	for _, k := range kinds {
		m, err := secfeed.BuildManifest(secfeed.ManifestInput{
			Kind: k.kind, ManifestVersion: o.ManifestVersion, Epoch: o.Epoch, Issued: o.Issued, Validity: k.valid,
			Name: k.name, Data: k.data, Version: o.Issued.Format("2006-01-02"), Source: k.source, License: k.license,
		})
		if err != nil {
			return st, err
		}
		env, err := content.Sign(m, o.Key)
		if err != nil {
			return st, err
		}
		envBytes, err := content.EncodeEnvelope(env)
		if err != nil {
			return st, err
		}
		dir := filepath.Join(o.Out, string(k.kind))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return st, fmt.Errorf("vendorsign secindex: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, k.name), k.data, 0o644); err != nil { //nolint:gosec // public feed artifacts
			return st, fmt.Errorf("vendorsign secindex: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), envBytes, 0o644); err != nil { //nolint:gosec // public feed artifacts
			return st, fmt.Errorf("vendorsign secindex: %w", err)
		}
	}
	return st, nil
}
