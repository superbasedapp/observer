package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// feedsingle.go is the publish path the small feed kinds share (the
// exploit-likelihood kinds security.kev and security.epss, OS and CI
// scanning plan section 14.7, and the install gate's index kinds
// security.malicious_packages and security.popular_names, secindex.go):
// one or more artifacts the verb builds whole
// each run, no base and no delta. Past the build it is osvexport's path
// exactly, through the helpers that file owns: the content-feed key check
// (loadFeedKey), the state directory's kind mark (claimFeedState), the
// unchanged / re-sign decision and the counters (nextFeedPublish), and the
// state written last (writeFeedState). Output:
//
//	<out>/<kind>/<artifact>... + manifest.json (written last)
//
// State, one directory per kind:
//
//	<state>/kind, <state>/state.json, <state>/manifest.json

// singleFeedOptions is one publish of a small feed kind.
type singleFeedOptions struct {
	Key   ed25519.PrivateKey
	State string
	Out   string
	// ManifestVersion is the version to publish; 0 means the state's last
	// plus one.
	ManifestVersion int64
	Reissue         time.Duration
	Now             time.Time
	// Validity is the manifest's lifetime; 0 means the kind's MaxValidity,
	// and a longer one is refused (nodes would refuse the manifest).
	Validity time.Duration
}

// singleFeedArtifact is one artifact of a publish, built whole in memory.
type singleFeedArtifact struct {
	name string
	data []byte
	// version is the entry's version label (the upstream's catalog version
	// or model and date); source, license and object describe the bytes.
	version string
	source  string
	license string
	// object is the upstream https URL the input was fetched from.
	object string
}

// singleFeedResult is one publish's outcome.
type singleFeedResult struct {
	Unchanged       bool
	ManifestVersion int64
	Epoch           int64
}

// singleFeedFlags are the flags every small feed verb shares, registered
// on fs; done returns the options once fs is parsed.
func singleFeedFlags(fs *flag.FlagSet) (done func(verb string) (singleFeedOptions, error)) {
	keyPath := fs.String("key", "", "content-feed signing key file (content-feed.key)")
	state := fs.String("state", "", "state directory owned by this tool (counters, last manifest); one per kind")
	outDir := fs.String("out", "", "output directory")
	version := fs.Int64("manifest-version", 0, "manifest version to publish (default: the state's last + 1)")
	reissueHours := fs.Int("reissue-hours", 20, "re-sign an unchanged manifest once it is this many hours old")
	allowUnpinned := fs.Bool("allow-unpinned-key", false, "sign with a key this tree's agents do not accept as a content-feed key (rotation step 4 only)")
	return func(verb string) (singleFeedOptions, error) {
		if *keyPath == "" || *state == "" || *outDir == "" {
			// Each verb checks its own inputs (-in, -osv-export, -popular).
			return singleFeedOptions{}, fmt.Errorf("vendorsign %s: -key, -state and -out are required", verb)
		}
		if *version < 0 || *reissueHours < 0 {
			return singleFeedOptions{}, fmt.Errorf("vendorsign %s: want -manifest-version >= 0 and -reissue-hours >= 0", verb)
		}
		priv, err := loadFeedKey(*keyPath, *allowUnpinned)
		if err != nil {
			return singleFeedOptions{}, err
		}
		return singleFeedOptions{
			Key: priv, State: *state, Out: *outDir, ManifestVersion: *version,
			Reissue: time.Duration(*reissueHours) * time.Hour, Now: time.Now().UTC(),
		}, nil
	}
}

// checkSourceURL refuses an upstream object that is not an https URL.
func checkSourceURL(verb, s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("vendorsign %s: -source-url must be an https URL, got %q", verb, s)
	}
	return nil
}

// publishSingleFeed signs and writes one publish of kind: unchanged when
// no artifact's digest moved and the last manifest is younger than the
// reissue interval (nothing written), else the artifacts and then the
// manifest into <out>/<kind>/ and the state last. A failure leaves the
// state and the last output as they were.
func publishSingleFeed(o singleFeedOptions, verb string, kind content.Kind, arts []singleFeedArtifact) (singleFeedResult, error) {
	if len(o.Key) != ed25519.PrivateKeySize || o.State == "" || o.Out == "" || o.Reissue < 0 {
		return singleFeedResult{}, fmt.Errorf("vendorsign %s: key, state and output are required", verb)
	}
	if len(arts) == 0 {
		return singleFeedResult{}, fmt.Errorf("vendorsign %s: nothing to publish", verb)
	}
	ks, ok := content.KindOf(kind)
	if !ok || ks.Class != content.ClassFeed {
		return singleFeedResult{}, fmt.Errorf("vendorsign %s: %s is not a feed kind of the content channel", verb, kind)
	}
	validity := ks.MaxValidity
	if o.Validity != 0 {
		if o.Validity < 0 || o.Validity > ks.MaxValidity {
			return singleFeedResult{}, fmt.Errorf("vendorsign %s: validity %s is outside %s's bound (0, %s]", verb, o.Validity, kind, ks.MaxValidity)
		}
		validity = o.Validity
	}
	now := o.Now.UTC().Truncate(time.Second)
	if err := claimFeedState(o.State, verb, kind); err != nil {
		return singleFeedResult{}, err
	}
	st, err := loadOSVState(o.State)
	if err != nil {
		return singleFeedResult{}, err
	}
	artifacts := map[string]string{}
	for _, a := range arts {
		if _, dup := artifacts[a.name]; dup || a.name == "manifest.json" {
			return singleFeedResult{}, fmt.Errorf("vendorsign %s: artifact name %q repeats or is reserved", verb, a.name)
		}
		artifacts[a.name] = content.HashBytes(a.data)
	}
	unchanged, version, epoch, err := nextFeedPublish(verb, st, artifacts, now, o.Reissue, o.ManifestVersion)
	if err != nil {
		return singleFeedResult{}, err
	}
	if unchanged {
		return singleFeedResult{Unchanged: true}, nil
	}

	stamp := now.Format(time.RFC3339)
	entries := make([]content.Entry, 0, len(arts))
	for _, a := range arts {
		entries = append(entries, content.Entry{
			Name: a.name, Version: a.version, SizeBytes: int64(len(a.data)), SHA256: artifacts[a.name],
			Source: a.source, License: a.license,
			// The upstreams publish no checksum or signature to check, so the
			// record names where the input came from and when, and the
			// content-feed signature is the origin.
			Upstream: content.UpstreamCheck{Method: content.UpstreamNone, Object: a.object, VerifiedAt: stamp, VerifiedWhere: "release_pipeline"},
		})
	}
	content.SortEntries(entries)
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: kind, ManifestVersion: version, Epoch: epoch,
		IssuedAt: stamp, ExpiresAt: now.Add(validity).Format(time.RFC3339), Entries: entries,
	}
	env, err := content.SignFeed(m, o.Key)
	if err != nil {
		return singleFeedResult{}, fmt.Errorf("vendorsign %s: %w", verb, err)
	}
	envBytes, err := content.EncodeEnvelope(env)
	if err != nil {
		return singleFeedResult{}, err
	}
	if len(envBytes) > content.MaxEnvelopeBytes {
		return singleFeedResult{}, fmt.Errorf("vendorsign %s: the envelope is %d bytes, over the %d nodes accept", verb, len(envBytes), content.MaxEnvelopeBytes)
	}

	dir := filepath.Join(o.Out, string(kind))
	if err := os.RemoveAll(dir); err != nil {
		return singleFeedResult{}, fmt.Errorf("vendorsign %s: clear %s: %w", verb, dir, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // public feed artifacts
		return singleFeedResult{}, fmt.Errorf("vendorsign %s: %w", verb, err)
	}
	for _, a := range arts {
		if err := writeFileAtomic(filepath.Join(dir, a.name), a.data, 0o644); err != nil {
			return singleFeedResult{}, err
		}
	}
	if err := writeFileAtomic(filepath.Join(dir, "manifest.json"), envBytes, 0o644); err != nil {
		return singleFeedResult{}, err
	}
	next := osvExportState{ManifestVersion: version, Epoch: epoch, IssuedAt: stamp, Artifacts: artifacts}
	if err := writeFeedState(o.State, verb, next, envBytes); err != nil {
		return singleFeedResult{}, err
	}
	return singleFeedResult{ManifestVersion: version, Epoch: epoch}, nil
}

// printSingleFeed writes a publish's summary: "unchanged", or the lines
// the verb built and the manifest's counters.
func printSingleFeed(out io.Writer, verb string, res singleFeedResult, lines []string) {
	if res.Unchanged {
		fmt.Fprintln(out, "unchanged")
		return
	}
	for _, l := range lines {
		fmt.Fprintf(out, "%s: %s\n", verb, l)
	}
	fmt.Fprintf(out, "%s: manifest_version %d, epoch %d\n", verb, res.ManifestVersion, res.Epoch)
}

// readInputFile reads an operator-supplied input file, refusing one over
// limit bytes before reading it.
func readInputFile(verb, path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied input file
	if err != nil {
		return nil, fmt.Errorf("vendorsign %s: %w", verb, err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("vendorsign %s: read %s: %w", verb, path, err)
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("vendorsign %s: %s is over %d bytes", verb, path, limit)
	}
	return raw, nil
}
