package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshardkey"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// osvshards.go is the `vendorsign osvshards` verb, the publisher of the
// security.osv_shards content kind (remote matching M1, OS and CI
// vulnerability scanning plan sections 13.3 and 13.11, lane RM-1; spike
// docs/plans/spikes/RM-0-remote-shards-2026-11.md). It splits each OSV
// export into hash-prefix shards so a node can look up only the shards its
// packages fall in instead of downloading the whole export. The key, the
// prefix lengths and the object format belong to
// internal/secscan/osvshardkey; this file only builds them.
//
// Input (either or both):
//
//	-lang <in>/<eco>/all.zip + source.json  the language exports, exactly
//	                                        osvexport's -in (checked against
//	                                        the bucket's checksums again)
//	-os   <dir>/<Artifact>.zip              the per-release OS files
//	                                        osvosexport cut (its
//	                                        <state>/stripped directory)
//
// A set is one language ecosystem (named osvdb.ArtifactBase: "npm",
// "GitHub-Actions") or one OS release (osvdb.OSRelease.Artifact:
// "Debian-12", "Ubuntu-24.04-LTS").
//
// Output:
//
//	<out>/security.osv_shards/<Set>.set.json   each set's descriptor
//	<out>/security.osv_shards/manifest.json    the signed manifest, last
//	<objects>/<Set>/obj/<sha256>.json.gz       the shards
//	<objects>/<Set>/index/<sha256>.json        the index files
//	<objects>/objects.txt                      every object path the
//	                                           published descriptors name,
//	                                           sorted, one per line
//
// The object store is content-addressed and kept across runs: an unchanged
// shard keeps its name and file, so the uploader sends only the paths of
// objects.txt it has not uploaded before. After a publish the store is
// pruned to exactly what objects.txt names.
//
// State (one directory, marked for this kind):
//
//	<state>/kind, state.json, manifest.json   as every feed verb
//	<state>/sets.json                         per set: the input digest,
//	                                          bits, epoch, content digest
//	<state>/sets/<Set>.set.json               the last descriptor of each
//	                                          set
//	<state>/work/                             one build's spill file
//
// A set whose input digest, bits and build format are unchanged and whose
// objects are all in the store is not rebuilt: its last descriptor is
// reused. Otherwise it is rebuilt from scratch.
//
// Determinism: records are read in entry-name order, each record is split
// per prefix (strip mode: only the affected entries whose names hash into
// the prefix, every other field and the field order kept, written
// compact), a shard is a JSON array of its records in entry-name order,
// gzip at best compression with a zero header, and every index file and
// descriptor is the compact JSON of its struct. So the same input always
// gives byte-identical objects, and the same objects the same names. A Go
// release that changes compress/flate's output would rename every rebuilt
// shard once (a one-time re-upload, nothing else).
//
// Memory: each record is split as it is read and its per-prefix copies are
// deflated into a spill file on disk, keeping only a small reference per
// copy in memory; each shard is then assembled from the spill. Peak memory
// is the zip directory, the references and one shard (at most
// osvshardkey.MaxShardBytes compressed), never the export.
//
// Epochs: a set's epoch moves when the content of its descriptor (every
// object it names, its bits and its counts) changed; the manifest's epoch
// moves when any descriptor changed (nextFeedPublish).

const (
	osvShardsVerb = "osvshards"
	// osvShardsFormat is the build's format number: bump it when the build
	// would write other bytes for the same input, so every set is rebuilt
	// once instead of reused.
	osvShardsFormat = 1
	// osvShardsSetsFile and osvShardsSetsDir are the per-set state.
	osvShardsSetsFile = "sets.json"
	osvShardsSetsDir  = "sets"
	// osvShardsObjectsList is the object store's list of referenced paths.
	osvShardsObjectsList = "objects.txt"
	// osvShardsSource labels the descriptors' bytes.
	osvShardsSource   = "osv.dev export bucket, split into hash-prefix shards by SuperBased"
	osvShardsOSSource = "osv.dev export bucket, stripped per release and split into hash-prefix shards by SuperBased"
)

// osvShardMaxBytes is the shard cap the build holds every shard to and
// writes into each descriptor: osvshardkey.MaxShardBytes, a variable only so
// a test can lower it.
var osvShardMaxBytes int64 = osvshardkey.MaxShardBytes

// osvShardsOptions is one publish.
type osvShardsOptions struct {
	Key ed25519.PrivateKey
	// Lang and OS are the two inputs; at least one is set.
	Lang    string
	OS      string
	State   string
	Objects string
	Out     string
	// ManifestVersion is the version to publish; 0 means the state's last
	// plus one.
	ManifestVersion int64
	Reissue         time.Duration
	Now             time.Time
	// Bits overrides osvshardkey.NameRules' bits per base ecosystem.
	Bits map[string]int
}

// shardSetInput is one set's checked input.
type shardSetInput struct {
	set       string
	ecosystem string
	base      string
	path      string
	sha256    string
	license   string
	source    string
	upstream  content.UpstreamCheck
	version   string
}

// shardSetState is one set's entry in sets.json.
type shardSetState struct {
	InputSHA256   string `json:"input_sha256"`
	Format        int    `json:"format"`
	Bits          int    `json:"bits"`
	Epoch         int64  `json:"epoch"`
	ContentSHA256 string `json:"content_sha256"`
	SetSHA256     string `json:"set_sha256"`
}

// shardsState is sets.json.
type shardsState struct {
	Sets map[string]shardSetState `json:"sets"`
}

// shardStats are one built set's shard sizes, for the summary.
type shardStats struct {
	median, p95, max int64
}

// shardSetBuild is one set's outcome.
type shardSetBuild struct {
	in      shardSetInput
	desc    osvshardkey.SetDescriptor
	data    []byte
	objects []string
	reused  bool
	stats   shardStats
	st      shardSetState
}

// osvShardsResult is one publish's outcome.
type osvShardsResult struct {
	Unchanged       bool
	ManifestVersion int64
	Epoch           int64
	Sets            []shardSetBuild
	// Omitted names the sets left out because no record keyed into them.
	Omitted     []string
	Objects     int
	ObjectBytes int64
}

func runOSVShards(args []string, out *os.File) error {
	fsx := flag.NewFlagSet(osvShardsVerb, flag.ContinueOnError)
	keyPath := fsx.String("key", "", "content-feed signing key file (content-feed.key)")
	lang := fsx.String("lang", "", "language input: <eco>/all.zip + <eco>/source.json per ecosystem (osvexport's -in)")
	osDir := fsx.String("os", "", "OS input: <Artifact>.zip per release (osvosexport's <state>/stripped)")
	state := fsx.String("state", "", "state directory owned by this tool (per-set state, counters, last manifest)")
	objects := fsx.String("objects", "", "content-addressed object store (shards and index files), kept across runs")
	outDir := fsx.String("out", "", "output directory")
	version := fsx.Int64("manifest-version", 0, "manifest version to publish (default: the state's last + 1)")
	reissueHours := fsx.Int("reissue-hours", 20, "re-sign an unchanged manifest once it is this many hours old")
	allowUnpinned := fsx.Bool("allow-unpinned-key", false, "sign with a key this tree's agents do not accept as a content-feed key (rotation step 4 only)")
	if err := fsx.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *state == "" || *objects == "" || *outDir == "" || (*lang == "" && *osDir == "") {
		return errors.New("vendorsign osvshards: -key, -state, -objects, -out and at least one of -lang and -os are required")
	}
	if *version < 0 || *reissueHours < 0 {
		return errors.New("vendorsign osvshards: want -manifest-version >= 0 and -reissue-hours >= 0")
	}
	priv, err := loadFeedKey(*keyPath, *allowUnpinned)
	if err != nil {
		return err
	}
	res, err := buildOSVShards(osvShardsOptions{
		Key: priv, Lang: *lang, OS: *osDir, State: *state, Objects: *objects, Out: *outDir,
		ManifestVersion: *version, Reissue: time.Duration(*reissueHours) * time.Hour, Now: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	printOSVShards(out, res)
	return nil
}

// buildOSVShards builds, signs and writes one publish. A failure leaves the
// state, the output and objects.txt as they were (the store may hold new
// objects nothing names yet; the next publish prunes them).
func buildOSVShards(o osvShardsOptions) (osvShardsResult, error) {
	verb := osvShardsVerb
	if len(o.Key) != ed25519.PrivateKeySize || o.State == "" || o.Objects == "" || o.Out == "" || (o.Lang == "" && o.OS == "") || o.Reissue < 0 {
		return osvShardsResult{}, fmt.Errorf("vendorsign %s: key, an input, state, objects and output are required", verb)
	}
	ks, ok := content.KindOf(content.OSVShards)
	if !ok || ks.Class != content.ClassFeed {
		return osvShardsResult{}, fmt.Errorf("vendorsign %s: %s is not a feed kind of the content channel", verb, content.OSVShards)
	}
	now := o.Now.UTC().Truncate(time.Second)
	if err := claimFeedState(o.State, verb, content.OSVShards); err != nil {
		return osvShardsResult{}, err
	}
	inputs, err := shardInputs(o, now)
	if err != nil {
		return osvShardsResult{}, err
	}
	st, err := loadOSVState(o.State)
	if err != nil {
		return osvShardsResult{}, err
	}
	sst, err := loadShardsState(o.State)
	if err != nil {
		return osvShardsResult{}, err
	}
	work := filepath.Join(o.State, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		return osvShardsResult{}, fmt.Errorf("vendorsign %s: %w", verb, err)
	}
	if err := os.MkdirAll(o.Objects, 0o755); err != nil { //nolint:gosec // public feed objects
		return osvShardsResult{}, fmt.Errorf("vendorsign %s: %w", verb, err)
	}

	var builds []shardSetBuild
	var omitted []string
	for _, in := range inputs {
		bits, err := shardBits(o, in.base)
		if err != nil {
			return osvShardsResult{}, err
		}
		b, empty, err := planShardSet(o, in, bits, sst.Sets[in.set], work)
		if err != nil {
			return osvShardsResult{}, err
		}
		if empty {
			omitted = append(omitted, in.set)
			continue
		}
		builds = append(builds, b)
	}
	if len(builds) == 0 {
		return osvShardsResult{}, fmt.Errorf("vendorsign %s: no set holds a record; nothing to publish", verb)
	}

	artifacts := map[string]string{}
	refs := map[string]bool{}
	for _, b := range builds {
		artifacts[osvshardkey.SetFile(b.in.set)] = content.HashBytes(b.data)
		for _, p := range b.objects {
			refs[p] = true
		}
	}
	list := make([]string, 0, len(refs))
	for p := range refs {
		list = append(list, p)
	}
	sort.Strings(list)
	res := osvShardsResult{Sets: builds, Omitted: omitted, Objects: len(list)}
	for _, b := range builds {
		res.ObjectBytes += b.desc.ShardBytes
		for _, r := range b.desc.Index {
			res.ObjectBytes += r.Size
		}
	}

	unchanged, version, epoch, err := nextFeedPublish(verb, st, artifacts, now, o.Reissue, o.ManifestVersion)
	if err != nil {
		return osvShardsResult{}, err
	}
	if unchanged {
		// Nothing is published; the per-set state still records this run's
		// inputs so the next run can reuse them.
		if err := saveShardsState(o.State, builds); err != nil {
			return osvShardsResult{}, err
		}
		res.Unchanged = true
		return res, nil
	}

	stamp := now.Format(time.RFC3339)
	entries := make([]content.Entry, 0, len(builds))
	for _, b := range builds {
		entries = append(entries, content.Entry{
			Name: osvshardkey.SetFile(b.in.set), Version: fmt.Sprintf("epoch %d, %d bits", b.desc.Epoch, b.desc.Bits),
			SizeBytes: int64(len(b.data)), SHA256: artifacts[osvshardkey.SetFile(b.in.set)],
			Source: b.in.source, License: b.in.license, Upstream: b.in.upstream,
		})
	}
	content.SortEntries(entries)
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.OSVShards, ManifestVersion: version, Epoch: epoch,
		IssuedAt: stamp, ExpiresAt: now.Add(ks.MaxValidity).Format(time.RFC3339), Entries: entries,
	}
	env, err := content.SignFeed(m, o.Key)
	if err != nil {
		return osvShardsResult{}, fmt.Errorf("vendorsign %s: %w", verb, err)
	}
	envBytes, err := content.EncodeEnvelope(env)
	if err != nil {
		return osvShardsResult{}, err
	}
	if len(envBytes) > content.MaxEnvelopeBytes {
		return osvShardsResult{}, fmt.Errorf("vendorsign %s: the envelope is %d bytes, over the %d nodes accept", verb, len(envBytes), content.MaxEnvelopeBytes)
	}

	// objects.txt first (the uploader's input), then the kind's directory
	// with the manifest last, then the state, then the prune.
	var lb bytes.Buffer
	for _, p := range list {
		lb.WriteString(p)
		lb.WriteByte('\n')
	}
	if err := writeFileAtomic(filepath.Join(o.Objects, osvShardsObjectsList), lb.Bytes(), 0o644); err != nil {
		return osvShardsResult{}, err
	}
	dir := filepath.Join(o.Out, string(content.OSVShards))
	if err := os.RemoveAll(dir); err != nil {
		return osvShardsResult{}, fmt.Errorf("vendorsign %s: clear %s: %w", verb, dir, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // public feed artifacts
		return osvShardsResult{}, fmt.Errorf("vendorsign %s: %w", verb, err)
	}
	for _, b := range builds {
		if err := writeFileAtomic(filepath.Join(dir, osvshardkey.SetFile(b.in.set)), b.data, 0o644); err != nil {
			return osvShardsResult{}, err
		}
	}
	if err := writeFileAtomic(filepath.Join(dir, "manifest.json"), envBytes, 0o644); err != nil {
		return osvShardsResult{}, err
	}
	if err := saveShardsState(o.State, builds); err != nil {
		return osvShardsResult{}, err
	}
	next := osvExportState{ManifestVersion: version, Epoch: epoch, IssuedAt: stamp, Artifacts: artifacts}
	if err := writeFeedState(o.State, verb, next, envBytes); err != nil {
		return osvShardsResult{}, err
	}
	if err := pruneShardObjects(o.Objects, refs); err != nil {
		return osvShardsResult{}, err
	}
	res.ManifestVersion, res.Epoch = version, epoch
	return res, nil
}

// shardBits is base's prefix length: the override, else the NameRules row.
// A base with neither is refused, never published at a guessed length.
func shardBits(o osvShardsOptions, base string) (int, error) {
	bits, ok := o.Bits[base]
	if !ok {
		r, found := osvshardkey.RuleFor(base)
		if !found {
			return 0, fmt.Errorf("vendorsign %s: ecosystem %q has no row in osvshardkey.NameRules; add one with its bits", osvShardsVerb, base)
		}
		bits = r.DefaultBits
	}
	if !osvshardkey.ValidBits(bits) {
		return 0, fmt.Errorf("vendorsign %s: %s: bits %d out of range", osvShardsVerb, base, bits)
	}
	return bits, nil
}

// shardInputs checks and lists every set's input, sorted by set name. The
// language inputs are checked against their source.json exactly as
// osvexport checks them; a directory or file that is no known ecosystem or
// release refuses the run.
func shardInputs(o osvShardsOptions, now time.Time) ([]shardSetInput, error) {
	verb := osvShardsVerb
	stamp := now.Format(time.RFC3339)
	var out []shardSetInput
	seen := map[string]string{}
	add := func(in shardSetInput, from string) error {
		if !osvshardkey.ValidSetName(in.set) {
			return fmt.Errorf("vendorsign %s: %q is not a set name", verb, in.set)
		}
		if prev, dup := seen[strings.ToLower(in.set)]; dup {
			return fmt.Errorf("vendorsign %s: %s and %s would publish the same set %s", verb, prev, from, in.set)
		}
		seen[strings.ToLower(in.set)] = from
		out = append(out, in)
		return nil
	}
	if o.Lang != "" {
		dirs, err := os.ReadDir(o.Lang)
		if err != nil {
			return nil, fmt.Errorf("vendorsign %s: %w", verb, err)
		}
		for _, d := range dirs {
			if !d.IsDir() {
				continue
			}
			set, ok := osvdb.ArtifactBase(d.Name())
			if !ok {
				return nil, fmt.Errorf("vendorsign %s: %q is not an OSV ecosystem name a set can carry", verb, d.Name())
			}
			in, err := checkOSVInput(verb, filepath.Join(o.Lang, d.Name()), d.Name(), "ecosystem")
			if err != nil {
				return nil, err
			}
			if err := add(shardSetInput{
				set: set, ecosystem: d.Name(), base: d.Name(), path: in.path, sha256: in.sum.sha256,
				license: osvLicense, source: osvShardsSource, upstream: osvUpstream(in.src, stamp),
				version: in.src.LastModified,
			}, "-lang "+d.Name()); err != nil {
				return nil, err
			}
		}
	}
	if o.OS != "" {
		files, err := os.ReadDir(o.OS)
		if err != nil {
			return nil, fmt.Errorf("vendorsign %s: %w", verb, err)
		}
		for _, f := range files {
			name := f.Name()
			// osvosexport's temp files start with a dot; they are its own.
			if f.IsDir() || strings.HasPrefix(name, ".") {
				continue
			}
			art, ok := strings.CutSuffix(name, ".zip")
			r, known := osvdb.ReleaseByArtifact(art)
			if !ok || !known {
				return nil, fmt.Errorf("vendorsign %s: %s in %s is not a release file of the release table", verb, name, o.OS)
			}
			path := filepath.Join(o.OS, name)
			sum, err := hashOSVFile(path)
			if err != nil {
				return nil, fmt.Errorf("vendorsign %s: %s: %w", verb, name, err)
			}
			if err := add(shardSetInput{
				set: r.Artifact, ecosystem: r.Ecosystem, base: r.Base, path: path, sha256: sum.sha256,
				license: osvOSLicense, source: osvShardsOSSource,
				upstream: content.UpstreamCheck{Method: content.UpstreamNone, VerifiedAt: stamp, VerifiedWhere: "release_pipeline"},
			}, "-os "+name); err != nil {
				return nil, err
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("vendorsign %s: no input set in %s", verb, strings.TrimSpace(o.Lang+" "+o.OS))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].set < out[j].set })
	return out, nil
}

// planShardSet reuses the set's last descriptor when its input, bits and
// format are unchanged and every object it names is in the store, else
// builds the set; then it sets the epoch. empty reports a set no record
// keys into.
func planShardSet(o osvShardsOptions, in shardSetInput, bits int, prev shardSetState, work string) (shardSetBuild, bool, error) {
	if prev.InputSHA256 == in.sha256 && prev.Bits == bits && prev.Format == osvShardsFormat && prev.Epoch > 0 {
		if b, ok := reuseShardSet(o, in, prev); ok {
			return b, false, nil
		}
	}
	desc, objects, stats, err := buildShardSet(in, bits, o.Objects, work)
	if err != nil {
		return shardSetBuild{}, false, err
	}
	if desc.Shards == 0 {
		return shardSetBuild{}, true, nil
	}
	desc.Epoch = 0
	probe, err := osvshardkey.EncodeSet(desc)
	if err != nil {
		return shardSetBuild{}, false, fmt.Errorf("vendorsign %s: %s: %w", osvShardsVerb, in.set, err)
	}
	contentSum := content.HashBytes(probe)
	desc.Epoch = prev.Epoch
	if contentSum != prev.ContentSHA256 || prev.Epoch == 0 {
		desc.Epoch = prev.Epoch + 1
	}
	data, err := osvshardkey.EncodeSet(desc)
	if err != nil {
		return shardSetBuild{}, false, fmt.Errorf("vendorsign %s: %s: %w", osvShardsVerb, in.set, err)
	}
	return shardSetBuild{
		in: in, desc: desc, data: data, objects: objects, stats: stats,
		st: shardSetState{
			InputSHA256: in.sha256, Format: osvShardsFormat, Bits: bits, Epoch: desc.Epoch,
			ContentSHA256: contentSum, SetSHA256: content.HashBytes(data),
		},
	}, false, nil
}

// reuseShardSet loads the set's last descriptor from the state and checks
// every object it names is in the store at its size (each index file is
// also re-read and checked against its digest, since it names the shards).
func reuseShardSet(o osvShardsOptions, in shardSetInput, prev shardSetState) (shardSetBuild, bool) {
	data, err := os.ReadFile(filepath.Join(o.State, osvShardsSetsDir, osvshardkey.SetFile(in.set))) //nolint:gosec // the tool's own state directory
	if err != nil || content.HashBytes(data) != prev.SetSHA256 {
		return shardSetBuild{}, false
	}
	desc, err := osvshardkey.DecodeSet(data)
	if err != nil || desc.Set != in.set || desc.Base != in.base || desc.Ecosystem != in.ecosystem || desc.Bits != prev.Bits || desc.Epoch != prev.Epoch ||
		desc.MaxShardBytes != osvShardMaxBytes || desc.MaxIndexBytes != osvshardkey.MaxIndexBytes {
		return shardSetBuild{}, false
	}
	var objects []string
	for _, r := range desc.Index {
		ip := osvshardkey.IndexPath(in.set, r.Object)
		raw, err := os.ReadFile(filepath.Join(o.Objects, filepath.FromSlash(ip))) //nolint:gosec // the tool's own object store
		if err != nil || int64(len(raw)) != r.Size || content.HashBytes(raw) != r.Object {
			return shardSetBuild{}, false
		}
		f, err := osvshardkey.DecodeIndex(raw, desc, r.Byte)
		if err != nil {
			return shardSetBuild{}, false
		}
		objects = append(objects, ip)
		for _, s := range f.Shards {
			sp := osvshardkey.ShardPath(in.set, s.Object)
			fi, err := os.Stat(filepath.Join(o.Objects, filepath.FromSlash(sp)))
			if err != nil || fi.Size() != s.Size {
				return shardSetBuild{}, false
			}
			objects = append(objects, sp)
		}
	}
	return shardSetBuild{in: in, desc: desc, data: data, objects: objects, reused: true, st: prev}, true
}

// spillRef is one per-prefix copy of a record in the spill file.
type spillRef struct {
	prefix uint32
	ord    uint32
	off    int64
	n      uint32
}

// buildShardSet splits one set's export into shards and index files in the
// object store and returns the descriptor (epoch unset), the object paths
// it names, and the shard size statistics.
func buildShardSet(in shardSetInput, bits int, objectsDir, work string) (osvshardkey.SetDescriptor, []string, shardStats, error) {
	fail := func(err error) (osvshardkey.SetDescriptor, []string, shardStats, error) {
		return osvshardkey.SetDescriptor{}, nil, shardStats{}, fmt.Errorf("vendorsign %s: %s: %w", osvShardsVerb, in.set, err)
	}
	zr, err := zip.OpenReader(in.path)
	if err != nil {
		return fail(fmt.Errorf("%s does not open as a zip: %w", in.path, err))
	}
	defer func() { _ = zr.Close() }()
	files, err := sortedFlatRecords(&zr.Reader)
	if err != nil {
		return fail(err)
	}
	spill, err := os.CreateTemp(work, ".osvshards-*.spill")
	if err != nil {
		return fail(err)
	}
	defer func() {
		_ = spill.Close()
		_ = os.Remove(spill.Name())
	}()

	refs, records, err := spillShardRecords(in, bits, files, spill)
	if err != nil {
		return fail(err)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].prefix != refs[j].prefix {
			return refs[i].prefix < refs[j].prefix
		}
		return refs[i].ord < refs[j].ord
	})

	desc := osvshardkey.SetDescriptor{
		Schema: osvshardkey.SetSchema, Set: in.set, Ecosystem: in.ecosystem, Base: in.base, Bits: bits,
		Mode: osvshardkey.ModeStrip, Records: records,
		MaxShardBytes: osvShardMaxBytes, MaxIndexBytes: osvshardkey.MaxIndexBytes,
	}
	shards, sizes, err := writeShards(in.set, refs, spill, objectsDir)
	if err != nil {
		return fail(err)
	}
	var objects []string
	for _, s := range shards {
		desc.Shards++
		desc.ShardBytes += s.Size
		objects = append(objects, osvshardkey.ShardPath(in.set, s.Object))
	}
	// One index file per first key byte that has a shard, in byte order.
	for i := 0; i < len(shards); {
		b := osvshardkey.FirstByte(shards[i].Prefix, bits)
		j := i
		for j < len(shards) && osvshardkey.FirstByte(shards[j].Prefix, bits) == b {
			j++
		}
		f := osvshardkey.IndexFile{Schema: osvshardkey.IndexSchema, Set: in.set, Bits: bits, Byte: b, Shards: shards[i:j]}
		data, err := osvshardkey.EncodeIndex(f, desc)
		if err != nil {
			return fail(err)
		}
		sum := content.HashBytes(data)
		p := osvshardkey.IndexPath(in.set, sum)
		if err := putShardObject(objectsDir, p, data); err != nil {
			return fail(err)
		}
		objects = append(objects, p)
		desc.Index = append(desc.Index, osvshardkey.IndexRef{Byte: b, Object: sum, Size: int64(len(data))})
		i = j
	}
	return desc, objects, sizeStats(sizes), nil
}

// spillShardRecords reads every record of the export in entry-name order
// and writes, for each prefix its affected entries of the set's base hash
// into, the record stripped to those entries, deflated, into spill. It
// returns a reference per copy and how many records were placed.
func spillShardRecords(in shardSetInput, bits int, files []*zip.File, spill *os.File) ([]spillRef, int, error) {
	bw := bufio.NewWriterSize(spill, 1<<20)
	fw, err := flate.NewWriter(nil, flate.BestSpeed)
	if err != nil {
		return nil, 0, err
	}
	var (
		raw, joined, compact, deflated bytes.Buffer
		refs                           []spillRef
		off                            int64
		records                        int
	)
	for ord, f := range files {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		if f.UncompressedSize64 > osvOSMaxRecord {
			return nil, 0, fmt.Errorf("record %s is %d bytes, over %d", f.Name, f.UncompressedSize64, osvOSMaxRecord)
		}
		raw.Reset()
		if err := readZipEntry(f, &raw); err != nil {
			return nil, 0, fmt.Errorf("record %s: %w", f.Name, err)
		}
		rec, err := splitOSVRecord(raw.Bytes())
		if err != nil {
			return nil, 0, fmt.Errorf("record %s: %w", f.Name, err)
		}
		if rec.aff < 0 {
			continue
		}
		var order []uint32
		byPrefix := map[uint32][]int{}
		for i := range rec.affected {
			if rec.names[i] == "" || osvshardkey.Base(rec.ecos[i]) != in.base {
				continue
			}
			p := osvshardkey.PrefixOf(in.base, rec.names[i], bits)
			if _, ok := byPrefix[p]; !ok {
				order = append(order, p)
			}
			byPrefix[p] = append(byPrefix[p], i)
		}
		if len(order) == 0 {
			continue
		}
		records++
		for _, p := range order {
			stripped, err := rec.withAffected(byPrefix[p], &joined, &compact)
			if err != nil {
				return nil, 0, fmt.Errorf("record %s: %w", f.Name, err)
			}
			deflated.Reset()
			fw.Reset(&deflated)
			if _, err := fw.Write(stripped); err != nil {
				return nil, 0, err
			}
			if err := fw.Close(); err != nil {
				return nil, 0, err
			}
			if _, err := bw.Write(deflated.Bytes()); err != nil {
				return nil, 0, fmt.Errorf("spill: %w", err)
			}
			refs = append(refs, spillRef{prefix: p, ord: uint32(ord), off: off, n: uint32(deflated.Len())}) //nolint:gosec // an export holds far fewer than 2^32 entries; a copy is under the 64 MiB record cap
			off += int64(deflated.Len())
		}
	}
	if err := bw.Flush(); err != nil {
		return nil, 0, fmt.Errorf("spill: %w", err)
	}
	return refs, records, nil
}

// writeShards assembles one shard per prefix from the sorted references
// (a JSON array of the prefix's records, gzip at best compression), puts
// each in the object store under its digest, and returns the shard
// references in prefix order and their sizes. A shard over
// osvshardkey.MaxShardBytes refuses the set.
func writeShards(set string, refs []spillRef, spill *os.File, objectsDir string) ([]osvshardkey.ShardRef, []int64, error) {
	var (
		shards []osvshardkey.ShardRef
		sizes  []int64
		buf    bytes.Buffer
	)
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, nil, err
	}
	fr := flate.NewReader(bytes.NewReader(nil))
	defer func() { _ = fr.Close() }()
	for i := 0; i < len(refs); {
		p := refs[i].prefix
		j := i
		for j < len(refs) && refs[j].prefix == p {
			j++
		}
		buf.Reset()
		gw.Reset(&buf)
		if _, err := gw.Write([]byte{'['}); err != nil {
			return nil, nil, err
		}
		for k := i; k < j; k++ {
			if k > i {
				if _, err := gw.Write([]byte{','}); err != nil {
					return nil, nil, err
				}
			}
			sr := io.NewSectionReader(spill, refs[k].off, int64(refs[k].n))
			if err := fr.(flate.Resetter).Reset(sr, nil); err != nil {
				return nil, nil, err
			}
			if _, err := io.Copy(gw, fr); err != nil {
				return nil, nil, fmt.Errorf("spill: %w", err)
			}
			if int64(buf.Len()) > osvShardMaxBytes {
				return nil, nil, fmt.Errorf("the shard of prefix %d is over %d bytes", p, osvShardMaxBytes)
			}
		}
		if _, err := gw.Write([]byte{']'}); err != nil {
			return nil, nil, err
		}
		if err := gw.Close(); err != nil {
			return nil, nil, err
		}
		if int64(buf.Len()) > osvShardMaxBytes {
			return nil, nil, fmt.Errorf("the shard of prefix %d is %d bytes, over %d", p, buf.Len(), osvShardMaxBytes)
		}
		data := buf.Bytes()
		sum := content.HashBytes(data)
		if err := putShardObject(objectsDir, osvshardkey.ShardPath(set, sum), data); err != nil {
			return nil, nil, err
		}
		shards = append(shards, osvshardkey.ShardRef{Prefix: p, Object: sum, Size: int64(len(data)), Records: j - i})
		sizes = append(sizes, int64(len(data)))
		i = j
	}
	return shards, sizes, nil
}

// putShardObject writes one content-addressed object into the store,
// skipping one already there at its size (its name is its digest).
func putShardObject(objectsDir, rel string, data []byte) error {
	path := filepath.Join(objectsDir, filepath.FromSlash(rel))
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() && fi.Size() == int64(len(data)) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // public feed objects
		return fmt.Errorf("vendorsign %s: %w", osvShardsVerb, err)
	}
	return writeFileAtomic(path, data, 0o644)
}

// pruneShardObjects removes every object file of the store that refs does
// not name, and any temp file a dead run left, so the store holds exactly
// the published set. Only files shaped like objects are touched.
func pruneShardObjects(objectsDir string, refs map[string]bool) error {
	return filepath.WalkDir(objectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(objectsDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		parts := strings.Split(rel, "/")
		if len(parts) != 3 || (parts[1] != "obj" && parts[1] != "index") {
			return nil
		}
		if refs[rel] {
			return nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vendorsign %s: prune %s: %w", osvShardsVerb, rel, err)
		}
		return nil
	})
}

// sizeStats is the median, 95th percentile and largest of sizes.
func sizeStats(sizes []int64) shardStats {
	if len(sizes) == 0 {
		return shardStats{}
	}
	s := append([]int64(nil), sizes...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	at := func(q float64) int64 {
		i := int(q * float64(len(s)-1))
		return s[i]
	}
	return shardStats{median: at(0.5), p95: at(0.95), max: s[len(s)-1]}
}

// loadShardsState reads sets.json; a missing file is the first run.
func loadShardsState(dir string) (shardsState, error) {
	raw, err := os.ReadFile(filepath.Join(dir, osvShardsSetsFile)) //nolint:gosec // the tool's own state directory
	if errors.Is(err, os.ErrNotExist) {
		return shardsState{Sets: map[string]shardSetState{}}, nil
	}
	if err != nil {
		return shardsState{}, fmt.Errorf("vendorsign %s: state: %w", osvShardsVerb, err)
	}
	var st shardsState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return shardsState{}, fmt.Errorf("vendorsign %s: state: %w", osvShardsVerb, err)
	}
	if st.Sets == nil {
		st.Sets = map[string]shardSetState{}
	}
	return st, nil
}

// saveShardsState records each set's descriptor, then sets.json (temp +
// rename) last; a set no longer built leaves the state.
func saveShardsState(dir string, builds []shardSetBuild) error {
	sdir := filepath.Join(dir, osvShardsSetsDir)
	if err := os.MkdirAll(sdir, 0o700); err != nil {
		return fmt.Errorf("vendorsign %s: %w", osvShardsVerb, err)
	}
	next := shardsState{Sets: map[string]shardSetState{}}
	keep := map[string]bool{}
	for _, b := range builds {
		name := osvshardkey.SetFile(b.in.set)
		if err := writeFileAtomic(filepath.Join(sdir, name), b.data, 0o600); err != nil {
			return err
		}
		keep[name] = true
		next.Sets[b.in.set] = b.st
	}
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("vendorsign %s: %w", osvShardsVerb, err)
	}
	if err := writeFileAtomic(filepath.Join(dir, osvShardsSetsFile), append(raw, '\n'), 0o600); err != nil {
		return err
	}
	entries, err := os.ReadDir(sdir)
	if err != nil {
		return fmt.Errorf("vendorsign %s: %w", osvShardsVerb, err)
	}
	for _, e := range entries {
		if !keep[e.Name()] && strings.HasSuffix(e.Name(), ".set.json") {
			_ = os.Remove(filepath.Join(sdir, e.Name()))
		}
	}
	return nil
}

// printOSVShards writes the summary: one line per set, the object totals,
// and the manifest's counters (or "unchanged").
func printOSVShards(out io.Writer, res osvShardsResult) {
	for _, b := range res.Sets {
		d := b.desc
		if b.reused {
			fmt.Fprintf(out, "%s: reused (input unchanged), %d bits, %d shards, %d records, %s, epoch %d\n",
				d.Set, d.Bits, d.Shards, d.Records, humanBytes(d.ShardBytes), d.Epoch)
			continue
		}
		fmt.Fprintf(out, "%s: built, %d bits, %d shards (median %s, p95 %s, max %s), %d index files, %d records, %s, epoch %d\n",
			d.Set, d.Bits, d.Shards, humanBytes(b.stats.median), humanBytes(b.stats.p95), humanBytes(b.stats.max),
			len(d.Index), d.Records, humanBytes(d.ShardBytes), d.Epoch)
	}
	for _, s := range res.Omitted {
		fmt.Fprintf(out, "%s: no record, left out of the manifest\n", s)
	}
	fmt.Fprintf(out, "%s: %d objects, %s\n", osvShardsVerb, res.Objects, humanBytes(res.ObjectBytes))
	if res.Unchanged {
		fmt.Fprintln(out, "unchanged")
		return
	}
	fmt.Fprintf(out, "%s: manifest_version %d, epoch %d\n", osvShardsVerb, res.ManifestVersion, res.Epoch)
}

// humanBytes renders a size for the summary.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MiB"
	case n >= 1<<10:
		return strconv.FormatFloat(float64(n)/(1<<10), 'f', 1, 64) + " KiB"
	}
	return strconv.FormatInt(n, 10) + " B"
}
