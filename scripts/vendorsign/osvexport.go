package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/md5" //nolint:gosec // MD5 is the bucket's own published checksum, compared, never trusted alone
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/update"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// osvexport.go is the `vendorsign osvexport` verb, the daily publisher of
// the security.osv_export content kind (static feed mirroring plan,
// docs/plans/static-feed-mirroring-plan-2026-11-03.md sections 6.2 to 6.4).
// It reads local files only: a fetch script mirrors each ecosystem's
// all.zip from the OSV bucket into -in beside a source.json naming the
// object and the checksums the bucket served, so this tool has no network
// code. It signs with the CONTENT-FEED key (content.SignFeed), never the
// release vendor key.
//
// Input, one directory per ecosystem:
//
//	<in>/<eco>/all.zip      the upstream export as fetched
//	<in>/<eco>/source.json  {"object","last_modified","crc32c","md5","generation"}
//
// State, owned by this tool (the bases and the publish counters):
//
//	<state>/state.json      last manifest version, epoch, issued_at, per-eco base
//	<state>/base/<eco>.zip  the current base of each ecosystem
//	<state>/manifest.json   the last envelope
//
// Output, the layout the feed host serves and a node's content store
// installs:
//
//	<out>/security.osv_export/manifest.json + <eco>.zip + <eco>.delta.zip
//
// where <eco> in an artifact name is osvdb.ArtifactBase's spelling (a space
// becomes '-': "GitHub-Actions.zip"), the one rule the node reads them by;
// the input and state keep the bucket's own spelling.
//
// Per ecosystem the manifest lists a BASE (an upstream all.zip, bytes
// unchanged) and a cumulative DELTA over it (every record of today's
// export that is new or changed against the base, copied raw, plus the
// names the base has and today's export does not), so a node holding the
// base fetches only the delta. The base is replaced by today's export when
// there is none, when it is older than -rebase-days, or when the delta
// would carry more than -rebase-ratio of the export's records.

// osvSourceFile and osvExportFile are the per-ecosystem input names.
const (
	osvSourceFile = "source.json"
	osvExportFile = "all.zip"
	// osvStateFile is the state directory's counters file.
	osvStateFile = "state.json"
	// osvSourceLabel and osvLicense describe the OSV exports' bytes.
	osvSourceLabel = "osv.dev export bucket"
	osvLicense     = "CC-BY-4.0"
)

// osvDeltaModTime is the fixed modified time of every delta zip entry, so
// identical deltas are byte-identical whatever the upstream stamped, and
// osvDeltaDOSDate / osvDeltaDOSTime its MS-DOS spelling, which is what
// CreateRaw writes (it does not derive them from Modified, as CreateHeader
// does): date (2000-1980)<<9 | 1<<5 | 1, time 00:00:00.
var osvDeltaModTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	osvDeltaDOSDate uint16 = (2000-1980)<<9 | 1<<5 | 1
	osvDeltaDOSTime uint16 = 0
)

// osvSource is one ecosystem's source.json: the upstream object and what
// the bucket served for it.
type osvSource struct {
	Object       string `json:"object"`
	LastModified string `json:"last_modified"`
	CRC32C       string `json:"crc32c,omitempty"`
	MD5          string `json:"md5,omitempty"`
	Generation   string `json:"generation,omitempty"`
}

// osvBaseState is one ecosystem's current base.
type osvBaseState struct {
	BaseSHA256    string `json:"base_sha256"`
	BaseSize      int64  `json:"base_size"`
	BaseCreatedAt string `json:"base_created_at"`
	BaseEntries   int    `json:"base_entries"`
	// Source is the upstream object the base was copied from, and
	// VerifiedAt when its checksums were checked.
	Source     osvSource `json:"source"`
	VerifiedAt string    `json:"verified_at"`
}

// osvExportState is <state>/state.json.
type osvExportState struct {
	ManifestVersion int64  `json:"manifest_version"`
	Epoch           int64  `json:"epoch"`
	IssuedAt        string `json:"issued_at,omitempty"`
	// Artifacts maps each published artifact name to its sha256.
	Artifacts  map[string]string       `json:"artifacts,omitempty"`
	Ecosystems map[string]osvBaseState `json:"ecosystems,omitempty"`
}

// osvExportOptions is one publish.
type osvExportOptions struct {
	Key   ed25519.PrivateKey
	In    string
	State string
	Out   string
	// ManifestVersion is the version to publish; 0 means the state's last
	// plus one.
	ManifestVersion int64
	RebaseAge       time.Duration
	RebaseRatio     float64
	Reissue         time.Duration
	Now             time.Time
}

// osvEcoResult is one ecosystem's outcome, for the summary line.
type osvEcoResult struct {
	Eco string
	// Rebased reports a new base; Reason is why (new, age, ratio,
	// base_mismatch).
	Rebased      bool
	Reason       string
	BaseAge      time.Duration
	DeltaEntries int
	Dropped      int
	Records      int
}

// osvExportResult is one publish's outcome.
type osvExportResult struct {
	// Unchanged reports that nothing was written: no artifact changed and
	// the last manifest is younger than the reissue interval.
	Unchanged       bool
	ManifestVersion int64
	Epoch           int64
	Ecosystems      []osvEcoResult
	// Omitted names the keys left out of the manifest because their input
	// holds no record (osvosexport: a release with no record yet).
	Omitted []string
	// Verb is the verb that built it, for the summary line ("" reads as
	// osvexport).
	Verb string
}

// zipKey is what decides whether a record changed: its CRC32 and
// uncompressed size.
type zipKey struct {
	crc  uint32
	size uint64
}

// osvSetSpec is one signed OSV content kind the publisher builds: the
// language exports (security.osv_export, keyed by ecosystem) or the
// per-release OS exports (security.osv_os_export, keyed by
// osvdb.OSRelease.Artifact). Everything past the input (the base and delta
// decision, the manifest, the output, the state) is shared through it.
type osvSetSpec struct {
	// verb prefixes every message ("osvexport").
	verb string
	kind content.Kind
	// sourceLabel and license describe the published bytes.
	sourceLabel string
	license     string
	// baseName and deltaName name a key's two artifacts.
	baseName  func(key string) string
	deltaName func(key string) string
}

// osvLanguageSet is the security.osv_export kind.
var osvLanguageSet = osvSetSpec{
	verb: "osvexport", kind: content.OSVExport, sourceLabel: osvSourceLabel, license: osvLicense,
	baseName: osvdb.ExportArtifact, deltaName: osvdb.DeltaArtifact,
}

// osvInput is one key's checked input: the export zip its base and delta
// are cut from, that file's digest, and the upstream object it came from.
type osvInput struct {
	key  string
	path string
	sum  osvFileSum
	src  osvSource
}

// osvEcoBuild is one ecosystem's work.
type osvEcoBuild struct {
	eco       string
	baseName  string
	deltaName string
	src       osvSource
	inputPath string
	// basePath holds the base bytes to publish; base is its state.
	basePath string
	base     osvBaseState
	delta    []byte
	drop     []string
	records  int
	res      osvEcoResult
}

func runOSVExport(args []string, out *os.File) error {
	o, err := parseOSVExportFlags("osvexport", "input directory: <eco>/all.zip + <eco>/source.json per ecosystem", args)
	if err != nil {
		return err
	}
	res, err := buildOSVExport(o)
	if err != nil {
		return err
	}
	printOSVExport(out, res)
	return nil
}

// parseOSVExportFlags parses the flags osvexport and osvosexport share,
// loads the key and checks it is a content-feed key, and returns the
// publish's options.
func parseOSVExportFlags(verb, inHelp string, args []string) (osvExportOptions, error) {
	fsx := flag.NewFlagSet(verb, flag.ContinueOnError)
	keyPath := fsx.String("key", "", "content-feed signing key file (content-feed.key)")
	in := fsx.String("in", "", inHelp)
	state := fsx.String("state", "", "state directory owned by this tool (bases, counters, last manifest)")
	outDir := fsx.String("out", "", "output directory")
	version := fsx.Int64("manifest-version", 0, "manifest version to publish (default: the state's last + 1)")
	rebaseDays := fsx.Int("rebase-days", 7, "replace a base older than this many days")
	rebaseRatio := fsx.Float64("rebase-ratio", 0.10, "replace a base when the delta would carry more than this share of the records")
	reissueHours := fsx.Int("reissue-hours", 20, "re-sign an unchanged manifest once it is this many hours old")
	allowUnpinned := fsx.Bool("allow-unpinned-key", false, "sign with a key this tree's agents do not accept as a content-feed key (rotation step 4 only)")
	if err := fsx.Parse(args); err != nil {
		return osvExportOptions{}, err
	}
	if *keyPath == "" || *in == "" || *state == "" || *outDir == "" {
		return osvExportOptions{}, fmt.Errorf("vendorsign %s: -key, -in, -state and -out are required", verb)
	}
	if *version < 0 || *rebaseDays <= 0 || *reissueHours < 0 || *rebaseRatio <= 0 || *rebaseRatio > 1 {
		return osvExportOptions{}, fmt.Errorf("vendorsign %s: want -manifest-version >= 0, -rebase-days > 0, -reissue-hours >= 0 and 0 < -rebase-ratio <= 1", verb)
	}
	priv, err := loadFeedKey(*keyPath, *allowUnpinned)
	if err != nil {
		return osvExportOptions{}, err
	}
	return osvExportOptions{
		Key: priv, In: *in, State: *state, Out: *outDir, ManifestVersion: *version,
		RebaseAge: time.Duration(*rebaseDays) * 24 * time.Hour, RebaseRatio: *rebaseRatio,
		Reissue: time.Duration(*reissueHours) * time.Hour, Now: time.Now().UTC(),
	}, nil
}

// printOSVExport writes the summary: "unchanged", or one line per
// ecosystem and the manifest's counters.
func printOSVExport(out io.Writer, res osvExportResult) {
	if res.Unchanged {
		fmt.Fprintln(out, "unchanged")
		return
	}
	for _, e := range res.Ecosystems {
		base := fmt.Sprintf("base kept (%s old)", e.BaseAge.Truncate(time.Hour))
		if e.Rebased {
			base = "base rebased (" + e.Reason + ")"
		}
		fmt.Fprintf(out, "%s: %s, delta %d entries, %d dropped, %d records\n", e.Eco, base, e.DeltaEntries, e.Dropped, e.Records)
	}
	for _, k := range res.Omitted {
		fmt.Fprintf(out, "%s: no record, left out of the manifest\n", k)
	}
	verb := res.Verb
	if verb == "" {
		verb = osvLanguageSet.verb
	}
	fmt.Fprintf(out, "%s: manifest_version %d, epoch %d\n", verb, res.ManifestVersion, res.Epoch)
}

// loadFeedKey loads the content-feed signing key at path and checks it is
// one (checkFeedKeyIsPinned), printing the check's warning to stderr. Every
// feed verb loads its key through it.
func loadFeedKey(path string, allowUnpinned bool) (ed25519.PrivateKey, error) {
	priv, err := loadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	warn, err := checkFeedKeyIsPinned(priv, allowUnpinned)
	if err != nil {
		return nil, err
	}
	if warn != "" {
		fmt.Fprintln(os.Stderr, warn)
	}
	return priv, nil
}

// acceptedFeedKeys is the content-feed key set a node verifies against; a
// variable so a test can stand in a key (the tree compiles in none until the
// operator generates it on the publisher host).
var acceptedFeedKeys = update.ContentFeedPublicKeys

// checkFeedKeyIsPinned is checkKeyIsPinned for the content-feed key, plus
// the one refusal the key exists for: the release vendor key never signs
// the feed, because then the online publisher would hold the key that
// signs agent binaries.
func checkFeedKeyIsPinned(priv ed25519.PrivateKey, allowUnpinned bool) (string, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("vendorsign: signing key is not Ed25519")
	}
	for _, k := range acceptedVendorKeys() {
		if pub.Equal(k) {
			return "", fmt.Errorf("vendorsign: refusing to sign with key id %s - it is a RELEASE vendor key; the feed is signed with the content-feed key (vendorsign keygen -feed)", keyID(pub))
		}
	}
	accepted := acceptedFeedKeys()
	if len(accepted) == 0 {
		return "WARNING: this tree compiles in NO content-feed public key, so the signing key could not be\n" +
			"         checked against what nodes accept. Every node refuses the manifest (no_vendor_key)\n" +
			"         until internal/update/contentfeedkey.go carries the matching public key.", nil
	}
	for _, k := range accepted {
		if pub.Equal(k) {
			return "", nil
		}
	}
	if allowUnpinned {
		return fmt.Sprintf("WARNING: signing with key id %s, which is NOT among the content-feed keys this tree's agents accept.\n"+
			"         -allow-unpinned-key was given, so this is a deliberate rotation step.", keyID(pub)), nil
	}
	return "", fmt.Errorf("vendorsign: refusing to sign with key id %s - it is not among the content-feed keys this tree's agents accept (%s); pass -allow-unpinned-key only for the deliberate rotation step",
		keyID(pub), acceptedKeyIDs(accepted))
}

// checkOSVOptions refuses a publish missing its key or directories, or
// with an impossible rebase or reissue bound.
func checkOSVOptions(verb string, o osvExportOptions) error {
	if len(o.Key) != ed25519.PrivateKeySize || o.In == "" || o.State == "" || o.Out == "" {
		return fmt.Errorf("vendorsign %s: key, input, state and output are required", verb)
	}
	if o.RebaseAge <= 0 || o.RebaseRatio <= 0 || o.RebaseRatio > 1 || o.Reissue < 0 {
		return fmt.Errorf("vendorsign %s: invalid rebase or reissue bound", verb)
	}
	return nil
}

// buildOSVExport builds, signs and writes one publish, then updates the
// state; a failure leaves the state and the last output as they were.
func buildOSVExport(o osvExportOptions) (osvExportResult, error) {
	spec := osvLanguageSet
	if err := checkOSVOptions(spec.verb, o); err != nil {
		return osvExportResult{}, err
	}
	dirs, err := os.ReadDir(o.In)
	if err != nil {
		return osvExportResult{}, fmt.Errorf("vendorsign osvexport: %w", err)
	}
	var inputs []osvInput
	names := map[string]string{}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		// The directory is the ecosystem as the OSV bucket spells it ("GitHub
		// Actions"); its artifacts are named by osvdb.ExportArtifact, the
		// rule every node reads them by, so a name the rule refuses, or two
		// directories with one artifact name, are refused here.
		art := osvdb.ExportArtifact(d.Name())
		if art == "" {
			return osvExportResult{}, fmt.Errorf("vendorsign osvexport: %q is not an OSV ecosystem name an artifact can carry", d.Name())
		}
		if prev, dup := names[strings.ToLower(art)]; dup {
			return osvExportResult{}, fmt.Errorf("vendorsign osvexport: %q and %q would publish the same artifact %s", prev, d.Name(), art)
		}
		names[strings.ToLower(art)] = d.Name()
		in, err := checkOSVInput(spec.verb, filepath.Join(o.In, d.Name()), d.Name(), "ecosystem")
		if err != nil {
			return osvExportResult{}, err
		}
		inputs = append(inputs, in)
	}
	if len(inputs) == 0 {
		return osvExportResult{}, fmt.Errorf("vendorsign osvexport: no ecosystem directory in %s", o.In)
	}
	return publishOSVSet(o, spec, inputs)
}

// checkOSVInput reads one upstream export's source.json and checks the
// all.zip beside it against the checksums the bucket served; what names
// the refused unit in the message ("ecosystem", "distribution").
func checkOSVInput(verb, dir, key, what string) (osvInput, error) {
	fail := func(format string, a ...any) (osvInput, error) {
		return osvInput{}, fmt.Errorf("vendorsign %s: %s: %s", verb, key, fmt.Sprintf(format, a...))
	}
	src, err := readOSVSource(filepath.Join(dir, osvSourceFile))
	if err != nil {
		return fail("%v", err)
	}
	path := filepath.Join(dir, osvExportFile)
	sum, err := hashOSVFile(path)
	if err != nil {
		return fail("%v", err)
	}
	if src.CRC32C != "" && src.CRC32C != sum.crc32c {
		return fail("%s crc32c is %s, source.json says %s; refusing the %s", osvExportFile, sum.crc32c, src.CRC32C, what)
	}
	if src.MD5 != "" && src.MD5 != sum.md5 {
		return fail("%s md5 is %s, source.json says %s; refusing the %s", osvExportFile, sum.md5, src.MD5, what)
	}
	return osvInput{key: key, path: path, sum: sum, src: src}, nil
}

// publishOSVSet is everything past the input, shared by both OSV kinds:
// per key the base and delta decision, then the changed/unchanged check,
// the signed manifest, the output and the state.
func publishOSVSet(o osvExportOptions, spec osvSetSpec, inputs []osvInput) (osvExportResult, error) {
	if err := checkOSVOptions(spec.verb, o); err != nil {
		return osvExportResult{}, err
	}
	now := o.Now.UTC().Truncate(time.Second)
	if err := claimOSVState(o.State, spec); err != nil {
		return osvExportResult{}, err
	}
	st, err := loadOSVState(o.State)
	if err != nil {
		return osvExportResult{}, err
	}
	builds := make([]osvEcoBuild, 0, len(inputs))
	for _, in := range inputs {
		b, err := planOSVBase(o, spec, st, in, now)
		if err != nil {
			return osvExportResult{}, err
		}
		builds = append(builds, b)
	}

	artifacts := map[string]string{}
	for _, b := range builds {
		artifacts[b.baseName] = b.base.BaseSHA256
		artifacts[b.deltaName] = content.HashBytes(b.delta)
	}
	unchanged, version, epoch, err := nextFeedPublish(spec.verb, st, artifacts, now, o.Reissue, o.ManifestVersion)
	if err != nil {
		return osvExportResult{}, err
	}
	if unchanged {
		return osvExportResult{Unchanged: true, Verb: spec.verb}, nil
	}
	env, err := signOSVManifest(spec, builds, version, epoch, now, o.Key)
	if err != nil {
		return osvExportResult{}, err
	}
	envBytes, err := content.EncodeEnvelope(env)
	if err != nil {
		return osvExportResult{}, err
	}
	if len(envBytes) > content.MaxEnvelopeBytes {
		return osvExportResult{}, fmt.Errorf("vendorsign %s: the envelope is %d bytes, over the %d nodes accept", spec.verb, len(envBytes), content.MaxEnvelopeBytes)
	}

	if err := writeOSVOutput(o.Out, spec, builds, envBytes); err != nil {
		return osvExportResult{}, err
	}
	next := osvExportState{
		ManifestVersion: version, Epoch: epoch, IssuedAt: now.Format(time.RFC3339),
		Artifacts: artifacts, Ecosystems: map[string]osvBaseState{},
	}
	res := osvExportResult{ManifestVersion: version, Epoch: epoch, Verb: spec.verb}
	for _, b := range builds {
		next.Ecosystems[b.eco] = b.base
		res.Ecosystems = append(res.Ecosystems, b.res)
	}
	if err := saveOSVState(o.State, spec, st, next, builds, envBytes); err != nil {
		return osvExportResult{}, err
	}
	return res, nil
}

// nextFeedPublish is the publish decision every feed verb shares: a set
// whose artifact digests equal the last published ones, re-signed less than
// reissue ago, is unchanged (nothing is written); otherwise the manifest
// version is the state's last plus one (or want, which must be above it, or
// nodes would refuse it as a rollback) and the epoch moves only when an
// artifact changed.
func nextFeedPublish(verb string, st osvExportState, artifacts map[string]string, now time.Time, reissue time.Duration, want int64) (unchanged bool, version, epoch int64, err error) {
	changed := !maps.Equal(artifacts, st.Artifacts)
	if !changed && st.IssuedAt != "" {
		if last, perr := time.Parse(time.RFC3339, st.IssuedAt); perr == nil && now.Sub(last) < reissue {
			return true, 0, 0, nil
		}
	}
	version = st.ManifestVersion + 1
	if want > 0 {
		if want <= st.ManifestVersion {
			return false, 0, 0, fmt.Errorf("vendorsign %s: -manifest-version %d is not above the last published %d; nodes would refuse it as a rollback", verb, want, st.ManifestVersion)
		}
		version = want
	}
	epoch = st.Epoch
	if changed {
		epoch++
	}
	return false, version, epoch, nil
}

// planOSVBase decides one key's base (keep the state's, or rebase on the
// checked input) and cuts the cumulative delta over it. Every file it opens
// is closed before it returns (a base about to be replaced must not be held
// open).
func planOSVBase(o osvExportOptions, spec osvSetSpec, st osvExportState, in osvInput, now time.Time) (osvEcoBuild, error) {
	eco, inputPath := in.key, in.path
	fail := func(format string, a ...any) (osvEcoBuild, error) {
		return osvEcoBuild{}, fmt.Errorf("vendorsign %s: %s: %s", spec.verb, eco, fmt.Sprintf(format, a...))
	}
	inName := filepath.Base(inputPath)
	input, err := zip.OpenReader(inputPath)
	if err != nil {
		return fail("%s does not open as a zip: %v", inName, err)
	}
	defer func() { _ = input.Close() }()
	inEntries, err := listOSVZip(&input.Reader)
	if err != nil {
		return fail("%s: %v", inName, err)
	}
	if len(inEntries) == 0 {
		return fail("%s holds no record", inName)
	}

	b := osvEcoBuild{
		eco: eco, baseName: spec.baseName(eco), deltaName: spec.deltaName(eco),
		src: in.src, inputPath: inputPath, records: len(inEntries),
	}
	if b.baseName == "" || b.deltaName == "" {
		return fail("no artifact name")
	}
	b.res = osvEcoResult{Eco: eco, Records: len(inEntries)}
	fresh := osvBaseState{
		BaseSHA256: in.sum.sha256, BaseSize: in.sum.size, BaseCreatedAt: now.Format(time.RFC3339),
		BaseEntries: len(inEntries), Source: in.src, VerifiedAt: now.Format(time.RFC3339),
	}
	rebase := func(reason string) {
		b.basePath, b.base = inputPath, fresh
		b.res.Rebased, b.res.Reason = true, reason
		b.drop = nil
	}

	var changedNames []string
	prev, had := st.Ecosystems[eco]
	switch {
	case !had:
		rebase("new")
	default:
		basePath := filepath.Join(o.State, "base", b.baseName)
		bsum, herr := hashOSVFile(basePath)
		if herr != nil || bsum.sha256 != prev.BaseSHA256 {
			// The base on disk is not the one state.json names (a run that
			// died between writing the base and the state): start over from
			// today's export rather than publish a base nobody recorded.
			rebase("base_mismatch")
			break
		}
		baseEntries, lerr := listOSVZipFile(basePath)
		if lerr != nil {
			rebase("base_mismatch")
			break
		}
		for name, k := range inEntries {
			if bk, ok := baseEntries[name]; !ok || bk != k {
				changedNames = append(changedNames, name)
			}
		}
		var drop []string
		for name := range baseEntries {
			if _, ok := inEntries[name]; !ok {
				drop = append(drop, name)
			}
		}
		created, perr := time.Parse(time.RFC3339, prev.BaseCreatedAt)
		age := now.Sub(created)
		switch {
		case perr != nil:
			rebase("base_mismatch")
		case age >= o.RebaseAge:
			rebase("age")
		case float64(len(changedNames)+len(drop)) > o.RebaseRatio*float64(len(inEntries)):
			rebase("ratio")
		default:
			sort.Strings(drop)
			b.basePath, b.base, b.drop = basePath, prev, drop
			b.res.BaseAge = age
		}
	}
	if b.res.Rebased {
		changedNames = nil
	}
	sort.Strings(changedNames)
	delta, err := writeOSVDelta(&input.Reader, changedNames)
	if err != nil {
		return fail("delta: %v", err)
	}
	b.delta = delta
	b.res.DeltaEntries, b.res.Dropped = len(changedNames), len(b.drop)
	return b, nil
}

// osvKindFile marks a state directory with the content kind it belongs to,
// so the two verbs never share one (their state.json shapes are the same,
// and a shared one would mix counters and bases). It is a file beside
// state.json rather than a field in it, so an older vendorsign still reads
// its own state.
const osvKindFile = "kind"

// claimOSVState checks the state directory belongs to spec's kind and
// marks it on first use. A directory with a state.json but no mark was
// written before the mark existed, which only the language kind did.
func claimOSVState(dir string, spec osvSetSpec) error {
	return claimFeedState(dir, spec.verb, spec.kind)
}

// claimFeedState is claimOSVState for any feed verb: dir belongs to kind,
// or is unclaimed and is marked for kind now.
func claimFeedState(dir, verb string, kind content.Kind) error {
	path := filepath.Join(dir, osvKindFile)
	raw, err := os.ReadFile(path) //nolint:gosec // the tool's own state directory
	switch {
	case err == nil:
		if got := strings.TrimSpace(string(raw)); got != string(kind) {
			return fmt.Errorf("vendorsign %s: the state directory %s belongs to %s, not %s; give each kind its own -state", verb, dir, got, kind)
		}
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("vendorsign %s: state: %w", verb, err)
	}
	if _, serr := os.Stat(filepath.Join(dir, osvStateFile)); serr == nil && kind != content.OSVExport {
		return fmt.Errorf("vendorsign %s: the state directory %s holds an unmarked state.json (a %s state); give each kind its own -state", verb, dir, content.OSVExport)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("vendorsign %s: %w", verb, err)
	}
	return writeFileAtomic(path, []byte(string(kind)+"\n"), 0o600)
}

// listOSVZip lists a flat OSV export: entry name to its CRC32 and size. A
// nested or repeated name is refused, since a record's identity is its name.
func listOSVZip(r *zip.Reader) (map[string]zipKey, error) {
	out := make(map[string]zipKey, len(r.File))
	for _, f := range r.File {
		if f.Name == "" || strings.ContainsAny(f.Name, `/\`) || strings.HasPrefix(f.Name, "-") || f.Name == "." || f.Name == ".." {
			return nil, fmt.Errorf("entry %q is not a flat record name", f.Name)
		}
		if _, dup := out[f.Name]; dup {
			return nil, fmt.Errorf("entry %q repeats", f.Name)
		}
		out[f.Name] = zipKey{crc: f.CRC32, size: f.UncompressedSize64}
	}
	return out, nil
}

// listOSVZipFile is listOSVZip over a file, closed before it returns.
func listOSVZipFile(path string) (map[string]zipKey, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return listOSVZip(&r.Reader)
}

// writeOSVDelta copies the named entries of r, raw (zip.Writer.Copy's
// CreateRaw over OpenRaw: no recompression), in the given order, with the
// header's time pinned and its extra fields and comment dropped, so the same
// records always give the same bytes. No name gives an empty zip.
func writeOSVDelta(r *zip.Reader, names []string) ([]byte, error) {
	byName := make(map[string]*zip.File, len(r.File))
	for _, f := range r.File {
		byName[f.Name] = f
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range names {
		f := byName[name]
		raw, err := f.OpenRaw()
		if err != nil {
			return nil, err
		}
		fh := f.FileHeader
		fh.Modified = osvDeltaModTime
		fh.ModifiedDate, fh.ModifiedTime = osvDeltaDOSDate, osvDeltaDOSTime
		fh.Extra = nil
		fh.Comment = ""
		dst, err := w.CreateRaw(&fh)
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(dst, raw); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// signOSVManifest builds spec's manifest and signs it with the content-feed
// key.
func signOSVManifest(spec osvSetSpec, builds []osvEcoBuild, version, epoch int64, now time.Time, key ed25519.PrivateKey) (content.Envelope, error) {
	ks, ok := content.KindOf(spec.kind)
	if !ok {
		return content.Envelope{}, fmt.Errorf("vendorsign %s: the content channel has no %s kind", spec.verb, spec.kind)
	}
	verified := now.Format(time.RFC3339)
	entries := make([]content.Entry, 0, 2*len(builds))
	for _, b := range builds {
		entries = append(entries, content.Entry{
			Name: b.baseName, Version: b.base.Source.LastModified, SizeBytes: b.base.BaseSize, SHA256: b.base.BaseSHA256,
			Source: spec.sourceLabel, License: spec.license, Upstream: osvUpstream(b.base.Source, b.base.VerifiedAt),
		}, content.Entry{
			Name: b.deltaName, Version: b.src.LastModified, SizeBytes: int64(len(b.delta)), SHA256: content.HashBytes(b.delta),
			Source: spec.sourceLabel, License: spec.license, Upstream: osvUpstream(b.src, verified),
			Delta: &content.DeltaOf{Base: b.baseName, BaseSHA256: b.base.BaseSHA256, Records: b.records, Drop: b.drop},
		})
	}
	content.SortEntries(entries)
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: spec.kind, ManifestVersion: version, Epoch: epoch,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(ks.MaxValidity).Format(time.RFC3339),
		Entries: entries,
	}
	env, err := content.SignFeed(m, key)
	if err != nil {
		return content.Envelope{}, fmt.Errorf("vendorsign %s: %w", spec.verb, err)
	}
	return env, nil
}

// osvUpstream is the gcs_object_hash record of a source object.
func osvUpstream(s osvSource, verifiedAt string) content.UpstreamCheck {
	return content.UpstreamCheck{
		Method: content.UpstreamGCSObjectHash, Object: s.Object, Generation: s.Generation,
		CRC32C: s.CRC32C, MD5: s.MD5, VerifiedAt: verifiedAt, VerifiedWhere: "release_pipeline",
	}
}

// writeOSVOutput replaces <out>/<kind> with this publish: the stale files
// go first, the manifest is written last.
func writeOSVOutput(out string, spec osvSetSpec, builds []osvEcoBuild, envBytes []byte) error {
	dir := filepath.Join(out, string(spec.kind))
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("vendorsign %s: clear %s: %w", spec.verb, dir, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // public feed artifacts
		return fmt.Errorf("vendorsign %s: %w", spec.verb, err)
	}
	for _, b := range builds {
		if err := copyFileAtomic(b.basePath, filepath.Join(dir, b.baseName), 0o644); err != nil {
			return err
		}
		if err := writeFileAtomic(filepath.Join(dir, b.deltaName), b.delta, 0o644); err != nil {
			return err
		}
	}
	return writeFileAtomic(filepath.Join(dir, "manifest.json"), envBytes, 0o644)
}

// saveOSVState records a publish: the new bases, the last envelope, then
// state.json (temp + rename) last, so a run that dies earlier leaves the
// previous state.json, and a base it already replaced is caught by its
// digest on the next run (base_mismatch).
func saveOSVState(dir string, spec osvSetSpec, prev, next osvExportState, builds []osvEcoBuild, envBytes []byte) error {
	baseDir := filepath.Join(dir, "base")
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return fmt.Errorf("vendorsign %s: %w", spec.verb, err)
	}
	for _, b := range builds {
		if b.basePath == b.inputPath {
			if err := copyFileAtomic(b.inputPath, filepath.Join(baseDir, b.baseName), 0o600); err != nil {
				return err
			}
		}
	}
	for eco := range prev.Ecosystems {
		if _, ok := next.Ecosystems[eco]; !ok {
			if name := spec.baseName(eco); name != "" && name == filepath.Base(name) {
				_ = os.Remove(filepath.Join(baseDir, name))
			}
		}
	}
	return writeFeedState(dir, spec.verb, next, envBytes)
}

// writeFeedState records a publish in the state directory: the last
// envelope, then state.json (temp + rename) last, so a run that dies
// earlier leaves the previous state.json.
func writeFeedState(dir, verb string, next osvExportState, envBytes []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("vendorsign %s: %w", verb, err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "manifest.json"), envBytes, 0o600); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("vendorsign %s: %w", verb, err)
	}
	return writeFileAtomic(filepath.Join(dir, osvStateFile), append(raw, '\n'), 0o600)
}

// loadOSVState reads state.json; a missing file is the first run.
func loadOSVState(dir string) (osvExportState, error) {
	raw, err := os.ReadFile(filepath.Join(dir, osvStateFile)) //nolint:gosec // the tool's own state directory
	if errors.Is(err, os.ErrNotExist) {
		return osvExportState{}, nil
	}
	if err != nil {
		return osvExportState{}, fmt.Errorf("vendorsign: state: %w", err)
	}
	var st osvExportState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return osvExportState{}, fmt.Errorf("vendorsign: state: %w", err)
	}
	return st, nil
}

// readOSVSource reads and checks a source.json: an https object, a
// last-modified time (RFC 3339 or the HTTP header's RFC 1123, normalized to
// RFC 3339 UTC) and at least one checksum to compare.
func readOSVSource(path string) (osvSource, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied input tree
	if err != nil {
		return osvSource{}, err
	}
	var s osvSource
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return osvSource{}, fmt.Errorf("%s: %w", osvSourceFile, err)
	}
	if u, err := url.Parse(s.Object); err != nil || u.Scheme != "https" || u.Host == "" {
		return osvSource{}, fmt.Errorf("%s: object must be an https URL, got %q", osvSourceFile, s.Object)
	}
	var lm time.Time
	for _, layout := range []string{time.RFC3339, time.RFC1123, time.RFC1123Z} {
		if lm, err = time.Parse(layout, s.LastModified); err == nil {
			break
		}
	}
	if err != nil {
		return osvSource{}, fmt.Errorf("%s: last_modified %q is not an RFC 3339 or RFC 1123 time", osvSourceFile, s.LastModified)
	}
	s.LastModified = lm.UTC().Format(time.RFC3339)
	if s.CRC32C == "" && s.MD5 == "" {
		return osvSource{}, fmt.Errorf("%s: needs crc32c or md5 to check the download", osvSourceFile)
	}
	return s, nil
}

// osvFileSum is one file's digests in the spellings they are compared in.
type osvFileSum struct {
	sha256 string
	crc32c string // base64 of the big-endian Castagnoli CRC (x-goog-hash)
	md5    string // base64
	size   int64
}

// hashOSVFile reads a file once for all three digests.
func hashOSVFile(path string) (osvFileSum, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied input or the tool's own state
	if err != nil {
		return osvFileSum{}, err
	}
	defer func() { _ = f.Close() }()
	sh := sha256.New()
	ch := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	mh := md5.New() //nolint:gosec // compared against the bucket's published MD5
	n, err := io.Copy(io.MultiWriter(sh, ch, mh), f)
	if err != nil {
		return osvFileSum{}, err
	}
	var crc [4]byte
	binary.BigEndian.PutUint32(crc[:], ch.Sum32())
	return osvFileSum{
		sha256: hex.EncodeToString(sh.Sum(nil)),
		crc32c: base64.StdEncoding.EncodeToString(crc[:]),
		md5:    base64.StdEncoding.EncodeToString(mh.Sum(nil)),
		size:   n,
	}, nil
}

// writeFileAtomic writes data to path through a temp file in the same
// directory and a rename.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	return replaceAtomic(path, perm, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// copyFileAtomic copies src to dst through a temp file and a rename.
func copyFileAtomic(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src) //nolint:gosec // operator-supplied input or the tool's own state
	if err != nil {
		return fmt.Errorf("vendorsign: %w", err)
	}
	defer func() { _ = in.Close() }()
	return replaceAtomic(dst, perm, func(w io.Writer) error {
		_, err := io.Copy(w, in)
		return err
	})
}

// replaceAtomic is the temp + sync + rename both writers share.
func replaceAtomic(path string, perm os.FileMode, fill func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.part")
	if err != nil {
		return fmt.Errorf("vendorsign: %w", err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := fill(tmp); err != nil {
		return fmt.Errorf("vendorsign: write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("vendorsign: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("vendorsign: write %s: %w", path, err)
	}
	if err := os.Chmod(name, perm); err != nil {
		return fmt.Errorf("vendorsign: write %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("vendorsign: write %s: %w", path, err)
	}
	ok = true
	return nil
}
