package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// SumsFileName is the checksum file the release job already writes. It
// is a CROSS-CHECK here, never the source of a hash: the manifest
// carries the hash this tool computed from the bytes it read, and a
// disagreement with SHA256SUMS fails the release.
const SumsFileName = "SHA256SUMS"

// CompanionBridge is the one non-alias file the agent archives carry
// beside the binary: the Windows-side helper the linux packages bundle
// for WSL2 users of the Antigravity adapter (npm-release.yml's "Place
// binaries in their package directories" step ships the whole bin/
// tree).
//
// It has to be DECLARED, because update.SelectMember treats any entry
// the manifest does not name as a failure (ErrUnlistedMember) — an
// undeclared third file would make every linux archive un-appliable.
// It rides in alias_members, whose contract is "declared companion
// entries the extractor SKIPS", which is exactly the treatment it needs:
// an update replaces the daemon binary and nothing else.
const CompanionBridge = "antigravity-bridge.exe"

// BuildOptions is one release-manifest build.
type BuildOptions struct {
	// Dir holds the release assets (archives, .sig files, SHA256SUMS).
	Dir string
	// Version is the release tag ("v1.33.0"); every archive in Dir that
	// names a different version is a mixed directory and fails.
	Version string
	// Channel is stable | lts | edge.
	Channel string
	// ManifestVersion is the monotonic publish ordinal. Zero derives it
	// from ReleasedAt (see buildManifest).
	ManifestVersion int64
	// ReleasedAt defaults to now.
	ReleasedAt time.Time
	// ExpiresDays is the manifest's freshness window (§2.3's anti-freeze
	// control). Zero uses defaultExpiryDays.
	ExpiresDays int
	// Notes / NotesURL / MinFromVersion / MinServerVersion are optional
	// manifest fields, passed straight through to Validate.
	Notes            string
	NotesURL         string
	MinFromVersion   string
	MinServerVersion string
	// SchemaVersion is the agent DB schema high-water mark the released
	// binary carries. Zero means "not declared", which every node treats
	// as "may advance the schema" and therefore snapshots its whole
	// database on every apply — correct, but expensive on a 14 GB node.
	// Declaring it is what makes VACUUM INTO run only across a real
	// migration.
	SchemaVersion int
	// Key signs the envelope.
	Key ed25519.PrivateKey
}

// defaultExpiryDays is how long a published release manifest stays
// fresh. It matches `observer-org update publish --expires-at`'s own
// default so the pipeline's document and an admin's do not disagree
// about what "current" means.
const defaultExpiryDays = 90

// buildManifest assembles, validates and signs the release manifest for
// one channel from a directory of release assets.
//
// The order is the security content: bytes are hashed before anything
// is recorded, every archive must carry a real signature, the member is
// read out of the archive itself, and the document is put through the
// SAME update.Validate the node runs before a signature is ever placed
// over it. Signing an invalid manifest is the one outcome worth
// preventing outright, because a signature is what makes it look
// trustworthy.
func buildManifest(opts BuildOptions) (update.Envelope, update.Manifest, error) {
	var env update.Envelope
	released := opts.ReleasedAt
	if released.IsZero() {
		released = time.Now()
	}
	released = released.UTC().Truncate(time.Second)
	expiryDays := opts.ExpiresDays
	if expiryDays <= 0 {
		expiryDays = defaultExpiryDays
	}
	manifestVersion := opts.ManifestVersion
	if manifestVersion == 0 {
		// The release timestamp in whole seconds. It is monotonic across
		// releases without any shared counter, which matters because
		// verify rule 6 refuses a manifest_version that is not ahead of
		// the last one a node accepted, and this producer has no state.
		manifestVersion = released.Unix()
	}
	if !update.KnownChannel(update.Channel(opts.Channel)) {
		return env, update.Manifest{}, fmt.Errorf("vendorsign: unknown channel %q (want stable, lts or edge)", opts.Channel)
	}

	sums, err := readSums(filepath.Join(opts.Dir, SumsFileName))
	if err != nil {
		return env, update.Manifest{}, err
	}
	artifacts, err := collectArtifacts(opts.Dir, opts.Version, sums)
	if err != nil {
		return env, update.Manifest{}, err
	}
	if len(artifacts) == 0 {
		return env, update.Manifest{}, fmt.Errorf("vendorsign: no agent archives for %s in %s", opts.Version, opts.Dir)
	}
	update.SortArtifacts(artifacts)

	m := update.Manifest{
		Schema:           update.SchemaV1,
		Channel:          update.Channel(opts.Channel),
		ManifestVersion:  manifestVersion,
		Version:          opts.Version,
		ReleasedAt:       released.Format(time.RFC3339),
		ExpiresAt:        released.AddDate(0, 0, expiryDays).Format(time.RFC3339),
		MinFromVersion:   opts.MinFromVersion,
		MinServerVersion: opts.MinServerVersion,
		Notes:            opts.Notes,
		NotesURL:         opts.NotesURL,
		SchemaVersion:    opts.SchemaVersion,
		Artifacts:        artifacts,
	}
	if err := update.Validate(m); err != nil {
		return env, update.Manifest{}, fmt.Errorf("vendorsign: refusing to sign an invalid manifest: %w", err)
	}

	body, err := update.CanonicalJSON(m)
	if err != nil {
		return env, update.Manifest{}, err
	}
	hash := update.HashBytes(body)
	pub, ok := opts.Key.Public().(ed25519.PublicKey)
	if !ok {
		return env, update.Manifest{}, fmt.Errorf("vendorsign: signing key is not Ed25519")
	}
	sig := ed25519.Sign(opts.Key, update.ManifestSigningMessage(manifestVersion, hash))
	env = update.Envelope{
		ManifestB64:  base64.StdEncoding.EncodeToString(body),
		ManifestHash: hash,
		KeyID:        keyID(pub),
		Signature:    base64.StdEncoding.EncodeToString(sig),
	}
	return env, m, nil
}

// collectArtifacts turns every agent archive in dir into a manifest row.
func collectArtifacts(dir, version string, sums map[string]string) ([]update.Artifact, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("vendorsign: %w", err)
	}
	var out []update.Artifact
	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		// One parser for archive names, shared with the org server's
		// importer (internal/update.ParseArtifactName). A foreign file
		// (SHA256SUMS, provenance, SBOMs, the observer-org archives) is
		// skipped; an agent archive with the wrong archive type for its
		// target is a mis-built release and fails loudly.
		ver, goos, goarch, archiveType, perr := update.ParseArtifactName(name)
		if errors.Is(perr, update.ErrArchiveTypeMismatch) {
			return nil, fmt.Errorf("vendorsign: %w", perr)
		}
		if perr != nil {
			continue
		}
		if ver != version {
			return nil, fmt.Errorf("vendorsign: %s is version %s but this manifest is for %s", name, ver, version)
		}
		a, aerr := buildArtifact(dir, name, goos, goarch, archiveType, sums)
		if aerr != nil {
			return nil, aerr
		}
		out = append(out, a)
	}
	return out, nil
}

// buildArtifact hashes one archive, reads its signature, derives the
// companion entries it carries and hashes the member inside it.
func buildArtifact(dir, name, osTok, archTok, archiveType string, sums map[string]string) (update.Artifact, error) {
	path := filepath.Join(dir, name)
	goos, goarch := update.NormalizeOS(osTok), update.NormalizeArch(archTok)
	if want := update.DefaultArchiveTypeFor(goos); want != archiveType {
		return update.Artifact{}, fmt.Errorf("vendorsign: %s is a %s but %s archives are %s", name, archiveType, goos, want)
	}
	sum, size, err := hashFile(path)
	if err != nil {
		return update.Artifact{}, err
	}
	if declared, ok := sums[name]; ok && declared != sum {
		return update.Artifact{}, fmt.Errorf("vendorsign: %s hashes to %s but %s says %s", name, sum, SumsFileName, declared)
	} else if !ok {
		return update.Artifact{}, fmt.Errorf("vendorsign: %s has no %s entry", name, SumsFileName)
	}
	sig, err := readSignature(path + SigSuffix)
	if err != nil {
		return update.Artifact{}, err
	}
	entries, err := archiveEntries(path, archiveType)
	if err != nil {
		return update.Artifact{}, err
	}
	member := update.BinaryName(goos)
	companions, err := deriveCompanions(name, member, update.AliasName(goos), entries)
	if err != nil {
		return update.Artifact{}, err
	}
	a := update.Artifact{
		Kind:            update.KindAgent,
		OS:              goos,
		Arch:            goarch,
		ArchiveType:     archiveType,
		Filename:        name,
		SizeBytes:       size,
		SHA256:          sum,
		Member:          member,
		AliasMembers:    companions,
		UpstreamSigType: update.SigTypeEd25519,
		UpstreamSig:     base64.StdEncoding.EncodeToString(sig),
	}
	memberSum, err := hashMember(path, a, entries)
	if err != nil {
		return update.Artifact{}, err
	}
	a.MemberSHA256 = memberSum
	return a, nil
}

// deriveCompanions lists the entries an archive carries beside the
// member, and refuses any the release is not expected to ship.
//
// It is an ALLOW-LIST, not a "declare whatever is in there" loop, and
// that is the whole point of the field: update.SelectMember treats an
// undeclared entry as a failure so that a file appearing in an archive
// is NOTICED. Deriving the declaration from the archive would forward
// any smuggled file straight into the manifest and hand it a signature.
// So a new companion file is a deliberate edit here plus a re-read of
// what the extractor should do with it.
//
// A directory entry named "." or "./" is rejected rather than skipped.
// It is what `tar -C dir .` records, and update.SelectMember refuses it
// ("empty entry name"), so an archive built that way is un-appliable no
// matter how well it is signed. The release job therefore tars EXPLICIT
// member names; this refusal is what keeps it that way.
func deriveCompanions(archive, member, alias string, entries []update.Entry) ([]string, error) {
	allowed := map[string]bool{alias: true, CompanionBridge: true}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		n := e.Name
		if n == "" || n == "." {
			return nil, fmt.Errorf("vendorsign: %s carries a %q root entry, which update.SelectMember refuses; "+
				"build the archive with explicit member names, not `tar -C dir .`", archive, e.Name)
		}
		if n == member || e.Kind == update.EntryDir {
			continue
		}
		if !allowed[n] {
			return nil, fmt.Errorf("vendorsign: %s carries an undeclared entry %q; "+
				"add it to the allow-list in deriveCompanions (and decide what the extractor does with it) "+
				"or keep it out of the archive", archive, n)
		}
		if seen[n] {
			return nil, fmt.Errorf("vendorsign: %s carries %q twice", archive, n)
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// readSums parses SHA256SUMS into filename -> hex hash. Both GNU
// coreutils shapes ("<hash>  <name>" and "<hash> *<name>") are read.
func readSums(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // a release-asset path this tool was pointed at
	if err != nil {
		return nil, fmt.Errorf("vendorsign: no %s beside the archives: %w", SumsFileName, err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out[filepath.Base(strings.TrimPrefix(fields[len(fields)-1], "*"))] = strings.ToLower(fields[0])
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("vendorsign: read %s: %w", SumsFileName, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("vendorsign: %s is empty", SumsFileName)
	}
	return out, nil
}

// writeEnvelope writes the signed envelope as indented JSON.
//
// Indented because a human reads this file when a release goes wrong,
// and the signature covers the base64 manifest INSIDE it rather than
// this file's own formatting, so pretty-printing costs nothing.
func writeEnvelope(path string, env update.Envelope) error {
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("vendorsign: encode envelope: %w", err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil { //nolint:gosec // a public release asset
		return fmt.Errorf("vendorsign: write %s: %w", path, err)
	}
	return nil
}
