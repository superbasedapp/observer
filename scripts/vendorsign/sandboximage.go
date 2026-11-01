package main

import (
	"archive/tar"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandboximage.go is the `vendorsign sandboximage` verb (sandbox plan v2
// section 12.3, ledger SBX-IMG-1, lane SBX-P3B): it turns the output of
// deploy/sandbox-image/build.sh (an OCI layout tarball and the per-platform
// Debian package lists) into the image's descriptor and SPDX SBOM, and,
// only when given a key, the signed sandbox.image content manifest. It
// reads local files only. Nothing in the tree runs it with the real key:
// that is the operator's release step, after the image is pushed with its
// digest preserved.
//
// Output, the layout a node's content store and the feed host both use:
//
//	<out>/sandbox.image/sandbox-image.json
//	<out>/sandbox.image/sandbox-image.spdx.json
//	<out>/sandbox.image/manifest.json        (only with -key)
//
// The signing seam (lane SBX-P3D): `-from-build` takes the descriptor and
// SBOM an earlier unsigned run wrote under -out, refuses unless -oci's
// digest and image ids are still the descriptor's (a rebuilt layout is
// sandbox_image_digest_mismatch) and the descriptor's repository is under
// -registry, then signs them with -key. With no -key it only checks.
// deploy/sandbox-image/publish.sh runs it before the push and again, with
// the key, after it.

// sandboxImageOptions is one build.
type sandboxImageOptions struct {
	OCI, Packages, Recipe, RecipePath string
	Repository, Version, MinVersion   string
	Commit, Base, Out                 string
	Created                           time.Time
	Key                               ed25519.PrivateKey
	ManifestVersion, Epoch            int64
	Valid                             time.Duration
	Revoke                            []string
	Issued                            time.Time
}

// revokeFlags is the repeatable -revoke sha256 flag.
type revokeFlags []string

func (r *revokeFlags) String() string { return strings.Join(*r, ",") }

func (r *revokeFlags) Set(v string) error {
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "sha256:")
	if len(v) != 64 {
		return fmt.Errorf("want a sha256 digest, got %q", v)
	}
	if _, err := hex.DecodeString(v); err != nil {
		return fmt.Errorf("want a sha256 digest, got %q", v)
	}
	*r = append(*r, v)
	return nil
}

func runSandboxImage(args []string, out *os.File) error {
	fsx := flag.NewFlagSet("sandboximage", flag.ContinueOnError)
	o := sandboxImageOptions{}
	fsx.StringVar(&o.OCI, "oci", "", "OCI layout tarball from build.sh")
	fsx.StringVar(&o.Packages, "packages", "", "directory of packages.tsv files from build.sh")
	fsx.StringVar(&o.Recipe, "recipe", "", "the recipe file (deploy/sandbox-image/Dockerfile)")
	fsx.StringVar(&o.RecipePath, "recipe-path", "deploy/sandbox-image/Dockerfile", "the recipe's path in the source tree")
	fsx.StringVar(&o.Repository, "repository", "", "the repository the image is pushed to")
	fsx.StringVar(&o.Version, "version", "", "image version MAJOR.MINOR.PATCH")
	fsx.StringVar(&o.MinVersion, "min-version", "", "lowest version still allowed")
	fsx.StringVar(&o.Commit, "commit", "", "full source commit id")
	fsx.StringVar(&o.Base, "base", "", "the base image, pinned by digest")
	fsx.StringVar(&o.Out, "out", "", "output directory")
	epochSecs := fsx.Int64("source-date-epoch", 0, "SOURCE_DATE_EPOCH of the build (the SBOM's created time)")
	keyPath := fsx.String("key", "", "vendor signing key file (release step only; omit for an unsigned build)")
	fsx.Int64Var(&o.ManifestVersion, "manifest-version", 0, "monotonic manifest version (with -key)")
	fsx.Int64Var(&o.Epoch, "epoch", 1, "data epoch (with -key)")
	validDays := fsx.Int("valid-days", 90, "manifest validity in days, at most 180 (with -key)")
	allowUnpinned := fsx.Bool("allow-unpinned-key", false, "sign with a key this tree's agents do not accept (rotation step 4 only)")
	var revoke revokeFlags
	fsx.Var(&revoke, "revoke", "sha256 digest of a withdrawn artifact or image (repeatable)")
	fromBuild := fsx.Bool("from-build", false, "check -oci against the descriptor and SBOM an unsigned run wrote under -out, then sign them with -key (no -key: check only)")
	registry := fsx.String("registry", "", "with -from-build: the registry the image is pushed to; the descriptor's repository must be under it")
	if err := fsx.Parse(args); err != nil {
		return err
	}
	if *fromBuild {
		if o.OCI == "" || o.Out == "" || *registry == "" {
			return errors.New("vendorsign sandboximage -from-build: -oci, -out and -registry are required")
		}
	} else if o.OCI == "" || o.Packages == "" || o.Recipe == "" || o.Out == "" || *epochSecs <= 0 {
		return errors.New("vendorsign sandboximage: -oci, -packages, -recipe, -out and a positive -source-date-epoch are required")
	}
	if *epochSecs > 0 {
		o.Created = time.Unix(*epochSecs, 0).UTC()
	}
	o.Revoke = revoke
	o.Valid = time.Duration(*validDays) * 24 * time.Hour
	o.Issued = time.Now().UTC()
	if *keyPath != "" {
		if o.ManifestVersion <= 0 {
			return errors.New("vendorsign sandboximage: -key needs a positive -manifest-version")
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
		o.Key = priv
	}
	if *fromBuild {
		d, err := signBuiltSandboxImage(o, *registry)
		if err != nil {
			return err
		}
		signed := "no"
		if o.Key != nil {
			signed = "yes"
		}
		// key=value lines: publish.sh reads them.
		fmt.Fprintf(out, "repository=%s\ndigest=%s\nversion=%s\nsigned=%s\n", d.Repository, d.Digest, d.Version, signed)
		return nil
	}
	d, err := buildSandboxImage(o)
	if err != nil {
		return err
	}
	signed := "unsigned (sign at the release step with -key)"
	if o.Key != nil {
		signed = "signed"
	}
	fmt.Fprintf(out, "sandboximage: %s version %s, %s\n", d.Ref(), d.Version, signed)
	return nil
}

// buildSandboxImage writes the descriptor and the SBOM, and the signed
// manifest when a key is given.
func buildSandboxImage(o sandboxImageOptions) (sandboximage.Descriptor, error) {
	layout, err := readOCILayout(o.OCI)
	if err != nil {
		return sandboximage.Descriptor{}, err
	}
	recipe, err := os.ReadFile(o.Recipe) //nolint:gosec // operator-supplied recipe path
	if err != nil {
		return sandboximage.Descriptor{}, fmt.Errorf("vendorsign sandboximage: %w", err)
	}
	platforms := make([]string, 0, len(layout.configs))
	for p := range layout.configs {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	d := sandboximage.Descriptor{
		Schema: sandboximage.DescriptorSchema, Repository: o.Repository, Digest: layout.digest,
		ConfigDigests: layout.configs, Version: o.Version, MinVersion: o.MinVersion, Platforms: platforms,
		Recipe: o.RecipePath, RecipeSHA256: content.HashBytes(recipe), SourceCommit: o.Commit,
		BaseImage: o.Base, SBOM: sandboximage.SBOMName,
		// The download size the launch-time pull says first and is bounded
		// by (R-038), from the layout itself.
		SizeBytes: layout.maxSize(),
	}
	if err := d.Validate(); err != nil {
		return d, err
	}
	pkgs, err := readPackageLists(o.Packages, platforms)
	if err != nil {
		return d, err
	}
	sbom, err := sandboximage.SPDX(sandboximage.SBOMInput{Descriptor: d, Created: o.Created, Packages: pkgs})
	if err != nil {
		return d, err
	}
	desc, err := d.Encode()
	if err != nil {
		return d, err
	}
	dir := filepath.Join(o.Out, string(content.SandboxImage))
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // public release artifacts
		return d, fmt.Errorf("vendorsign sandboximage: %w", err)
	}
	files := map[string][]byte{sandboximage.DescriptorName: desc, sandboximage.SBOMName: sbom}
	if o.Key != nil {
		eb, err := signSandboxImageManifest(o, desc, sbom)
		if err != nil {
			return d, err
		}
		files["manifest.json"] = eb
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil { //nolint:gosec // public release artifacts
			return d, fmt.Errorf("vendorsign sandboximage: %w", err)
		}
	}
	return d, nil
}

// signSandboxImageManifest builds and signs the sandbox.image manifest over
// the descriptor and SBOM bytes, returning the envelope bytes.
func signSandboxImageManifest(o sandboxImageOptions, desc, sbom []byte) ([]byte, error) {
	revoked := make([]content.Revocation, 0, len(o.Revoke))
	for _, r := range o.Revoke {
		revoked = append(revoked, content.Revocation{SHA256: r, Reason: "withdrawn by the publisher"})
	}
	m, err := sandboximage.BuildManifest(sandboximage.ManifestInput{
		Descriptor: desc, SBOM: sbom, ManifestVersion: o.ManifestVersion, Epoch: o.Epoch,
		Issued: o.Issued, Valid: o.Valid, Revoked: revoked,
	})
	if err != nil {
		return nil, err
	}
	env, err := content.Sign(m, o.Key)
	if err != nil {
		return nil, err
	}
	return content.EncodeEnvelope(env)
}

// errDigestMismatch names the publish path's reproducibility refusal.
var errDigestMismatch = errors.New("sandbox_image_digest_mismatch")

// signBuiltSandboxImage is the signing seam: it reads the descriptor and
// SBOM an unsigned run wrote, checks the OCI layout still carries the
// descriptor's digest and image ids and that the repository is under
// registry, and only then, with a key, writes the signed manifest. The
// descriptor and SBOM bytes are never rewritten, so the manifest covers
// exactly what build.sh produced.
func signBuiltSandboxImage(o sandboxImageOptions, registry string) (sandboximage.Descriptor, error) {
	dir := filepath.Join(o.Out, string(content.SandboxImage))
	desc, err := os.ReadFile(filepath.Join(dir, sandboximage.DescriptorName)) //nolint:gosec // build output
	if err != nil {
		return sandboximage.Descriptor{}, fmt.Errorf("vendorsign sandboximage: no unsigned build under -out: %w", err)
	}
	d, err := sandboximage.ParseDescriptor(desc)
	if err != nil {
		return d, err
	}
	sbom, err := os.ReadFile(filepath.Join(dir, sandboximage.SBOMName)) //nolint:gosec // build output
	if err != nil {
		return d, fmt.Errorf("vendorsign sandboximage: %w", err)
	}
	if err := sandboximage.CheckSBOM(sbom); err != nil {
		return d, err
	}
	reg := strings.TrimSuffix(strings.TrimSpace(registry), "/")
	if reg == "" || !strings.HasPrefix(d.Repository, reg+"/") {
		return d, fmt.Errorf("vendorsign sandboximage: the descriptor's repository %s is not under the registry %q", d.Repository, registry)
	}
	layout, err := readOCILayout(o.OCI)
	if err != nil {
		return d, err
	}
	if layout.digest != d.Digest {
		return d, fmt.Errorf("vendorsign sandboximage: %w: the layout's digest %s is not the descriptor's %s (rebuilt or changed after build.sh)", errDigestMismatch, layout.digest, d.Digest)
	}
	for p, id := range d.ConfigDigests {
		if layout.configs[p] != id {
			return d, fmt.Errorf("vendorsign sandboximage: %w: the layout's %s image id %s is not the descriptor's %s", errDigestMismatch, p, layout.configs[p], id)
		}
	}
	if len(layout.configs) != len(d.ConfigDigests) && len(d.ConfigDigests) > 0 {
		return d, fmt.Errorf("vendorsign sandboximage: %w: the layout carries %d platforms, the descriptor %d", errDigestMismatch, len(layout.configs), len(d.ConfigDigests))
	}
	// The signed size must be the layout's (R-038): a declared size the
	// layers do not add up to is refused; a descriptor an older unsigned
	// run wrote without one is signed as it is, said once.
	switch {
	case d.SizeBytes != 0 && d.SizeBytes != layout.maxSize():
		return d, fmt.Errorf("vendorsign sandboximage: %w: the descriptor declares %d bytes, the layout's largest platform is %d", errDigestMismatch, d.SizeBytes, layout.maxSize())
	case d.SizeBytes == 0:
		fmt.Fprintln(os.Stderr, "vendorsign sandboximage: the descriptor declares no size_bytes (written before the signing step filled it); nodes will say \"size not declared\" and apply the 8 GB bound. Re-run the unsigned build to declare it.")
	}
	if o.Key == nil {
		return d, nil
	}
	eb, err := signSandboxImageManifest(o, desc, sbom)
	if err != nil {
		return d, err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), eb, 0o644); err != nil { //nolint:gosec // public release artifacts
		return d, fmt.Errorf("vendorsign sandboximage: %w", err)
	}
	return d, nil
}

// ociLayout is what the verb reads from the OCI layout: the top digest
// (what a pull by digest names) and each platform's config digest (the
// image id the engine reports).
type ociLayout struct {
	digest  string
	configs map[string]string
	// sizes is each platform's download size: the sum of its compressed
	// layers as its image manifest lists them (R-038).
	sizes map[string]int64
}

// maxSize is the largest platform's download size, what the descriptor's
// size_bytes declares.
func (l ociLayout) maxSize() int64 {
	var m int64
	for _, s := range l.sizes {
		m = max(m, s)
	}
	return m
}

// ociLayerSum sums an image manifest's layer sizes; a negative size, or a
// sum past the descriptor's cap, is refused.
func ociLayerSum(m ociIndex) (int64, error) {
	var sum int64
	for _, layer := range m.Layers {
		if layer.Size < 0 {
			return 0, fmt.Errorf("vendorsign sandboximage: layer %s has a negative size", layer.Digest)
		}
		sum += layer.Size
		if sum > sandboximage.MaxSizeBytes {
			return 0, fmt.Errorf("vendorsign sandboximage: the image's layers pass %d bytes", int64(sandboximage.MaxSizeBytes))
		}
	}
	return sum, nil
}

// maxOCIJSON caps each JSON file read from the layout; layers are skipped.
const maxOCIJSON = 1 << 20

var ociBlobRE = regexp.MustCompile(`^blobs/sha256/[a-f0-9]{64}$`)

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size,omitempty"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
	} `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type ociIndex struct {
	MediaType string          `json:"mediaType"`
	Manifests []ociDescriptor `json:"manifests"`
	Config    *ociDescriptor  `json:"config,omitempty"`
	Layers    []ociDescriptor `json:"layers,omitempty"`
}

const (
	mediaIndex       = "application/vnd.oci.image.index.v1+json"
	mediaManifest    = "application/vnd.oci.image.manifest.v1+json"
	mediaDockerList  = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaDockerImage = "application/vnd.docker.distribution.manifest.v2+json"
)

// readOCILayout reads index.json and the small JSON blobs of an OCI layout
// tarball and resolves the top digest and the per-platform config digests.
// Every blob read is checked against its name.
func readOCILayout(path string) (ociLayout, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied build output
	if err != nil {
		return ociLayout{}, fmt.Errorf("vendorsign sandboximage: %w", err)
	}
	defer func() { _ = f.Close() }()
	files := map[string][]byte{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ociLayout{}, fmt.Errorf("vendorsign sandboximage: %w", err)
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag != tar.TypeReg || h.Size > maxOCIJSON || (name != "index.json" && !ociBlobRE.MatchString(name)) {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxOCIJSON+1))
		if err != nil {
			return ociLayout{}, fmt.Errorf("vendorsign sandboximage: %w", err)
		}
		files[name] = b
	}
	blob := func(digest string) ([]byte, error) {
		hexd := strings.TrimPrefix(digest, "sha256:")
		b, ok := files["blobs/sha256/"+hexd]
		if !ok || len(hexd) != 64 {
			return nil, fmt.Errorf("vendorsign sandboximage: blob %s is missing from the layout", digest)
		}
		if content.HashBytes(b) != hexd {
			return nil, fmt.Errorf("vendorsign sandboximage: blob %s does not match its digest", digest)
		}
		return b, nil
	}
	var top ociIndex
	if err := json.Unmarshal(files["index.json"], &top); err != nil || len(top.Manifests) != 1 {
		return ociLayout{}, errors.New("vendorsign sandboximage: index.json must name exactly one image")
	}
	l := ociLayout{digest: top.Manifests[0].Digest, configs: map[string]string{}, sizes: map[string]int64{}}
	b, err := blob(l.digest)
	if err != nil {
		return ociLayout{}, err
	}
	var m ociIndex
	if err := json.Unmarshal(b, &m); err != nil {
		return ociLayout{}, fmt.Errorf("vendorsign sandboximage: %w", err)
	}
	switch top.Manifests[0].MediaType {
	case mediaIndex, mediaDockerList:
		for _, pm := range m.Manifests {
			if pm.Platform == nil || pm.Platform.OS == "unknown" || pm.Annotations["vnd.docker.reference.type"] != "" {
				continue // an attestation manifest, not a platform image
			}
			mb, err := blob(pm.Digest)
			if err != nil {
				return ociLayout{}, err
			}
			var pmm ociIndex
			if err := json.Unmarshal(mb, &pmm); err != nil || pmm.Config == nil {
				return ociLayout{}, fmt.Errorf("vendorsign sandboximage: manifest %s has no config", pm.Digest)
			}
			plat := pm.Platform.OS + "/" + pm.Platform.Architecture
			l.configs[plat] = pmm.Config.Digest
			if l.sizes[plat], err = ociLayerSum(pmm); err != nil {
				return ociLayout{}, err
			}
		}
	case mediaManifest, mediaDockerImage:
		if m.Config == nil {
			return ociLayout{}, errors.New("vendorsign sandboximage: the image manifest has no config")
		}
		cb, err := blob(m.Config.Digest)
		if err != nil {
			return ociLayout{}, err
		}
		var cfg struct {
			OS           string `json:"os"`
			Architecture string `json:"architecture"`
		}
		if err := json.Unmarshal(cb, &cfg); err != nil {
			return ociLayout{}, fmt.Errorf("vendorsign sandboximage: %w", err)
		}
		l.configs[cfg.OS+"/"+cfg.Architecture] = m.Config.Digest
		if l.sizes[cfg.OS+"/"+cfg.Architecture], err = ociLayerSum(m); err != nil {
			return ociLayout{}, err
		}
	default:
		return ociLayout{}, fmt.Errorf("vendorsign sandboximage: unknown media type %q", top.Manifests[0].MediaType)
	}
	if len(l.configs) == 0 {
		return ociLayout{}, errors.New("vendorsign sandboximage: the layout carries no platform image")
	}
	return l, nil
}

// readPackageLists reads build.sh's package lists: <dir>/linux_<arch>/
// packages.tsv for a multi-platform build, <dir>/packages.tsv for one.
func readPackageLists(dir string, platforms []string) (map[string][]sandboximage.Package, error) {
	out := map[string][]sandboximage.Package{}
	for _, p := range platforms {
		candidates := []string{filepath.Join(dir, strings.ReplaceAll(p, "/", "_"), "packages.tsv")}
		if len(platforms) == 1 {
			candidates = append(candidates, filepath.Join(dir, "packages.tsv"))
		}
		var b []byte
		var err error
		for _, c := range candidates {
			if b, err = os.ReadFile(c); err == nil { //nolint:gosec // build output
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf("vendorsign sandboximage: no package list for %s: %w", p, err)
		}
		pk, err := sandboximage.ParsePackagesTSV(b)
		if err != nil {
			return nil, fmt.Errorf("vendorsign sandboximage: %s: %w", p, err)
		}
		out[p] = pk
	}
	return out, nil
}
