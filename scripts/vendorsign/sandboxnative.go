package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sandboxnative.go is the `vendorsign sandboxnative` verb (sandbox plan v2
// section 12.3, ledger SBX-SUP-1, roadmap F0-6; lane SBX-P3D): it turns the
// release's unsigned mxc-manifest.json (scripts/mxc-files.sh manifest, the
// Authenticode result included) into the canonical descriptor
// (sandboxmxc.NativeFiles) and, only when given a key, the signed
// sandbox.native_files content manifest covering it. It refuses a file set
// the compiled pins (internal/sandboxmxc.ManifestFor) do not name: a node
// would refuse it anyway, since the compiled pins are the floor. Nothing in
// the tree runs it with the real key: that is the operator's release step.
//
// Output:
//
//	<out>/sandbox.native_files/mxc-files.json
//	<out>/sandbox.native_files/manifest.json   (only with -key)

// mxcReleaseManifest is mxc-manifest.json as scripts/mxc-files.sh writes it.
type mxcReleaseManifest struct {
	Kind          string `json:"kind"`
	Upstream      string `json:"upstream"`
	Version       string `json:"version"`
	PackageURL    string `json:"package_url"`
	PackageSHA256 string `json:"package_sha256"`
	Signer        string `json:"signer"`
	Authenticode  string `json:"authenticode"`
	Files         []struct {
		Name        string `json:"name"`
		PackagePath string `json:"package_path"`
		SHA256      string `json:"sha256"`
		Size        int64  `json:"size"`
	} `json:"files"`
}

// mxcReleaseKind is mxc-manifest.json's kind.
const mxcReleaseKind = "observer.mxc-files.v1"

// sandboxNativeOptions is one run.
type sandboxNativeOptions struct {
	In, Arch, MinVersion, Out string
	Key                       ed25519.PrivateKey
	ManifestVersion, Epoch    int64
	Valid                     time.Duration
	Revoke                    []string
	Issued                    time.Time
}

func runSandboxNative(args []string, out *os.File) error {
	fsx := flag.NewFlagSet("sandboxnative", flag.ContinueOnError)
	o := sandboxNativeOptions{}
	fsx.StringVar(&o.In, "in", "", "mxc-manifest.json from scripts/mxc-files.sh manifest")
	fsx.StringVar(&o.Arch, "arch", "amd64", "Go architecture of the files")
	fsx.StringVar(&o.MinVersion, "min-version", "", "lowest MXC version still allowed (default: the file set's own)")
	fsx.StringVar(&o.Out, "out", "", "output directory")
	keyPath := fsx.String("key", "", "vendor signing key file (release step only; omit for an unsigned descriptor)")
	fsx.Int64Var(&o.ManifestVersion, "manifest-version", 0, "monotonic manifest version (with -key)")
	fsx.Int64Var(&o.Epoch, "epoch", 1, "data epoch (with -key)")
	validDays := fsx.Int("valid-days", 90, "manifest validity in days, at most 180 (with -key)")
	allowUnpinned := fsx.Bool("allow-unpinned-key", false, "sign with a key this tree's agents do not accept (rotation step 4 only)")
	var revoke revokeFlags
	fsx.Var(&revoke, "revoke", "sha256 digest of a withdrawn MXC file or package (repeatable)")
	if err := fsx.Parse(args); err != nil {
		return err
	}
	if o.In == "" || o.Out == "" {
		return errors.New("vendorsign sandboxnative: -in and -out are required")
	}
	o.Revoke = revoke
	o.Valid = time.Duration(*validDays) * 24 * time.Hour
	o.Issued = time.Now().UTC()
	if *keyPath != "" {
		if o.ManifestVersion <= 0 {
			return errors.New("vendorsign sandboxnative: -key needs a positive -manifest-version")
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
	n, err := buildSandboxNative(o)
	if err != nil {
		return err
	}
	signed := "unsigned (sign at the release step with -key)"
	if o.Key != nil {
		signed = "signed"
	}
	fmt.Fprintf(out, "sandboxnative: %s %s for windows/%s, %d files, %s\n", n.Upstream, n.Version, n.Arch, len(n.Files), signed)
	return nil
}

// buildSandboxNative writes the descriptor, and the signed manifest when a
// key is given.
func buildSandboxNative(o sandboxNativeOptions) (sandboxmxc.NativeFiles, error) {
	raw, err := os.ReadFile(o.In) //nolint:gosec // operator-supplied release output
	if err != nil {
		return sandboxmxc.NativeFiles{}, fmt.Errorf("vendorsign sandboxnative: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rm mxcReleaseManifest
	if err := dec.Decode(&rm); err != nil {
		return sandboxmxc.NativeFiles{}, fmt.Errorf("vendorsign sandboxnative: %s: %w", filepath.Base(o.In), err)
	}
	if rm.Kind != mxcReleaseKind {
		return sandboxmxc.NativeFiles{}, fmt.Errorf("vendorsign sandboxnative: %s is kind %q, want %s", filepath.Base(o.In), rm.Kind, mxcReleaseKind)
	}
	if !strings.HasPrefix(rm.Authenticode, "valid ") {
		return sandboxmxc.NativeFiles{}, fmt.Errorf("vendorsign sandboxnative: the release's Authenticode check did not pass (%q); nothing is signed", rm.Authenticode)
	}
	n := sandboxmxc.NativeFiles{
		Schema: sandboxmxc.NativeFilesSchema, OS: "windows", Arch: o.Arch, Upstream: rm.Upstream, Version: rm.Version,
		PackageURL: rm.PackageURL, PackageSHA256: rm.PackageSHA256, MinVersion: rm.Version, Signer: rm.Signer,
		Authenticode: rm.Authenticode,
	}
	if o.MinVersion != "" {
		n.MinVersion = o.MinVersion
	}
	for _, f := range rm.Files {
		n.Files = append(n.Files, sandboxmxc.NativeFile{Name: f.Name, PackagePath: f.PackagePath, SHA256: strings.ToLower(f.SHA256), Size: f.Size})
	}
	if err := n.Validate(); err != nil {
		return n, fmt.Errorf("vendorsign sandboxnative: %w", err)
	}
	compiled, ok := sandboxmxc.ManifestFor(o.Arch)
	if !ok {
		return n, fmt.Errorf("vendorsign sandboxnative: this tree compiles no MXC pins for %s", o.Arch)
	}
	if why := n.MatchesCompiled(compiled); why != "" {
		return n, fmt.Errorf("vendorsign sandboxnative: the file set is not this tree's compiled pins (%s); a node refuses it, so it is not signed", why)
	}
	desc, err := n.Encode()
	if err != nil {
		return n, err
	}
	dir := filepath.Join(o.Out, string(content.SandboxNative))
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // public release artifacts
		return n, fmt.Errorf("vendorsign sandboxnative: %w", err)
	}
	files := map[string][]byte{sandboxmxc.NativeFilesName: desc}
	if o.Key != nil {
		spec, _ := content.KindOf(content.SandboxNative)
		if o.Valid <= 0 || o.Valid > spec.MaxValidity {
			return n, fmt.Errorf("vendorsign sandboxnative: the validity must be set and at most %s", spec.MaxValidity)
		}
		revoked := make([]content.Revocation, 0, len(o.Revoke))
		for _, r := range o.Revoke {
			revoked = append(revoked, content.Revocation{SHA256: r, Reason: "withdrawn by the publisher"})
		}
		m := content.Manifest{
			Schema: content.SchemaV1, Kind: content.SandboxNative, ManifestVersion: o.ManifestVersion, Epoch: o.Epoch,
			IssuedAt: o.Issued.UTC().Format(time.RFC3339), ExpiresAt: o.Issued.Add(o.Valid).UTC().Format(time.RFC3339),
			Entries: []content.Entry{{
				Name: sandboxmxc.NativeFilesName, Version: n.Version, OS: "windows", Arch: o.Arch,
				SizeBytes: int64(len(desc)), SHA256: content.HashBytes(desc), Source: n.Upstream + "@" + n.Version,
				Upstream: content.UpstreamCheck{Method: content.UpstreamAuthenticode, Identity: n.Signer, VerifiedWhere: "release_pipeline"},
			}},
			Revoked: revoked,
		}
		env, err := content.Sign(m, o.Key)
		if err != nil {
			return n, err
		}
		eb, err := content.EncodeEnvelope(env)
		if err != nil {
			return n, err
		}
		files["manifest.json"] = eb
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil { //nolint:gosec // public release artifacts
			return n, fmt.Errorf("vendorsign sandboxnative: %w", err)
		}
	}
	return n, nil
}
