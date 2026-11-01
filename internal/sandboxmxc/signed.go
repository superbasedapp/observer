package sandboxmxc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// signed.go is the MXC files as the signed content kind sandbox.native_files
// (sandbox plan v2 section 12.3, ledger SBX-SUP-1, roadmap F0-6; lane
// SBX-P3D). The release turns its unsigned mxc-manifest.json into a
// canonical descriptor (NativeFiles, the kind's one artifact) that the
// vendor key signs; the node reads it back through the content channel and
// ResolveSigned decides which file set the helper checks before it loads
// anything.
//
// The compiled pins (ManifestX64) stay the floor: a signed descriptor may
// revoke the set, raise the minimum version and expire, but never name a
// file, hash or size the compiled pins do not (shipping newer MXC files
// without an agent release is later work). With none installed the
// compiled pins are used byte for byte, as before.

// The descriptor's names.
const (
	// NativeFilesName is the descriptor's entry name in the kind.
	NativeFilesName = "mxc-files.json"
	// NativeFilesSchema is its schema id.
	NativeFilesSchema = "sbo.sandbox-native-files.v1"
	// maxNativeFilesBytes caps the descriptor.
	maxNativeFilesBytes = 64 << 10
)

// NativeFiles is the signed description of one MXC file set.
type NativeFiles struct {
	Schema string `json:"schema"`
	// OS is "windows"; Arch the Go architecture the files are for.
	OS   string `json:"os"`
	Arch string `json:"arch"`
	// Upstream, Version, PackageURL and PackageSHA256 pin the package.
	Upstream      string `json:"upstream"`
	Version       string `json:"version"`
	PackageURL    string `json:"package_url"`
	PackageSHA256 string `json:"package_sha256"`
	// MinVersion is the lowest upstream version the publisher still
	// allows; a compiled set below it is refused.
	MinVersion string `json:"min_version"`
	// Signer is the Authenticode subject every file carries, and
	// Authenticode the release job's check result ("valid <thumbprints>").
	Signer       string       `json:"signer"`
	Authenticode string       `json:"authenticode"`
	Files        []NativeFile `json:"files"`
}

// NativeFile is one file of the set.
type NativeFile struct {
	Name        string `json:"name"`
	PackagePath string `json:"package_path"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
}

var (
	nativeHexRE     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	nativeVersionRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}$`)
)

// Validate checks the descriptor's structure.
func (n NativeFiles) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("sandboxmxc: native files: "+format, a...)
	}
	switch {
	case n.Schema != NativeFilesSchema:
		return bad("unknown schema %q", n.Schema)
	case n.OS != "windows":
		return bad("os must be windows, got %q", n.OS)
	case n.Arch == "":
		return bad("arch is required")
	case n.Upstream == "" || n.PackageURL == "" || n.Signer == "":
		return bad("upstream, package_url and signer are required")
	case !nativeVersionRE.MatchString(n.Version) || !nativeVersionRE.MatchString(n.MinVersion):
		return bad("version and min_version must be dotted numbers")
	case !nativeHexRE.MatchString(n.PackageSHA256):
		return bad("package_sha256 must be 64 lowercase hex characters")
	case !strings.HasPrefix(n.Authenticode, "valid"):
		return bad("the Authenticode check did not pass (%q)", n.Authenticode)
	case len(n.Files) == 0:
		return bad("no files")
	}
	seen := map[string]bool{}
	for _, f := range n.Files {
		if f.Name == "" || strings.ContainsAny(f.Name, `/\`) || seen[f.Name] {
			return bad("file name %q is empty, a path or repeated", f.Name)
		}
		seen[f.Name] = true
		if !nativeHexRE.MatchString(f.SHA256) || f.Size <= 0 || f.PackagePath == "" {
			return bad("file %s needs a lowercase sha256, a positive size and its package path", f.Name)
		}
	}
	return nil
}

// ParseNativeFiles decodes and checks a descriptor; unknown fields are
// refused.
func ParseNativeFiles(b []byte) (NativeFiles, error) {
	if len(b) > maxNativeFilesBytes {
		return NativeFiles{}, fmt.Errorf("sandboxmxc: native files: over %d bytes", maxNativeFilesBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var n NativeFiles
	if err := dec.Decode(&n); err != nil {
		return NativeFiles{}, fmt.Errorf("sandboxmxc: native files: %w", err)
	}
	if dec.More() {
		return NativeFiles{}, errors.New("sandboxmxc: native files: trailing data")
	}
	return n, n.Validate()
}

// Encode is the descriptor's canonical bytes (what the manifest covers).
func (n NativeFiles) Encode() ([]byte, error) {
	if err := n.Validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sandboxmxc: native files: %w", err)
	}
	return append(b, '\n'), nil
}

// NativeFilesFromManifest is the descriptor of a pinned set for arch, with
// the release job's Authenticode result; MinVersion is the set's own
// version (raise it on the descriptor to withdraw older sets).
func NativeFilesFromManifest(m Manifest, arch, authenticode string) NativeFiles {
	n := NativeFiles{
		Schema: NativeFilesSchema, OS: "windows", Arch: arch, Upstream: m.Upstream, Version: m.Version,
		PackageURL: m.PackageURL, PackageSHA256: m.PackageSHA256, MinVersion: m.Version, Signer: m.Signer,
		Authenticode: authenticode,
	}
	for _, f := range m.Files {
		n.Files = append(n.Files, NativeFile{Name: f.Name, PackagePath: f.PackagePath, SHA256: f.SHA256, Size: f.Size})
	}
	return n
}

// MatchesCompiled reports why the descriptor's file set is not the compiled
// pins m ("" when it is): the same upstream, version, package and files,
// name for name, hash for hash, size for size.
func (n NativeFiles) MatchesCompiled(m Manifest) string {
	switch {
	case n.Upstream != m.Upstream || n.Version != m.Version:
		return fmt.Sprintf("it names %s %s, the compiled pins %s %s", n.Upstream, n.Version, m.Upstream, m.Version)
	case n.PackageSHA256 != m.PackageSHA256:
		return "it names another package hash than the compiled pins"
	case n.Signer != m.Signer:
		return "it names another Authenticode signer than the compiled pins"
	case len(n.Files) != len(m.Files):
		return fmt.Sprintf("it names %d files, the compiled pins %d", len(n.Files), len(m.Files))
	}
	for _, f := range n.Files {
		p, ok := m.File(f.Name)
		if !ok {
			return f.Name + " is not a compiled pin"
		}
		if !strings.EqualFold(p.SHA256, f.SHA256) || p.Size != f.Size || p.PackagePath != f.PackagePath {
			return f.Name + "'s hash, size or package path is not the compiled pin's"
		}
	}
	return ""
}

// The sources of the effective set.
const (
	SignedSourceCompiled = "compiled"
	SignedSourceSigned   = "signed"
)

// SignedInput is what the node read from its content store, reduced to
// plain facts at the boundary (this package imports no content code).
type SignedInput struct {
	// Compiled is this build's pinned set for the architecture.
	Compiled    Manifest
	HasCompiled bool
	// Arch is the Go architecture.
	Arch string
	// Installed: a sandbox.native_files manifest is installed.
	Installed bool
	// LoadError is why the installed envelope failed re-verification.
	LoadError string
	// Freshness is the content channel's "fresh", "stale" or "unknown".
	Freshness string
	// Revoked are the sha256 digests the signed manifest revokes.
	Revoked []string
	// Descriptor is the verified descriptor's bytes; DescriptorError why
	// it could not be read (not covered, changed on disk).
	Descriptor      []byte
	DescriptorError string
}

// SignedResult is the effective set and how it was decided.
type SignedResult struct {
	// Manifest is the set the helper checks: always the compiled pins
	// (the floor), never a set the signed descriptor names alone; when OK
	// is false the run is refused before any file is loaded.
	Manifest Manifest
	OK       bool
	Source   string
	// Stale: used as last-known-good under an expired signed manifest.
	Stale   bool
	Verdict Verdict
	// Rule is the id of the row that decided.
	Rule string
}

type signedPass struct {
	in   SignedInput
	desc NativeFiles
}

type signedRow struct {
	id string
	// check returns a refusal reason ("" passes) and whether the row
	// decided the result without a refusal (done).
	check func(p *signedPass) (reason string, done bool)
}

// signedRows is THE decision table, walked top-down; revocation is judged
// before anything else is read, so a revoked set is refused before any
// file is opened or loaded.
var signedRows = []signedRow{
	{"no_compiled_set", func(p *signedPass) (string, bool) {
		return "", !p.in.HasCompiled // today's answer: the ladder refuses with artifact_missing
	}},
	{"none_installed", func(p *signedPass) (string, bool) {
		return "", !p.in.Installed // the compiled pins byte for byte
	}},
	{"load", func(p *signedPass) (string, bool) {
		if p.in.LoadError != "" {
			return "the installed sandbox.native_files manifest does not verify (" + p.in.LoadError + ")", false
		}
		return "", false
	}},
	{"age", func(p *signedPass) (string, bool) {
		if p.in.Freshness != "fresh" && p.in.Freshness != "stale" {
			return "the installed sandbox.native_files manifest is past its age floor (unknown); fetch a current one with `observer sandbox content fetch` (the daemon also refreshes it in the background while the node is online)", false
		}
		return "", false
	}},
	{"revoked", func(p *signedPass) (string, bool) {
		if revokedIn(p.in.Revoked, p.in.Compiled.PackageSHA256) {
			return "the signed manifest revokes the MXC package " + p.in.Compiled.Upstream + " " + p.in.Compiled.Version, false
		}
		for _, f := range p.in.Compiled.Files {
			if revokedIn(p.in.Revoked, f.SHA256) {
				return "the signed manifest revokes " + f.Name + " of MXC " + p.in.Compiled.Version, false
			}
		}
		return "", false
	}},
	{"descriptor", func(p *signedPass) (string, bool) {
		if p.in.DescriptorError != "" {
			return "the signed MXC descriptor cannot be read (" + p.in.DescriptorError + ")", false
		}
		d, err := ParseNativeFiles(p.in.Descriptor)
		if err != nil {
			return err.Error(), false
		}
		p.desc = d
		return "", false
	}},
	{"platform", func(p *signedPass) (string, bool) {
		if p.desc.Arch != p.in.Arch {
			return "the signed MXC descriptor is for " + p.desc.Arch + ", this build is " + p.in.Arch, false
		}
		return "", false
	}},
	{"floor", func(p *signedPass) (string, bool) {
		if why := p.desc.MatchesCompiled(p.in.Compiled); why != "" {
			return "the signed MXC descriptor names a file set this build's compiled pins do not (" + why + "); newer MXC files need an agent release", false
		}
		return "", false
	}},
	{"min_version", func(p *signedPass) (string, bool) {
		if versionLess(p.in.Compiled.Version, p.desc.MinVersion) {
			return "MXC " + p.in.Compiled.Version + " is below the signed minimum " + p.desc.MinVersion + "; update Observer", false
		}
		return "", false
	}},
}

// ResolveSigned walks the decision table.
func ResolveSigned(in SignedInput) SignedResult {
	p := &signedPass{in: in}
	for _, row := range signedRows {
		reason, done := row.check(p)
		if reason != "" {
			// The compiled pins ride along so no caller ever checks an empty
			// set; OK false is what refuses (before anything is loaded).
			return SignedResult{Manifest: in.Compiled, Rule: row.id, Verdict: Verdict{Code: VerdictArtifactUnverified, Reason: reason}}
		}
		if done {
			return SignedResult{Manifest: in.Compiled, OK: true, Source: SignedSourceCompiled, Rule: row.id, Verdict: Verdict{Code: VerdictAvailable}}
		}
	}
	return SignedResult{
		Manifest: in.Compiled, OK: true, Source: SignedSourceSigned, Stale: in.Freshness == "stale",
		Rule: "signed", Verdict: Verdict{Code: VerdictAvailable},
	}
}

// SignedRules lists the table's row ids, for the one-test-per-row pin.
func SignedRules() []string {
	out := make([]string, len(signedRows))
	for i, r := range signedRows {
		out[i] = r.id
	}
	return out
}

func revokedIn(list []string, sha string) bool {
	return sha != "" && slices.ContainsFunc(list, func(r string) bool { return strings.EqualFold(r, sha) })
}

// versionLess compares dotted numeric versions; a malformed one is never
// less (the descriptor's own validation refuses malformed versions).
func versionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		var err error
		if i < len(as) {
			if x, err = strconv.Atoi(as[i]); err != nil {
				return false
			}
		}
		if i < len(bs) {
			if y, err = strconv.Atoi(bs[i]); err != nil {
				return false
			}
		}
		if x != y {
			return x < y
		}
	}
	return false
}
