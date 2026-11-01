package sandboximage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The artifact names the sandbox.image manifest covers.
const (
	// DescriptorName is the descriptor's entry name.
	DescriptorName = "sandbox-image.json"
	// SBOMName is the SBOM's entry name (SPDX 2.3 JSON).
	SBOMName = "sandbox-image.spdx.json"
	// DescriptorSchema is the descriptor's schema id.
	DescriptorSchema = "sbo.sandbox-image.v1"
	// maxDescriptorBytes caps the descriptor.
	maxDescriptorBytes = 16 << 10
)

// MinVersion is the lowest default image version this agent accepts,
// whatever a manifest says. Raising it is one line plus an agent release,
// the only channel that can move a floor a captured manifest cannot lower.
const MinVersion = "1.0.0"

// Descriptor is the signed description of one published default image.
type Descriptor struct {
	Schema string `json:"schema"`
	// Repository is the image's repository, without a tag or digest.
	Repository string `json:"repository"`
	// Digest is the image's content digest (sha256:<64 hex>), the index or
	// manifest digest a pull by digest names.
	Digest string `json:"digest"`
	// ConfigDigests are the per-platform image ids (config digests,
	// sha256:<64 hex>) the engine reports after the pull; empty skips the
	// id check (the RepoDigests check still runs).
	ConfigDigests map[string]string `json:"config_digests,omitempty"`
	// Version is the image's version (MAJOR.MINOR.PATCH).
	Version string `json:"version"`
	// MinVersion is the lowest version the publisher still allows; a
	// manifest naming an image below it is refused.
	MinVersion string `json:"min_version"`
	// Platforms are the os/arch pairs the image carries.
	Platforms []string `json:"platforms"`
	// Recipe is the recipe's path in the source tree and RecipeSHA256 its
	// hex digest; SourceCommit the commit it was built from.
	Recipe       string `json:"recipe"`
	RecipeSHA256 string `json:"recipe_sha256"`
	SourceCommit string `json:"source_commit"`
	// BaseImage is the recipe's base, pinned by digest.
	BaseImage string `json:"base_image"`
	// SBOM names the SBOM entry of the same manifest.
	SBOM string `json:"sbom"`
	// AgentCLI must be false: Observer's image never carries an agent CLI
	// (plan I9, SBX-IMG-1); the agent comes from the host-toolchain bind.
	AgentCLI bool `json:"agent_cli"`
	// SizeBytes is the image's download size for the largest platform
	// (the sum of its compressed layers), optional: a launch-time pull says
	// it before the download and is stopped past it (lane SBX-P3C audit
	// finding 5). Zero means not declared.
	SizeBytes int64 `json:"size_bytes,omitempty"`
}

// MaxSizeBytes caps a declared image size.
const MaxSizeBytes = 32 << 30

var (
	digestRE     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	hexRE        = regexp.MustCompile(`^[a-f0-9]{64}$`)
	commitRE     = regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`)
	repositoryRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*[a-z0-9](:[0-9]+)?(/[a-z0-9][a-z0-9._/-]*)*$`)
	platformRE   = regexp.MustCompile(`^linux/(amd64|arm64)$`)
	baseRefRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]*@sha256:[a-f0-9]{64}$`)
)

// descriptorRule is one row of the descriptor's structure table.
type descriptorRule struct {
	name  string
	check func(d Descriptor) error
}

// descriptorRules are walked top-down; the first failing row is the reason.
var descriptorRules = []descriptorRule{
	{"schema", func(d Descriptor) error {
		return want(d.Schema == DescriptorSchema, "schema %q, want %q", d.Schema, DescriptorSchema)
	}},
	{"repository", func(d Descriptor) error {
		ok := repositoryRE.MatchString(d.Repository) && !strings.Contains(d.Repository, "@") && !strings.Contains(d.Repository, "//")
		return want(ok, "repository %q is not a plain repository name", d.Repository)
	}},
	{"digest", func(d Descriptor) error {
		return want(digestRE.MatchString(d.Digest), "digest %q is not sha256:<64 hex>", d.Digest)
	}},
	{"config_digests", func(d Descriptor) error {
		for p, id := range d.ConfigDigests {
			if !platformRE.MatchString(p) || !digestRE.MatchString(id) {
				return fmt.Errorf("config digest %s=%s is not linux/<arch>=sha256:<64 hex>", p, id)
			}
		}
		return nil
	}},
	{"version", func(d Descriptor) error {
		_, err := ParseVersion(d.Version)
		return err
	}},
	{"min_version", func(d Descriptor) error {
		_, err := ParseVersion(d.MinVersion)
		return err
	}},
	{"platforms", func(d Descriptor) error {
		if len(d.Platforms) == 0 {
			return errors.New("no platforms")
		}
		for _, p := range d.Platforms {
			if !platformRE.MatchString(p) {
				return fmt.Errorf("platform %q is not linux/amd64 or linux/arm64", p)
			}
		}
		return nil
	}},
	{"recipe", func(d Descriptor) error {
		ok := d.Recipe != "" && !strings.HasPrefix(d.Recipe, "/") && !strings.Contains(d.Recipe, "..") && hexRE.MatchString(d.RecipeSHA256)
		return want(ok, "recipe %q with digest %q is not a relative path and a hex sha256", d.Recipe, d.RecipeSHA256)
	}},
	{"source_commit", func(d Descriptor) error {
		return want(commitRE.MatchString(d.SourceCommit), "source commit %q is not a full hex commit id", d.SourceCommit)
	}},
	{"base_image", func(d Descriptor) error {
		return want(baseRefRE.MatchString(d.BaseImage), "base image %q is not pinned by digest", d.BaseImage)
	}},
	{"sbom", func(d Descriptor) error { return want(d.SBOM == SBOMName, "sbom %q, want %q", d.SBOM, SBOMName) }},
	{"size_bytes", func(d Descriptor) error {
		return want(d.SizeBytes >= 0 && d.SizeBytes <= MaxSizeBytes, "size %d is not between 0 and %d bytes", d.SizeBytes, int64(MaxSizeBytes))
	}},
	{"agent_cli", func(d Descriptor) error {
		return want(!d.AgentCLI, "the image declares an agent CLI; Observer's image never carries one (SBX-IMG-1)")
	}},
}

func want(ok bool, format string, args ...any) error {
	if ok {
		return nil
	}
	return fmt.Errorf(format, args...)
}

// ParseDescriptor decodes and checks a descriptor. Unknown fields are
// refused, so a field this agent does not understand is never ignored.
func ParseDescriptor(b []byte) (Descriptor, error) {
	if len(b) > maxDescriptorBytes {
		return Descriptor{}, fmt.Errorf("sandboximage: the descriptor is over %d bytes", maxDescriptorBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d Descriptor
	if err := dec.Decode(&d); err != nil {
		return Descriptor{}, fmt.Errorf("sandboximage: descriptor: %w", err)
	}
	if dec.More() {
		return Descriptor{}, errors.New("sandboximage: descriptor: trailing data")
	}
	if err := d.Validate(); err != nil {
		return Descriptor{}, err
	}
	return d, nil
}

// Validate walks the descriptor's structure table.
func (d Descriptor) Validate() error {
	for _, r := range descriptorRules {
		if err := r.check(d); err != nil {
			return fmt.Errorf("sandboximage: descriptor %s: %w", r.name, err)
		}
	}
	return nil
}

// Ref is the image reference a run uses: the repository pinned by digest.
func (d Descriptor) Ref() string { return d.Repository + "@" + d.Digest }

// Encode is the descriptor's canonical bytes (what the manifest covers).
func (d Descriptor) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sandboximage: encode: %w", err)
	}
	return append(b, '\n'), nil
}

// Version is a MAJOR.MINOR.PATCH version.
type Version [3]int

// ParseVersion parses MAJOR.MINOR.PATCH (no prefix, no suffix).
func ParseVersion(s string) (Version, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", s)
	}
	var v Version
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return Version{}, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", s)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 1<<20 {
			return Version{}, fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", s)
		}
		v[i] = n
	}
	return v, nil
}

// Less reports whether v sorts before w.
func (v Version) Less(w Version) bool {
	for i := range v {
		if v[i] != w[i] {
			return v[i] < w[i]
		}
	}
	return false
}
