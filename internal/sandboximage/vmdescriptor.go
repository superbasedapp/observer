package sandboximage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// vmdescriptor.go is the microVM guest image set's descriptor (sandbox plan
// v2 sections 12.3 and 13 P4, lane SBX-P4, ledger SBX-BE-4): the small
// signed file the sandbox.rootfs manifest covers beside the kernel, the
// initramfs, the read-only rootfs and its dm-verity hash tree. It names the
// set's version and the lowest version its publisher still allows, the
// verity root hash the kernel command line carries, the recipe's hash and
// source commit, the pinned distro kernel package, whether the guest allows
// unprivileged user namespaces (N13), and where the bulk bytes may be
// fetched from. A guest image set never carries an agent CLI (D-751 Q38).

// The sandbox.rootfs entry names.
const (
	VMDescriptorName = "sandbox-vm.json"
	VMSBOMName       = "sandbox-vm.spdx.json"
	VMKernelName     = "vmlinuz"
	VMInitramfsName  = "initrd.img"
	VMRootfsName     = "rootfs.img"
	VMVerityName     = "rootfs.verity"
	// VMDescriptorSchema is the descriptor's schema id.
	VMDescriptorSchema = "sbo.sandbox-vm.v1"
)

// GuestBinaryName is the sandbox.guest_binary entry name (one entry per
// architecture, OS linux).
const GuestBinaryName = "observer-guest"

// MinVMVersion is the lowest guest image set version this agent accepts,
// whatever a manifest says (raised only by an agent release).
const MinVMVersion = "1.0.0"

// The per-entry size caps: the import and the fetch stream each entry
// under its cap, and the manifest builder refuses an entry above it.
var vmEntryCaps = map[string]int64{
	VMDescriptorName: maxDescriptorBytes,
	VMSBOMName:       8 << 20,
	VMKernelName:     64 << 20,
	VMInitramfsName:  256 << 20,
	VMRootfsName:     4 << 30,
	VMVerityName:     512 << 20,
	GuestBinaryName:  256 << 20,
}

// VMEntryCap is an entry's size cap (0: not a VM set entry).
func VMEntryCap(name string) int64 { return vmEntryCaps[name] }

// VMDescriptor is the signed description of one guest image set.
type VMDescriptor struct {
	Schema string `json:"schema"`
	// Version is the set's version (MAJOR.MINOR.PATCH), its id in
	// [terminal.sandbox.vm].image_set; MinVersion the lowest the publisher
	// still allows.
	Version    string `json:"version"`
	MinVersion string `json:"min_version"`
	// Arch is the guest architecture (amd64 or arm64).
	Arch string `json:"arch"`
	// VerityRootHash is the dm-verity root hash of the rootfs (64 hex); the
	// hash tree is the rootfs.verity entry, with its own superblock.
	VerityRootHash string `json:"verity_root_hash"`
	// Recipe and RecipeSHA256 are the recipe directory's manifest path and
	// digest; SourceCommit the commit it was built from.
	Recipe       string `json:"recipe"`
	RecipeSHA256 string `json:"recipe_sha256"`
	SourceCommit string `json:"source_commit"`
	// Kernel is the pinned distro kernel package the vmlinuz came from.
	Kernel KernelPackage `json:"kernel"`
	// GuestUserns: the guest kernel allows unprivileged user namespaces (an
	// agent's own sandbox nests in the VM, N13); the guest init's
	// self-test confirms it before it counts.
	GuestUserns bool `json:"guest_userns"`
	// SBOM names the SBOM entry of the same manifest.
	SBOM string `json:"sbom"`
	// AgentCLI must be false: no agent CLI in a guest image (D-751 Q38).
	AgentCLI bool `json:"agent_cli"`
	// FetchBase is where the entries may be fetched from (an https URL on
	// the public Observer release, operator ruling P-126); empty means
	// import only.
	FetchBase string `json:"fetch_base,omitempty"`
	// Debug marks a debug image set (R-016): the recipe variant under
	// deploy/sandbox-vm-image/debug that adds the guest-helper kill and
	// guest-root remount hooks for the live checks. It is never shipped:
	// vendorsign refuses to sign one with the vendor key, the importer
	// takes one only with --debug-set and --debug-key, and a node boots
	// one only when the debug key it was imported with verifies it.
	Debug bool `json:"debug,omitempty"`
}

// KernelPackage pins the distro kernel package by name, version and the
// package file's sha256.
type KernelPackage struct {
	Package string `json:"package"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

var (
	archRE    = regexp.MustCompile(`^(amd64|arm64)$`)
	pkgRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]{1,127}$`)
	pkgVerRE  = regexp.MustCompile(`^[A-Za-z0-9.+:~-]{1,64}$`)
	fetchHost = map[string]bool{"github.com": true, "superbased.app": true}
)

// vmDescriptorRules are walked top-down; the first failing row is the
// reason.
var vmDescriptorRules = []struct {
	name  string
	check func(d VMDescriptor) error
}{
	{"schema", func(d VMDescriptor) error {
		return want(d.Schema == VMDescriptorSchema, "schema %q, want %q", d.Schema, VMDescriptorSchema)
	}},
	{"version", func(d VMDescriptor) error { _, err := ParseVersion(d.Version); return err }},
	{"min_version", func(d VMDescriptor) error { _, err := ParseVersion(d.MinVersion); return err }},
	{"arch", func(d VMDescriptor) error {
		return want(archRE.MatchString(d.Arch), "arch %q is not amd64 or arm64", d.Arch)
	}},
	{"verity_root_hash", func(d VMDescriptor) error {
		return want(hexRE.MatchString(d.VerityRootHash), "verity root hash %q is not 64 lowercase hex", d.VerityRootHash)
	}},
	{"recipe", func(d VMDescriptor) error {
		ok := d.Recipe != "" && !strings.HasPrefix(d.Recipe, "/") && !strings.Contains(d.Recipe, "..") && hexRE.MatchString(d.RecipeSHA256)
		return want(ok, "recipe %q with digest %q is not a relative path and a hex sha256", d.Recipe, d.RecipeSHA256)
	}},
	{"source_commit", func(d VMDescriptor) error {
		return want(commitRE.MatchString(d.SourceCommit), "source commit %q is not a full hex commit id", d.SourceCommit)
	}},
	{"kernel", func(d VMDescriptor) error {
		k := d.Kernel
		return want(pkgRE.MatchString(k.Package) && pkgVerRE.MatchString(k.Version) && hexRE.MatchString(k.SHA256),
			"kernel package %+v is not a name, a version and a sha256", k)
	}},
	{"sbom", func(d VMDescriptor) error { return want(d.SBOM == VMSBOMName, "sbom %q, want %q", d.SBOM, VMSBOMName) }},
	{"agent_cli", func(d VMDescriptor) error {
		return want(!d.AgentCLI, "the image set declares an agent CLI; a guest image never carries one (D-751 Q38)")
	}},
	{"fetch_base", func(d VMDescriptor) error {
		if d.FetchBase == "" {
			return nil
		}
		u, err := url.Parse(d.FetchBase)
		ok := err == nil && u.Scheme == "https" && fetchHost[u.Hostname()] && u.Port() == "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
		return want(ok, "fetch base %q is not an https URL on the Observer release hosts", d.FetchBase)
	}},
}

// ParseVMDescriptor decodes and checks a descriptor; unknown fields are
// refused.
func ParseVMDescriptor(b []byte) (VMDescriptor, error) {
	if len(b) > maxDescriptorBytes {
		return VMDescriptor{}, fmt.Errorf("sandboximage: the VM descriptor is over %d bytes", maxDescriptorBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var d VMDescriptor
	if err := dec.Decode(&d); err != nil {
		return VMDescriptor{}, fmt.Errorf("sandboximage: VM descriptor: %w", err)
	}
	if dec.More() {
		return VMDescriptor{}, errors.New("sandboximage: VM descriptor: trailing data")
	}
	if err := d.Validate(); err != nil {
		return VMDescriptor{}, err
	}
	return d, nil
}

// Validate walks the descriptor's table.
func (d VMDescriptor) Validate() error {
	for _, r := range vmDescriptorRules {
		if err := r.check(d); err != nil {
			return fmt.Errorf("sandboximage: VM descriptor %s: %w", r.name, err)
		}
	}
	return nil
}

// Encode is the descriptor's canonical bytes.
func (d VMDescriptor) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sandboximage: encode: %w", err)
	}
	return append(b, '\n'), nil
}
