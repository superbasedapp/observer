package sandboximage

import (
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// vmresolve.go decides whether a guest image set may boot (lane SBX-P4
// decision 2, acceptance case A12): from what the content channel loaded
// for sandbox.rootfs and sandbox.guest_binary, and from the cmd layer's
// re-hash of every bulk entry through a no-follow descriptor on this load.
// Every refusal is artifact_unverified with a reason. A replayed older
// manifest is refused by the channel itself at install (its high-water
// mark), which this table sees as a load error.

// The VM set's reasons beside the image reasons.
const (
	ReasonWrongArch         = "wrong_arch"
	ReasonWrongGuestVersion = "wrong_guest_version"
	ReasonGuestMissing      = "guest_not_installed"
	ReasonEntryMissing      = "entry_missing"
	ReasonImageSetPinned    = "image_set_not_found"
	// ReasonDebugSet: a debug image set signed by a release key, or a
	// release set signed by a debug key (R-016).
	ReasonDebugSet = "debug_set"
)

// KindLoad is one kind's load.
type KindLoad struct {
	NotInstalled bool
	LoadErr      error
	Manifest     content.Manifest
	Freshness    content.Freshness
}

// VMSetInput is one resolution.
type VMSetInput struct {
	Rootfs KindLoad
	Guest  KindLoad
	// Descriptor and SBOM are ReadArtifact's results.
	Descriptor    []byte
	DescriptorErr error
	SBOM          []byte
	SBOMErr       error
	// BulkErr is the re-hash of each bulk entry (kernel, initramfs, rootfs,
	// verity; nil when it matched its entry).
	BulkErr map[string]error
	// GuestEntry is the guest binary's entry for this architecture and
	// GuestErr its lookup or re-hash error.
	GuestEntry content.Entry
	GuestErr   error
	// Arch is the host architecture; AgentVersion the running agent's
	// version (the guest binary must equal it).
	Arch         string
	AgentVersion string
	// Want is [terminal.sandbox.vm].image_set ("" accepts the installed
	// set).
	Want string
	// Floor is the agent's own minimum ("" means MinVMVersion).
	Floor string
	// DebugSigned reports that both kinds verified only under the debug
	// key the set was imported with (R-016), never a vendor key: the set
	// must then be a debug set, and a debug set must be signed so.
	DebugSigned bool
}

// VMSetResult is a resolution.
type VMSetResult struct {
	OK         bool
	Descriptor VMDescriptor
	// Stale reports a last-known-good use of an expired manifest (either
	// kind), named in the probe and the run's notes.
	Stale  bool
	Reason string
	Detail string
}

// Error is the refusal as one line.
func (r VMSetResult) Error() string {
	if r.OK {
		return ""
	}
	return VerdictArtifactUnverified + " (" + r.Reason + "): " + r.Detail
}

type vmPass struct {
	in  VMSetInput
	d   VMDescriptor
	out VMSetResult
}

func loadReason(name string, l KindLoad, kind content.Kind) (string, string) {
	if l.LoadErr != nil {
		if r := content.ReasonOf(l.LoadErr); r != "" {
			return string(r), name + ": " + l.LoadErr.Error()
		}
		return string(content.ContentReasonEnvelope), name + ": " + l.LoadErr.Error()
	}
	if l.Manifest.Kind != kind {
		return string(content.ContentReasonKind), fmt.Sprintf("%s: the manifest is %q, not %q", name, l.Manifest.Kind, kind)
	}
	return "", ""
}

func freshReason(name string, l KindLoad, p *vmPass) (string, string) {
	switch l.Freshness {
	case content.Fresh:
		return "", ""
	case content.Stale:
		// The bytes are local and re-hashed on every load, so an expired
		// manifest within the age floor boots as last-known-good, reported.
		p.out.Stale = true
		return "", ""
	}
	return ReasonUnknownAge, name + ": the manifest is past its age floor"
}

func artifactReason(err error) string {
	switch content.ReasonOf(err) {
	case content.ContentReasonRevoked:
		return ReasonRevoked
	case content.ContentReasonArtifact:
		return ReasonTampered
	}
	return ReasonEntryMissing
}

// vmSetRules are walked top-down; one test case per row.
var vmSetRules = []struct {
	name  string
	check func(p *vmPass) (string, string)
}{
	{"rootfs installed", func(p *vmPass) (string, string) {
		if p.in.Rootfs.NotInstalled {
			return ReasonNotInstalled, "no signed sandbox.rootfs manifest is installed; import a guest image set with Import image set in the microVM panel of Terminals > Settings > Sandbox isolation (same as `observer sandbox content import <dir>`)"
		}
		return "", ""
	}},
	{"guest installed", func(p *vmPass) (string, string) {
		if p.in.Guest.NotInstalled {
			return ReasonGuestMissing, "no signed sandbox.guest_binary manifest is installed; the guest observer is imported with the image set, the host's own binary is never substituted"
		}
		return "", ""
	}},
	{"rootfs verifies", func(p *vmPass) (string, string) {
		return loadReason("sandbox.rootfs", p.in.Rootfs, content.SandboxRootfs)
	}},
	{"guest verifies", func(p *vmPass) (string, string) {
		return loadReason("sandbox.guest_binary", p.in.Guest, content.SandboxGuest)
	}},
	{"rootfs fresh", func(p *vmPass) (string, string) { return freshReason("sandbox.rootfs", p.in.Rootfs, p) }},
	{"guest fresh", func(p *vmPass) (string, string) { return freshReason("sandbox.guest_binary", p.in.Guest, p) }},
	{"descriptor covered", func(p *vmPass) (string, string) {
		if p.in.DescriptorErr != nil {
			return artifactReason(p.in.DescriptorErr), "the descriptor: " + p.in.DescriptorErr.Error()
		}
		d, err := ParseVMDescriptor(p.in.Descriptor)
		if err != nil {
			return ReasonDescriptor, err.Error()
		}
		p.d = d
		return "", ""
	}},
	{"debug set only under the debug key", func(p *vmPass) (string, string) {
		switch {
		case p.d.Debug && !p.in.DebugSigned:
			return ReasonDebugSet, "the image set " + p.d.Version + " is a debug set (never shipped) but a release key signed it; a debug set boots only under the debug key it was imported with"
		case !p.d.Debug && p.in.DebugSigned:
			return ReasonDebugSet, "the image set " + p.d.Version + " is signed by the imported debug key but is not a debug set; a debug key signs only debug sets"
		}
		return "", ""
	}},
	{"set not revoked", func(p *vmPass) (string, string) {
		// A set is withdrawn by its verity root hash (which is no entry's
		// digest, so a manifest may list the set and revoke it at once: an
		// emergency withdrawal with no replacement), in either kind.
		for _, m := range []content.Manifest{p.in.Rootfs.Manifest, p.in.Guest.Manifest} {
			if content.IsRevoked(m, p.d.VerityRootHash) {
				return ReasonRevoked, "the image set " + p.d.Version + " is revoked " + RevokedBy(m, p.d.VerityRootHash) + " (its verity root hash)"
			}
		}
		return "", ""
	}},
	{"the pinned set", func(p *vmPass) (string, string) {
		if p.in.Want != "" && p.in.Want != p.d.Version {
			return ReasonImageSetPinned, "[terminal.sandbox.vm].image_set is " + p.in.Want + " but the verified set is " + p.d.Version
		}
		return "", ""
	}},
	{"architecture", func(p *vmPass) (string, string) {
		if p.d.Arch != p.in.Arch {
			return ReasonWrongArch, "the image set is for " + p.d.Arch + ", this host is " + p.in.Arch
		}
		return "", ""
	}},
	{"at or above the minimum", func(p *vmPass) (string, string) {
		v, _ := ParseVersion(p.d.Version)
		floor := p.in.Floor
		if floor == "" {
			floor = MinVMVersion
		}
		for _, m := range []string{floor, p.d.MinVersion} {
			mv, err := ParseVersion(m)
			if err != nil {
				return ReasonBelowMinimum, "the minimum version " + m + " cannot be read"
			}
			if v.Less(mv) {
				return ReasonBelowMinimum, fmt.Sprintf("image set %s is below the minimum %s", p.d.Version, m)
			}
		}
		return "", ""
	}},
	{"sbom covered", func(p *vmPass) (string, string) {
		if p.in.SBOMErr != nil {
			return artifactReason(p.in.SBOMErr), "the SBOM: " + p.in.SBOMErr.Error()
		}
		if err := CheckSBOM(p.in.SBOM); err != nil {
			return ReasonSBOM, err.Error()
		}
		return "", ""
	}},
	{"bulk entries re-hashed", func(p *vmPass) (string, string) {
		for _, name := range vmBulkEntries {
			err, ok := p.in.BulkErr[name]
			if !ok {
				return ReasonEntryMissing, name + " was not checked"
			}
			if err != nil {
				return artifactReason(err), name + ": " + err.Error()
			}
		}
		return "", ""
	}},
	{"guest binary", func(p *vmPass) (string, string) {
		if p.in.GuestErr != nil {
			return artifactReason(p.in.GuestErr), "the guest observer: " + p.in.GuestErr.Error()
		}
		e := p.in.GuestEntry
		if content.IsRevoked(p.in.Rootfs.Manifest, e.SHA256) {
			return ReasonRevoked, "the guest observer " + e.Version + " is revoked " + RevokedBy(p.in.Rootfs.Manifest, e.SHA256)
		}
		if e.Name != GuestBinaryName || e.OS != "linux" || e.Arch != p.in.Arch {
			return ReasonWrongArch, "the guest observer entry is not linux/" + p.in.Arch
		}
		if strings.TrimPrefix(p.in.AgentVersion, "v") != e.Version {
			return ReasonWrongGuestVersion, "the guest observer is " + e.Version + ", this agent is " + p.in.AgentVersion + "; import the guest binary of this release"
		}
		return "", ""
	}},
}

// ResolveVMSet decides whether the set may boot.
func ResolveVMSet(in VMSetInput) VMSetResult {
	p := &vmPass{in: in}
	for _, r := range vmSetRules {
		if reason, detail := r.check(p); reason != "" {
			return VMSetResult{Reason: reason, Detail: detail}
		}
	}
	p.out.OK = true
	p.out.Descriptor = p.d
	return p.out
}

// BulkEntries lists the rootfs manifest's bulk entry names in order.
func BulkEntries() []string { return append([]string(nil), vmBulkEntries...) }
