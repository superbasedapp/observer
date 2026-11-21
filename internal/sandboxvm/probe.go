package sandboxvm

import (
	"strconv"
	"strings"
)

// probe.go is the microVM probe ladder (sandbox plan v2 section 4.7): a
// pure ordered table over injected local facts, the first failing row wins.
// Nothing below the active row runs unless the driver is active and
// cloud-hypervisor is listed: no /dev/kvm open, no program stat, no content
// store read. No row boots a VM, dials a socket or fetches anything.

// The pins of the row (sandboxbackend: RequiredMin, TestedLow and
// TestedHigh 54): the version the ladder reports is the VMM's major.
const (
	RequiredMajor = 54
	TestedMajor   = 54
)

// KVMFacts are what a stat and a read-write open (closed at once) of
// /dev/kvm established.
type KVMFacts struct {
	// Exists: the path exists (a stat succeeded).
	Exists bool
	// CharDevice: it is a character device.
	CharDevice bool
	// OpenErr is the open's error text ("" when it opened).
	OpenErr string
	// PermissionDenied: the open failed with EACCES or EPERM (the user is
	// not in the device's group).
	PermissionDenied bool
}

// ProgramFacts are what a no-follow stat of a resolved program established.
type ProgramFacts struct {
	Regular bool
	// OwnerOK: owned by this user or by root.
	OwnerOK bool
	// Perm is the permission bits.
	Perm uint32
}

// ImageSetFacts is the verified guest image set the content store holds
// (internal/sandboximage decided it from what internal/contentchan loaded).
type ImageSetFacts struct {
	// Present: a sandbox.rootfs and a sandbox.guest_binary are installed.
	Present bool
	// Verdict is the trust check's answer (available or
	// artifact_unverified with the reason).
	Verdict Verdict
	// Version is the set's version; GuestUserns its descriptor's flag.
	Version     string
	GuestUserns bool
	// LastKnownGood names a previously verified set when the current one
	// is refused (an expired manifest), for the refusal's text.
	LastKnownGood string
}

// ProbeEnv is the injected I/O. A nil func the ladder reaches is a refusal.
type ProbeEnv struct {
	GOOS string
	// Active: the driver's component is selected, [terminal.sandbox] is on
	// and cloud-hypervisor is in its backends.
	Active bool
	// KVM stats and opens /dev/kvm.
	KVM func() KVMFacts
	// InVM reports whether this host is itself a virtual machine (WSL2, or
	// the hypervisor CPU flag), which makes a missing /dev/kvm a nested
	// virtualisation question.
	InVM func() bool
	// LookVMM and LookVirtiofsd resolve the programs (the configured path,
	// or PATH with Observer's own shims excluded).
	LookVMM       func() (string, error)
	LookVirtiofsd func() (string, error)
	StatProgram   func(path string) (ProgramFacts, error)
	// VMMVersion runs `cloud-hypervisor --version` (a bare version from a
	// local binary: inferred; the row's pins need no authenticated read).
	VMMVersion func(path string) (string, error)
	// ImageSet loads the verified guest image set.
	ImageSet func() ImageSetFacts
}

// ProbeResult is the ladder's answer and what it established.
type ProbeResult struct {
	Verdict   Verdict
	VMM       string
	Virtiofsd string
	// Version is the VMM's major version (the pin's unit); Full the whole
	// version it printed.
	Version string
	Full    string
	// Beta: the version is outside the tested range (usable).
	Beta     bool
	ImageSet ImageSetFacts
	Rule     string
}

type probeRow struct {
	id  string
	run func(env ProbeEnv, r *ProbeResult) Verdict
}

// probeRows is THE ladder, one test case per row.
var probeRows = []probeRow{
	{"V1 platform", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if env.GOOS != "linux" {
			return refuse(VerdictUnsupportedPlatform, "the Cloud Hypervisor microVM backend runs on Linux and WSL2 only")
		}
		return pass()
	}},
	{"V2 active", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if !env.Active {
			return refuse(VerdictDisabledByConfig, "the microVM driver is not active, or cloud-hypervisor is not in [terminal.sandbox].backends; nothing was probed")
		}
		return pass()
	}},
	{"V3 kvm", func(env ProbeEnv, _ *ProbeResult) Verdict {
		if env.KVM == nil {
			return refuse(VerdictNoHypervisor, "/dev/kvm could not be checked")
		}
		f := env.KVM()
		inVM := env.InVM != nil && env.InVM()
		switch {
		case !f.Exists && inVM:
			return refuse(VerdictNestedVirtUnavailable, "this host is itself a virtual machine and exposes no /dev/kvm: nested virtualisation is off (enable it in the hypervisor, or use the container or bubblewrap rows)")
		case !f.Exists:
			return refuse(VerdictNoHypervisor, "/dev/kvm is missing: hardware virtualisation is off in the firmware, or the kvm module is not loaded")
		case !f.CharDevice:
			return refuse(VerdictNoHypervisor, "/dev/kvm is not a character device")
		case f.PermissionDenied:
			return refuse(VerdictNoHypervisor, "/dev/kvm exists but this user cannot open it: add the user to the device's group (usually kvm) and log in again")
		case f.OpenErr != "":
			return refuse(VerdictNoHypervisor, "/dev/kvm could not be opened: "+f.OpenErr)
		}
		return pass()
	}},
	{"V4 cloud-hypervisor", func(env ProbeEnv, r *ProbeResult) Verdict {
		p, v := lookTrusted(env, env.LookVMM, "cloud-hypervisor", "install Cloud Hypervisor 54 (the static release binary) or set [terminal.sandbox.vm].cloud_hypervisor_path")
		r.VMM = p
		return v
	}},
	{"V5 version", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.VMMVersion == nil {
			return refuse(VerdictVersionUntested, "the cloud-hypervisor version could not be read")
		}
		raw, err := env.VMMVersion(r.VMM)
		full := ParseVMMVersion(raw)
		major := majorOf(full)
		if err != nil || major < 0 {
			return refuse(VerdictVersionUntested, "the cloud-hypervisor version could not be read")
		}
		r.Full, r.Version = full, strconv.Itoa(major)
		if major < RequiredMajor {
			return refuse(VerdictVersionUntested, "cloud-hypervisor "+full+" is below "+strconv.Itoa(RequiredMajor)+", the release this driver's API calls and the hybrid vsock protocol were built against")
		}
		r.Beta = major != TestedMajor
		return pass()
	}},
	{"V6 virtiofsd", func(env ProbeEnv, r *ProbeResult) Verdict {
		p, v := lookTrusted(env, env.LookVirtiofsd, "virtiofsd", "install virtiofsd (Ubuntu: the virtiofsd package, /usr/libexec/virtiofsd) or set [terminal.sandbox.vm].virtiofsd_path")
		r.Virtiofsd = p
		return v
	}},
	{"V7 image set", func(env ProbeEnv, r *ProbeResult) Verdict {
		if env.ImageSet == nil {
			return refuse(VerdictImageMissing, "the guest image set could not be read")
		}
		set := env.ImageSet()
		r.ImageSet = set
		if !set.Present {
			return refuse(VerdictImageMissing, "no guest image set is installed: import a signed set with Import image set in the microVM panel of Terminals > Settings > Sandbox isolation (same as `observer sandbox content import <dir>`; sandbox.rootfs and sandbox.guest_binary)")
		}
		if !set.Verdict.OK() {
			reason := set.Verdict.Reason
			if set.LastKnownGood != "" {
				reason += "; the last set that verified was " + set.LastKnownGood
			}
			return refuse(VerdictArtifactUnverified, reason)
		}
		return pass()
	}},
}

// lookTrusted resolves a program and checks its file: absolute, regular,
// owned by this user or root and writable by its owner only.
func lookTrusted(env ProbeEnv, look func() (string, error), name, hint string) (string, Verdict) {
	if look == nil || env.StatProgram == nil {
		return "", refuse(VerdictBackendMissing, name+" could not be looked up")
	}
	p, err := look()
	if err != nil || !strings.HasPrefix(p, "/") {
		return "", refuse(VerdictBackendMissing, name+" is not installed: "+hint)
	}
	f, err := env.StatProgram(p)
	if err != nil || !f.Regular || !f.OwnerOK || f.Perm&0o022 != 0 {
		return "", refuse(VerdictBackendUntrusted, p+" is not a regular file owned by you or root that only its owner can write; it is never run")
	}
	return p, pass()
}

// Probe walks the ladder.
func Probe(env ProbeEnv) ProbeResult {
	var r ProbeResult
	for _, row := range probeRows {
		v := row.run(env, &r)
		r.Rule = row.id
		if !v.OK() {
			r.Verdict = v
			return r
		}
	}
	r.Verdict = pass()
	return r
}

// ParseVMMVersion reads `cloud-hypervisor --version` ("cloud-hypervisor
// v54.0", "cloud-hypervisor v54.0-12-gabcdef"): the first field that is a
// dotted numeric version after an optional leading v, its git suffix cut.
// Empty when there is none.
func ParseVMMVersion(raw string) string {
	for _, f := range strings.Fields(raw) {
		f = strings.TrimPrefix(f, "v")
		if i := strings.IndexByte(f, '-'); i > 0 {
			f = f[:i]
		}
		parts := strings.Split(f, ".")
		if len(parts) < 1 || len(parts) > 3 {
			continue
		}
		ok := true
		for _, p := range parts {
			if _, err := strconv.Atoi(p); err != nil || p == "" {
				ok = false
			}
		}
		if ok && strings.Contains(f, ".") {
			return f
		}
	}
	return ""
}

// majorOf returns the major of a dotted version, -1 when unreadable.
func majorOf(v string) int {
	head, _, _ := strings.Cut(strings.TrimSpace(v), ".")
	n, err := strconv.Atoi(head)
	if err != nil || head == "" {
		return -1
	}
	return n
}
