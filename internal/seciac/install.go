package seciac

import (
	"bytes"
	"fmt"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secengine"
)

// install.go is the guided install's decision half, per engine (lane
// GATES-SEC decision 3, the secengine install shape): which pin, from
// where, how large before anything is downloaded, whether the developer's
// one-time size consent covers it, and whether a downloaded archive and
// the binary extracted from it may be installed. Pure: the caller reads the
// manifests, the consent and the files.

// InstallSource is where an install's bytes come from (the
// allow.scanner_sources vocabulary).
type InstallSource = secengine.InstallSource

// The InstallSource values.
const (
	SourceVendorRelease = secengine.SourceVendorRelease
	SourceOrgMirror     = secengine.SourceOrgMirror
)

// MaxDownloadBytes caps any archive whose pin states no exact size.
const MaxDownloadBytes = 256 << 20

// MaxBinaryBytes caps the executable extracted from an archive.
const MaxBinaryBytes = 512 << 20

// The blocked reasons, one per row of installRules.
const (
	BlockNoVendorRelease  = "no_vendor_release"
	BlockManagedNoMirror  = secengine.BlockManagedNoMirror
	BlockSourceNotAllowed = secengine.BlockSourceNotAllowed
	BlockPinOwed          = secengine.BlockPinOwed
	BlockRevoked          = secengine.BlockRevoked
)

// InstallInput is one plan's facts.
type InstallInput struct {
	Engine       EngineID
	GOOS, GOARCH string
	Managed      bool
	// MirrorNamed: the managed pull in force names the org mirror.
	MirrorNamed bool
	// SourceAllowed reports whether the floors allow a source; nil allows
	// every source.
	SourceAllowed func(InstallSource) bool
	// Manifest is the accepted engine manifest (nil when none).
	Manifest *ManifestPins
	// Compiled overrides the compiled pin table (tests); nil reads it.
	Compiled []Pin
	// InstalledArchive is the archive digest of the last guided install
	// whose binary is still at the install path ("" when none).
	InstalledArchive string
	// Revoked are digests remembered as revoked.
	Revoked []string
}

// InstallPlan is PlanInstall's answer.
type InstallPlan struct {
	Engine  EngineID
	Source  InstallSource
	Pin     Pin
	URL     string
	Bundle  string
	PinFrom string
	// DownloadBytes is the archive's size, about (exact when the pin
	// states it); CapBytes the most it may be.
	DownloadBytes int64
	CapBytes      int64
	NeedsConsent  bool
	Installed     bool
	Blocked       string
}

func newestRow(m *ManifestPins, goos, goarch string) (Pin, bool) {
	if m == nil {
		return Pin{}, false
	}
	var best Pin
	ok := false
	for _, p := range m.Pins {
		if p.OS == goos && p.Arch == goarch && (!ok || secengine.CompareVersions(p.Version, best.Version) > 0) {
			best, ok = p, true
		}
	}
	return best, ok
}

type installFacts struct {
	in     InstallInput
	engine Engine
	source InstallSource
	pin    Pin
	from   string
	ok     bool
}

// installRules is the plan's ordered table: the first row whose test holds
// blocks the install with its reason.
var installRules = []struct {
	reason string
	when   func(installFacts) bool
}{
	{BlockNoVendorRelease, func(f installFacts) bool { return !f.in.Managed && !f.engine.GuidedInstall() }},
	{BlockManagedNoMirror, func(f installFacts) bool { return f.in.Managed && !f.in.MirrorNamed }},
	{BlockSourceNotAllowed, func(f installFacts) bool { return f.in.SourceAllowed != nil && !f.in.SourceAllowed(f.source) }},
	{BlockPinOwed, func(f installFacts) bool { return !f.ok || f.pin.AssetSHA256 == "" }},
	{BlockRevoked, func(f installFacts) bool {
		revoked := append([]string(nil), f.in.Revoked...)
		if f.in.Manifest != nil {
			revoked = append(revoked, f.in.Manifest.Revoked...)
		}
		for _, r := range revoked {
			if lower(r) == f.pin.AssetSHA256 || (f.pin.BinarySHA256 != "" && lower(r) == lower(f.pin.BinarySHA256)) {
				return true
			}
		}
		return false
	}},
}

// PlanInstall decides what a guided install would do.
func PlanInstall(in InstallInput) InstallPlan {
	e, _ := Lookup(in.Engine)
	f := installFacts{in: in, engine: e, source: SourceVendorRelease}
	if in.Managed {
		f.source = SourceOrgMirror
	}
	if p, ok := newestRow(in.Manifest, in.GOOS, in.GOARCH); ok {
		f.pin, f.from, f.ok = p, "manifest", true
	} else {
		pins := in.Compiled
		if pins == nil {
			pins = CompiledPins(in.Engine)
		}
		if c, ok := pinFor(pins, in.GOOS, in.GOARCH); ok && c.Status == PinPinned && !in.Managed {
			// A managed node's pin comes from the mirror's manifest only.
			f.pin, f.from, f.ok = c, "compiled", true
		}
	}
	f.pin.AssetSHA256 = lower(f.pin.AssetSHA256)
	p := InstallPlan{Engine: in.Engine, Source: f.source, Pin: f.pin, PinFrom: f.from}
	for _, r := range installRules {
		if r.when(f) {
			p.Blocked = r.reason
			return p
		}
	}
	if f.source == SourceVendorRelease {
		p.URL, p.Bundle = f.pin.URL(), f.pin.BundleURL()
	}
	switch {
	case f.pin.SizeBytes > 0:
		p.DownloadBytes, p.CapBytes = f.pin.SizeBytes, f.pin.SizeBytes
	case f.pin.ApproxBytes > 0:
		p.DownloadBytes, p.CapBytes = f.pin.ApproxBytes, min(f.pin.ApproxBytes+f.pin.ApproxBytes/2, MaxDownloadBytes)
	default:
		p.CapBytes = MaxDownloadBytes
	}
	p.Installed = in.InstalledArchive != "" && lower(in.InstalledArchive) == f.pin.AssetSHA256
	p.NeedsConsent = !in.Managed && !p.Installed
	return p
}

// ErrInstallRefused wraps every refusal of a downloaded file.
var ErrInstallRefused = fmt.Errorf("seciac: the downloaded engine is refused")

// VerifyArchive decides whether a downloaded archive may be unpacked: the
// plan unblocked, its size within the cap (exactly the pin's when stated)
// and its sha256 the pin's. The signature pre-check comes next
// (PrecheckBundle), then the extraction.
func VerifyArchive(p InstallPlan, digest string, size int64) error {
	switch {
	case p.Blocked != "":
		return fmt.Errorf("%w: the install is blocked (%s)", ErrInstallRefused, p.Blocked)
	case size <= 0 || size > p.CapBytes:
		return fmt.Errorf("%w: %d bytes is not within the pin's %d", ErrInstallRefused, size, p.CapBytes)
	case p.Pin.SizeBytes > 0 && size != p.Pin.SizeBytes:
		return fmt.Errorf("%w: %d bytes is not the pinned %d", ErrInstallRefused, size, p.Pin.SizeBytes)
	case lower(digest) != p.Pin.AssetSHA256:
		return fmt.Errorf("%w: sha256 %s is not the pinned %s", ErrInstallRefused, digest, p.Pin.AssetSHA256)
	}
	return nil
}

// VerifyBinary decides whether the executable extracted from a verified
// archive may be placed: within its cap, and, when the pin states the
// binary's digest, that digest.
func VerifyBinary(p InstallPlan, digest string, size int64) error {
	switch {
	case size <= 0 || size > MaxBinaryBytes:
		return fmt.Errorf("%w: the extracted %s is %d bytes", ErrInstallRefused, p.Pin.Member, size)
	case p.Pin.BinarySHA256 != "" && lower(digest) != lower(p.Pin.BinarySHA256):
		return fmt.Errorf("%w: the extracted %s is %s, not the pinned %s", ErrInstallRefused, p.Pin.Member, digest, p.Pin.BinarySHA256)
	}
	return nil
}

// InstallConsentVersion is bumped when the consent text changes.
const InstallConsentVersion = 1

// InstallConsentSurfaces are where the consent may be given: explicit
// actions of the developer. An agent never gives it (guard rule R-165).
var InstallConsentSurfaces = map[string]bool{"dashboard": true, "cli": true}

// InstallConsent is the node's record of the developer's one-time size
// consent for one engine's pin.
type InstallConsent struct {
	Version       int       `json:"version"`
	Engine        EngineID  `json:"engine"`
	PinSHA256     string    `json:"pin_sha256"`
	PinVersion    string    `json:"pin_version"`
	DownloadBytes int64     `json:"download_bytes"`
	AcceptedAt    time.Time `json:"accepted_at"`
	Surface       string    `json:"surface"`
	By            string    `json:"by,omitempty"`
	MAC           string    `json:"mac,omitempty"`
	// Verified is set by the caller after the MAC verified.
	Verified bool `json:"-"`
}

// Canonical is the MAC input: every field but the MAC, fixed order.
func (c InstallConsent) Canonical() []byte {
	var b bytes.Buffer
	for _, f := range []string{
		strconv.Itoa(c.Version), strconv.Quote(string(c.Engine)), lower(c.PinSHA256), strconv.Quote(c.PinVersion),
		strconv.FormatInt(c.DownloadBytes, 10), c.AcceptedAt.UTC().Format(time.RFC3339Nano), strconv.Quote(c.Surface), strconv.Quote(c.By),
	} {
		b.WriteString(f)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// Covers reports whether c is a verified consent for the plan's pin.
func (c InstallConsent) Covers(p InstallPlan) bool {
	return c.Verified && c.Version >= InstallConsentVersion && !c.AcceptedAt.IsZero() && c.Engine == p.Engine &&
		InstallConsentSurfaces[c.Surface] && p.Pin.AssetSHA256 != "" && lower(c.PinSHA256) == p.Pin.AssetSHA256
}

// NewInstallConsent is the record of a consent to p given on surface.
func NewInstallConsent(p InstallPlan, surface, by string, at time.Time) (InstallConsent, error) {
	if !InstallConsentSurfaces[surface] || at.IsZero() || p.Pin.AssetSHA256 == "" || p.Blocked != "" {
		return InstallConsent{}, fmt.Errorf("seciac.NewInstallConsent: a consenting surface, a time and an unblocked plan are required")
	}
	if len(by) > 128 {
		by = by[:128]
	}
	return InstallConsent{
		Version: InstallConsentVersion, Engine: p.Engine, PinSHA256: p.Pin.AssetSHA256, PinVersion: p.Pin.Version,
		DownloadBytes: p.DownloadBytes, AcceptedAt: at.UTC(), Surface: surface, By: by,
	}, nil
}

// ConsentText is what the developer accepts, on both surfaces.
func ConsentText(p InstallPlan) string {
	e, _ := Lookup(p.Engine)
	sig := "and pre-checks its sigstore signature against the pinned identity " + e.Identity(p.Pin.Version)
	if e.Signature == SigNone {
		sig = "(the vendor publishes no signature, so the pin rests on its digest alone)"
	}
	return fmt.Sprintf("Observer can install %s %s (%s) for its infrastructure-as-code checks. "+
		"It downloads %s from the vendor's GitHub release (%s), checks its sha256 against the pin %s %s, "+
		"and installs the %s program from it in Observer's own scanner directory. "+
		"The download sends nothing about your projects: GitHub sees your IP address and the time. "+
		"Nothing is downloaded until you accept, and a new pin asks again.",
		e.Title, p.Pin.Version, e.Licence, secengine.MB(p.DownloadBytes), p.URL, p.Pin.AssetSHA256, sig, p.Pin.Member)
}

// BlockedWords is the plain sentence of a blocked reason.
func BlockedWords(e EngineID, reason, goos, goarch string) string {
	eng, _ := Lookup(e)
	switch reason {
	case BlockNoVendorRelease:
		return eng.Title + " " + eng.TestedVersion + " publishes no release binaries, so there is nothing to install from the vendor; install it yourself, it then runs labelled unverified on an individual node (" + reason + ")"
	case BlockManagedNoMirror:
		return "this is a managed node: its engine comes only from the org mirror, and the managed pull in force does not name it (" + reason + ")"
	case BlockSourceNotAllowed:
		return "the org's floors do not allow this source for scanners (" + reason + ")"
	case BlockPinOwed:
		return "no verified pin exists for " + goos + "/" + goarch + " yet (" + reason + "); install " + eng.Title + " yourself, it then runs labelled unverified on an individual node"
	case BlockRevoked:
		return "the pinned engine was revoked (" + reason + ")"
	}
	return reason
}
