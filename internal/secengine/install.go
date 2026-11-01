package secengine

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// install.go is the guided install's decision half (security pillar plan
// section 8.1, ruling (b) for an individual node and (c) for a managed one;
// lane SEC-G2 milestone 1): which pin an install fetches, from where, how
// large it is before anything is downloaded, whether the developer's
// one-time size consent covers it, and whether a downloaded file may be
// installed. It is pure like the rest of the package: the caller reads the
// manifests, the consent record and the downloaded file's digest.

// InstallSource is where an install's bytes come from.
type InstallSource string

// The InstallSource values (the allow.scanner_sources vocabulary).
const (
	// SourceVendorRelease is the vendor's own GitHub release (an
	// individual node, after the size consent).
	SourceVendorRelease InstallSource = "vendor_release"
	// SourceOrgMirror is the enrolled org server's mirror (a managed node
	// only; never the public release, case X19).
	SourceOrgMirror InstallSource = "org_mirror"
)

// MaxDownloadBytes caps any engine download whose pin states no exact size
// (the v1.30.1 linux amd64 asset is 46.6 MB).
const MaxDownloadBytes = 256 << 20

// The plan's blocked reasons, one per row of installRules.
const (
	BlockManagedNoMirror  = "managed_node_uses_org_mirror"
	BlockSourceNotAllowed = "scanner_source_not_allowed"
	BlockPinOwed          = "pin_owed"
	BlockRevoked          = "revoked"
)

// Where a plan's pin came from.
const (
	PinFromCompiled = "compiled"
	PinFromManifest = "manifest"
	// PinFromPending is a verified engine manifest from the public feed
	// that is not installed yet: it is installed together with the binary
	// its entry pins, after the consent.
	PinFromPending = "pending_manifest"
)

// InstallInput is one plan's facts.
type InstallInput struct {
	GOOS, GOARCH string
	Managed      bool
	// MirrorNamed: the managed pull in force names the org mirror.
	MirrorNamed bool
	// SourceAllowed reports whether the floors in force allow a source;
	// nil allows every source.
	SourceAllowed func(InstallSource) bool
	// Manifest is the accepted engine manifest; Pending a verified one from
	// the public feed not yet accepted (it supersedes Manifest for the
	// platforms it lists). Either may be nil.
	Manifest *ManifestPins
	Pending  *ManifestPins
	// InstalledDigest is the sha256 of the binary at the guided install's
	// path, "" when there is none.
	InstalledDigest string
	// Revoked are digests remembered as revoked whatever the manifests say.
	Revoked []string
}

// InstallPlan is PlanInstall's answer.
type InstallPlan struct {
	Source InstallSource
	Pin    Pin
	// PinFrom says where Pin came from (PinFromCompiled, PinFromManifest,
	// PinFromPending).
	PinFrom string
	// URL is the vendor download URL (a vendor release only).
	URL string
	// DownloadBytes is the download's size, about (exact when the pin
	// states it); CapBytes the most the download may be.
	DownloadBytes int64
	CapBytes      int64
	// TreeBytes and TreeFiles are what the bundle unpacks on its first
	// run (0 when not measured on this platform).
	TreeBytes int64
	TreeFiles int
	// NeedsConsent: an individual node's install waits for the developer's
	// one-time size consent for this pin.
	NeedsConsent bool
	// Installed: the install path already holds this pin's binary.
	Installed bool
	// Blocked is the first closed row's reason, "" when the install may
	// proceed.
	Blocked string
	// Decide is the manifest a downloaded file is decided against (the one
	// the pin came from, nil for a compiled pin).
	Decide *ManifestPins
}

// newestRow returns the manifest's newest pin for the platform.
func newestRow(m *ManifestPins, goos, goarch string) (Pin, bool) {
	if m == nil {
		return Pin{}, false
	}
	var best Pin
	ok := false
	for _, p := range m.Pins {
		if p.OS != goos || p.Arch != goarch {
			continue
		}
		if !ok || CompareVersions(p.Version, best.Version) > 0 {
			best, ok = p, true
		}
	}
	return best, ok
}

// pick chooses the pin: a pending manifest's row, else the accepted
// manifest's row, else a pinned compiled row.
func pick(in InstallInput) (Pin, string, *ManifestPins, bool) {
	if p, ok := newestRow(in.Pending, in.GOOS, in.GOARCH); ok {
		return p, PinFromPending, in.Pending, true
	}
	if p, ok := newestRow(in.Manifest, in.GOOS, in.GOARCH); ok {
		return p, PinFromManifest, in.Manifest, true
	}
	if c, ok := CompiledPin(in.GOOS, in.GOARCH); ok && c.Status == PinPinned {
		return c, PinFromCompiled, in.Manifest, true
	}
	return Pin{}, "", nil, false
}

// revokedIn reports whether digest is revoked by any of the lists.
func revokedIn(digest string, lists ...[]string) bool {
	for _, l := range lists {
		for _, r := range l {
			if strings.EqualFold(strings.TrimSpace(r), digest) {
				return true
			}
		}
	}
	return false
}

// installFacts are what installRules read.
type installFacts struct {
	in     InstallInput
	source InstallSource
	pin    Pin
	ok     bool
}

// installRules is the plan's ordered table (CLAUDE.md module rule 5): the
// first row whose test holds blocks the install with its reason.
var installRules = []struct {
	reason string
	when   func(installFacts) bool
}{
	{BlockManagedNoMirror, func(f installFacts) bool { return f.in.Managed && !f.in.MirrorNamed }},
	{BlockSourceNotAllowed, func(f installFacts) bool { return f.in.SourceAllowed != nil && !f.in.SourceAllowed(f.source) }},
	{BlockPinOwed, func(f installFacts) bool { return !f.ok }},
	{BlockRevoked, func(f installFacts) bool {
		var lists [][]string
		for _, m := range []*ManifestPins{f.in.Manifest, f.in.Pending} {
			if m != nil {
				lists = append(lists, m.Revoked)
			}
		}
		return revokedIn(f.pin.SHA256, append(lists, f.in.Revoked)...)
	}},
}

// PlanInstall decides what a guided install would do.
func PlanInstall(in InstallInput) InstallPlan {
	f := installFacts{in: in, source: SourceVendorRelease}
	if in.Managed {
		f.source = SourceOrgMirror
		// A managed node's pin comes from the mirror's manifest only; the
		// public feed never reaches it.
		in.Pending = nil
		f.in.Pending = nil
	}
	pin, from, decideOn, ok := pick(in)
	f.pin, f.ok = pin, ok
	p := InstallPlan{Source: f.source, Pin: pin, PinFrom: from, Decide: decideOn}
	for _, r := range installRules {
		if r.when(f) {
			p.Blocked = r.reason
			return p
		}
	}
	if f.source == SourceVendorRelease {
		p.URL = pin.URL()
	}
	p.DownloadBytes, p.CapBytes = sizesOf(pin)
	p.TreeBytes, p.TreeFiles = pin.TreeBytes, pin.TreeFiles
	if p.TreeBytes == 0 {
		// A manifest row of the measured platform and version unpacks the
		// same tree the compiled row recorded.
		if c, ok := CompiledPin(pin.OS, pin.Arch); ok && c.Version == pin.Version {
			p.TreeBytes, p.TreeFiles = c.TreeBytes, c.TreeFiles
		}
	}
	p.Installed = in.InstalledDigest != "" && strings.EqualFold(in.InstalledDigest, pin.SHA256)
	p.NeedsConsent = !in.Managed && !p.Installed
	return p
}

// sizesOf returns the stated download size and the cap.
func sizesOf(p Pin) (about, limit int64) {
	switch {
	case p.SizeBytes > 0:
		return p.SizeBytes, p.SizeBytes
	case p.ApproxBytes > 0:
		return p.ApproxBytes, min(p.ApproxBytes+p.ApproxBytes/4, MaxDownloadBytes)
	}
	return 0, MaxDownloadBytes
}

// ErrInstallRefused wraps every refusal of a downloaded file.
var ErrInstallRefused = fmt.Errorf("secengine: the downloaded engine is refused")

// VerifyDownload decides whether a downloaded file may be installed: its
// size within the plan's cap, its sha256 the pin's, and then the decision
// table on that digest (a revoked digest, a platform with no pin, anything
// but a verified engine is refused). An install Observer performs never
// installs an engine it would only run labelled.
func VerifyDownload(p InstallPlan, digest string, size int64, goos, goarch string, managed bool) (Decision, error) {
	if p.Blocked != "" {
		return Decision{}, fmt.Errorf("%w: the install is blocked (%s)", ErrInstallRefused, p.Blocked)
	}
	if size <= 0 || size > p.CapBytes {
		return Decision{}, fmt.Errorf("%w: %d bytes is not within the pin's %d", ErrInstallRefused, size, p.CapBytes)
	}
	if p.Pin.SizeBytes > 0 && size != p.Pin.SizeBytes {
		return Decision{}, fmt.Errorf("%w: %d bytes is not the pinned %d", ErrInstallRefused, size, p.Pin.SizeBytes)
	}
	if !strings.EqualFold(strings.TrimSpace(digest), p.Pin.SHA256) {
		return Decision{}, fmt.Errorf("%w: sha256 %s is not the pinned %s", ErrInstallRefused, digest, p.Pin.SHA256)
	}
	d := Decide(Input{GOOS: goos, GOARCH: goarch, Digest: digest, Managed: managed, Manifest: p.Decide, Tree: TreeNone})
	if d.Status != StatusVerified {
		return d, fmt.Errorf("%w: the decision table says %s (%s)", ErrInstallRefused, d.Status, d.Detail)
	}
	return d, nil
}

// InstallConsentVersion is bumped when the consent text changes materially;
// an older record reads not given.
const InstallConsentVersion = 1

// InstallConsentSurfaces are where the consent may be given: each is an
// explicit action by the developer (the dashboard dialog, the CLI's
// question or its --yes flag). An agent never gives it (guard rule R-165).
var InstallConsentSurfaces = map[string]bool{"dashboard": true, "cli": true}

// InstallConsent is the node's record of the developer's one-time size
// consent for one pin: a pin change (another digest) asks again.
type InstallConsent struct {
	Version   int    `json:"version"`
	PinSHA256 string `json:"pin_sha256"`
	// PinVersion and the two sizes are what the developer was shown.
	PinVersion    string    `json:"pin_version"`
	DownloadBytes int64     `json:"download_bytes"`
	TreeBytes     int64     `json:"tree_bytes"`
	AcceptedAt    time.Time `json:"accepted_at"`
	Surface       string    `json:"surface"`
	By            string    `json:"by,omitempty"`
	// MAC is the record's MAC under the node's posture key, over Canonical.
	MAC string `json:"mac,omitempty"`
	// Verified is set by the caller after the MAC verified; never read
	// from the file.
	Verified bool `json:"-"`
}

// Canonical is the MAC input: every field but the MAC, fixed order and
// spelling.
func (c InstallConsent) Canonical() []byte {
	var b bytes.Buffer
	for _, f := range []string{
		strconv.Itoa(c.Version), strings.ToLower(c.PinSHA256), strconv.Quote(c.PinVersion),
		strconv.FormatInt(c.DownloadBytes, 10), strconv.FormatInt(c.TreeBytes, 10),
		c.AcceptedAt.UTC().Format(time.RFC3339Nano), strconv.Quote(c.Surface), strconv.Quote(c.By),
	} {
		b.WriteString(f)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// Covers reports whether c is a verified consent for the plan's pin.
func (c InstallConsent) Covers(p InstallPlan) bool {
	return c.Verified && c.Version >= InstallConsentVersion && !c.AcceptedAt.IsZero() &&
		InstallConsentSurfaces[c.Surface] && p.Pin.SHA256 != "" && strings.EqualFold(c.PinSHA256, p.Pin.SHA256)
}

// NewInstallConsent is the record of a consent to p given on surface.
func NewInstallConsent(p InstallPlan, surface, by string, at time.Time) (InstallConsent, error) {
	if !InstallConsentSurfaces[surface] || at.IsZero() || p.Pin.SHA256 == "" || p.Blocked != "" {
		return InstallConsent{}, fmt.Errorf("secengine.NewInstallConsent: a consenting surface, a time and an unblocked plan are required")
	}
	if len(by) > 128 {
		by = by[:128]
	}
	return InstallConsent{
		Version: InstallConsentVersion, PinSHA256: strings.ToLower(p.Pin.SHA256), PinVersion: p.Pin.Version,
		DownloadBytes: p.DownloadBytes, TreeBytes: p.TreeBytes, AcceptedAt: at.UTC(), Surface: surface, By: by,
	}, nil
}

// MB renders a byte count in megabytes, about ("unknown" for 0).
func MB(n int64) string {
	switch {
	case n <= 0:
		return "an unknown amount"
	case n < 1_000_000:
		return "less than 1 MB"
	}
	return fmt.Sprintf("about %d MB", (n+500_000)/1_000_000)
}

// ConsentText is what the developer accepts, on both surfaces.
func ConsentText(p InstallPlan) string {
	tree := "an unpacked tree of " + MB(p.TreeBytes)
	if p.TreeFiles > 0 {
		tree += fmt.Sprintf(" (%d files)", p.TreeFiles)
	}
	return fmt.Sprintf("Observer can install Opengrep %s (LGPL-2.1, a separate program, never bundled) for its code rules. "+
		"It downloads %s from the vendor's GitHub release (%s), checks its sha256 against the pin %s and installs it in "+
		"Observer's own scanner directory. On its first run Opengrep unpacks %s into its own cache there. "+
		"The download sends nothing about your projects: GitHub sees your IP address and the time. "+
		"Nothing is downloaded until you accept, and a new pin asks again.",
		p.Pin.Version, MB(p.DownloadBytes), p.URL, p.Pin.SHA256, tree)
}
