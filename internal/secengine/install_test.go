package secengine

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const pinned = "d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4"

func TestPlanInstallRows(t *testing.T) {
	other := strings.Repeat("b", 64)
	newer := &ManifestPins{Version: 3, Pins: []Pin{
		{Version: "1.31.0", OS: "linux", Arch: "amd64", Asset: "opengrep_manylinux_x86", SHA256: other, Status: PinPinned, Source: "manifest", SizeBytes: 48_000_000},
	}}
	mac := &ManifestPins{Version: 2, Pins: []Pin{
		{Version: "1.30.1", OS: "darwin", Arch: "arm64", Asset: "opengrep_osx_arm64", SHA256: other, Status: PinPinned, Source: "manifest", SizeBytes: 50_000_000},
	}}
	cases := []struct {
		name    string
		in      InstallInput
		blocked string
		from    string
		consent bool
		source  InstallSource
	}{
		{"individual, compiled pin", InstallInput{GOOS: "linux", GOARCH: "amd64"}, "", PinFromCompiled, true, SourceVendorRelease},
		{"other platforms are pin owed", InstallInput{GOOS: "windows", GOARCH: "amd64"}, BlockPinOwed, "", false, SourceVendorRelease},
		{"macOS arm64 owed", InstallInput{GOOS: "darwin", GOARCH: "arm64"}, BlockPinOwed, "", false, SourceVendorRelease},
		{"a manifest fills an owed platform", InstallInput{GOOS: "darwin", GOARCH: "arm64", Manifest: mac}, "", PinFromManifest, true, SourceVendorRelease},
		{"a pending feed manifest wins", InstallInput{GOOS: "linux", GOARCH: "amd64", Pending: newer}, "", PinFromPending, true, SourceVendorRelease},
		{"managed without the mirror", InstallInput{GOOS: "linux", GOARCH: "amd64", Managed: true}, BlockManagedNoMirror, "", false, SourceOrgMirror},
		{"managed with the mirror: no consent, never the feed", InstallInput{GOOS: "linux", GOARCH: "amd64", Managed: true, MirrorNamed: true, Pending: newer}, "", PinFromCompiled, false, SourceOrgMirror},
		{"a floor forbids the vendor release", InstallInput{GOOS: "linux", GOARCH: "amd64", SourceAllowed: func(s InstallSource) bool { return s == SourceOrgMirror }}, BlockSourceNotAllowed, "", false, SourceVendorRelease},
		{"a remembered revocation", InstallInput{GOOS: "linux", GOARCH: "amd64", Revoked: []string{strings.ToUpper(pinned)}}, BlockRevoked, "", false, SourceVendorRelease},
		{"already installed needs no consent", InstallInput{GOOS: "linux", GOARCH: "amd64", InstalledDigest: pinned}, "", PinFromCompiled, false, SourceVendorRelease},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := PlanInstall(c.in)
			if p.Blocked != c.blocked || p.NeedsConsent != c.consent || p.Source != c.source {
				t.Fatalf("plan %+v", p)
			}
			if c.blocked == "" && p.PinFrom != c.from {
				t.Fatalf("pin from %q, want %q", p.PinFrom, c.from)
			}
		})
	}
}

func TestPlanInstallStatesSizesBeforeConsent(t *testing.T) {
	p := PlanInstall(InstallInput{GOOS: "linux", GOARCH: "amd64"})
	if p.DownloadBytes != 46_600_000 || p.TreeBytes != 246_000_000 || p.TreeFiles != 102 || p.CapBytes < p.DownloadBytes || p.CapBytes > MaxDownloadBytes {
		t.Fatalf("sizes %+v", p)
	}
	if p.URL != "https://github.com/opengrep/opengrep/releases/download/v1.30.1/opengrep_manylinux_x86" {
		t.Fatalf("url %s", p.URL)
	}
	text := ConsentText(p)
	for _, want := range []string{"about 47 MB", "about 246 MB", "102 files", pinned, "github.com"} {
		if !strings.Contains(text, want) {
			t.Errorf("consent text lacks %q: %s", want, text)
		}
	}
	// A manifest row of the measured version keeps the measured tree size.
	m := &ManifestPins{Pins: []Pin{{Version: TestedVersion, OS: "linux", Arch: "amd64", SHA256: pinned, Status: PinPinned, SizeBytes: 46_612_345}}}
	p = PlanInstall(InstallInput{GOOS: "linux", GOARCH: "amd64", Manifest: m})
	if p.DownloadBytes != 46_612_345 || p.CapBytes != 46_612_345 || p.TreeBytes != 246_000_000 {
		t.Fatalf("manifest sizes %+v", p)
	}
}

func TestInstallConsentCoversOnlyItsPin(t *testing.T) {
	p := PlanInstall(InstallInput{GOOS: "linux", GOARCH: "amd64"})
	c, err := NewInstallConsent(p, "cli", "dev", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if c.Covers(p) {
		t.Fatal("an unverified record covers")
	}
	c.Verified = true
	if !c.Covers(p) {
		t.Fatal("a verified record does not cover its pin")
	}
	changed := PlanInstall(InstallInput{GOOS: "linux", GOARCH: "amd64", Pending: &ManifestPins{Pins: []Pin{{Version: "1.31.0", OS: "linux", Arch: "amd64", SHA256: strings.Repeat("c", 64), Status: PinPinned}}}})
	if c.Covers(changed) {
		t.Fatal("a consent covers a changed pin: the developer must be asked again")
	}
	for _, s := range []string{"agent", "hook", ""} {
		if _, err := NewInstallConsent(p, s, "", time.Now()); err == nil {
			t.Errorf("surface %q recorded a consent", s)
		}
	}
	a, b := c, c
	b.By = "someone else"
	if string(a.Canonical()) == string(b.Canonical()) {
		t.Error("the canonical form does not bind the account")
	}
}

func TestVerifyDownloadOrder(t *testing.T) {
	p := PlanInstall(InstallInput{GOOS: "linux", GOARCH: "amd64"})
	if _, err := VerifyDownload(p, pinned, 46_600_000, "linux", "amd64", false); err != nil {
		t.Fatalf("the pinned digest: %v", err)
	}
	for name, c := range map[string]struct {
		digest string
		size   int64
	}{
		"wrong digest":  {strings.Repeat("e", 64), 46_600_000},
		"over the cap":  {pinned, p.CapBytes + 1},
		"empty":         {pinned, 0},
		"tampered byte": {tamperedDigest, 46_600_001},
	} {
		if _, err := VerifyDownload(p, c.digest, c.size, "linux", "amd64", false); !errors.Is(err, ErrInstallRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A pin a manifest revokes is refused by the decision table even when
	// the plan was built before the revocation reached it.
	p.Decide = &ManifestPins{Revoked: []string{pinned}}
	if _, err := VerifyDownload(p, pinned, 46_600_000, "linux", "amd64", false); !errors.Is(err, ErrInstallRefused) {
		t.Errorf("revoked: %v", err)
	}
	// An exact size is exact.
	m := &ManifestPins{Pins: []Pin{{Version: TestedVersion, OS: "linux", Arch: "amd64", SHA256: pinned, Status: PinPinned, SizeBytes: 100}}}
	q := PlanInstall(InstallInput{GOOS: "linux", GOARCH: "amd64", Manifest: m})
	if _, err := VerifyDownload(q, pinned, 99, "linux", "amd64", false); err == nil {
		t.Error("a short file of an exact pin passed")
	}
	blocked := PlanInstall(InstallInput{GOOS: "windows", GOARCH: "amd64"})
	if _, err := VerifyDownload(blocked, pinned, 10, "windows", "amd64", false); err == nil {
		t.Error("a blocked plan installed")
	}
}
