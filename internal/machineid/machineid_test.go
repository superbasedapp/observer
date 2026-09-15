package machineid

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withSeams swaps the injectable I/O seams for the duration of fn and restores
// them after, so a test can drive any platform branch deterministically.
//
// It ALSO makes the persisted-seed rung inert (homeDir errors), for two
// reasons: these tests assert the OS-source and hostname rungs in isolation,
// and a test that left the write seams at their defaults would mint a real
// ~/.observer/machine-id on the developer's machine. Persistence is exercised
// by withSeedDir below.
func withSeams(t *testing.T, os_ string, rf func(string) ([]byte, error), hn func() (string, error), rt func(string, ...string) ([]byte, error), fn func()) {
	t.Helper()
	origGOOS, origRF, origHN, origRT := goos, readFile, hostname, runTool
	goos, readFile, hostname, runTool = os_, rf, hn, rt
	defer func() { goos, readFile, hostname, runTool = origGOOS, origRF, origHN, origRT }()
	withNoSeedDir(t, fn)
}

// withNoSeedDir pins homeDir to an error for the duration of fn, disabling the
// persisted-seed rung.
func withNoSeedDir(t *testing.T, fn func()) {
	t.Helper()
	orig := homeDir
	homeDir = func() (string, error) { return "", errors.New("no home") }
	defer func() { homeDir = orig }()
	fn()
}

// withSeedDir points the persisted-seed rung at a real temp dir and restores
// the true filesystem seams (the withSeams family stubs readFile, which the
// seed rung also uses), so the rung's read-or-mint behaviour is exercised
// against actual files. The OS-native sources stay absent so the ladder
// reaches rung 2.
func withSeedDir(t *testing.T, dir string, fn func()) {
	t.Helper()
	origGOOS, origRF, origHN, origRT := goos, readFile, hostname, runTool
	origHome := homeDir
	goos = "linux"
	readFile = func(p string) ([]byte, error) {
		if p == "/etc/machine-id" || p == "/var/lib/dbus/machine-id" {
			return nil, os.ErrNotExist
		}
		return os.ReadFile(p)
	}
	hostname = func() (string, error) { return "SandboxHost-000000000000", nil }
	runTool = func(string, ...string) ([]byte, error) { return nil, errors.New("no tool") }
	homeDir = func() (string, error) { return dir, nil }
	defer func() {
		goos, readFile, hostname, runTool, homeDir = origGOOS, origRF, origHN, origRT, origHome
	}()
	fn()
}

func fixedFile(m map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		if v, ok := m[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
}

func TestForOrgStableAndOrgSalted(t *testing.T) {
	files := fixedFile(map[string]string{"/etc/machine-id": "abc123\n"})
	hn := func() (string, error) { return "host", nil }
	rt := func(string, ...string) ([]byte, error) { return nil, errors.New("unused") }

	var a1, a2, b string
	withSeams(t, "linux", files, hn, rt, func() {
		var err error
		if a1, err = ForOrg("org-A"); err != nil {
			t.Fatalf("ForOrg org-A: %v", err)
		}
		if a2, err = ForOrg("org-A"); err != nil {
			t.Fatalf("ForOrg org-A again: %v", err)
		}
		if b, err = ForOrg("org-B"); err != nil {
			t.Fatalf("ForOrg org-B: %v", err)
		}
	})

	if a1 == "" {
		t.Fatal("expected a non-empty identity")
	}
	if a1 != a2 {
		t.Errorf("identity not stable across calls: %q != %q", a1, a2)
	}
	if a1 == b {
		t.Error("identity must differ across orgs for the same machine")
	}
	if len(a1) != 64 {
		t.Errorf("expected a 64-char hex SHA-256, got %d chars", len(a1))
	}
}

func TestForOrgDistinctPerRawSource(t *testing.T) {
	hn := func() (string, error) { return "host", nil }
	rt := func(string, ...string) ([]byte, error) { return nil, errors.New("unused") }

	var m1, m2 string
	withSeams(t, "linux", fixedFile(map[string]string{"/etc/machine-id": "machine-one"}), hn, rt, func() {
		m1, _ = ForOrg("org")
	})
	withSeams(t, "linux", fixedFile(map[string]string{"/etc/machine-id": "machine-two"}), hn, rt, func() {
		m2, _ = ForOrg("org")
	})
	if m1 == "" || m2 == "" {
		t.Fatal("expected non-empty identities")
	}
	if m1 == m2 {
		t.Error("different machines must produce different identities")
	}
}

func TestForOrgLinuxFileOrderPrefersMachineID(t *testing.T) {
	hn := func() (string, error) { return "host", nil }
	rt := func(string, ...string) ([]byte, error) { return nil, errors.New("unused") }
	files := fixedFile(map[string]string{
		"/etc/machine-id":          "primary",
		"/var/lib/dbus/machine-id": "secondary",
	})
	var pref, dbusOnly string
	withSeams(t, "linux", files, hn, rt, func() { pref, _ = ForOrg("org") })
	withSeams(t, "linux", fixedFile(map[string]string{"/var/lib/dbus/machine-id": "secondary"}), hn, rt, func() {
		dbusOnly, _ = ForOrg("org")
	})
	// The identity built from /etc/machine-id="primary" must differ from the
	// one built from the dbus fallback="secondary", proving /etc wins when both
	// are present.
	if pref == dbusOnly {
		t.Error("expected /etc/machine-id to be preferred over the dbus fallback")
	}
}

func TestForOrgHostnameFallback(t *testing.T) {
	// No files readable; hostname is the only source.
	noFiles := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	hn := func() (string, error) { return "the-host\n", nil }
	rt := func(string, ...string) ([]byte, error) { return nil, errors.New("no tool") }

	var got string
	withSeams(t, "linux", noFiles, hn, rt, func() { got, _ = ForOrg("org") })
	if got == "" {
		t.Fatal("expected the hostname fallback to yield an identity")
	}
	// Confirm it is actually the hostname source (matches a direct hash).
	want := hashIdentity("org", "the-host")
	if got != want {
		t.Errorf("hostname fallback = %q, want %q", got, want)
	}
}

func TestForOrgEmptyWhenNoSource(t *testing.T) {
	noFiles := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	noHost := func() (string, error) { return "", errors.New("no hostname") }
	rt := func(string, ...string) ([]byte, error) { return nil, errors.New("no tool") }

	var got string
	var err error
	withSeams(t, "linux", noFiles, noHost, rt, func() { got, err = ForOrg("org") })
	if err != nil {
		t.Errorf("a merely-absent source must not be an error, got %v", err)
	}
	if got != "" {
		t.Errorf("expected empty identity when no source is available, got %q", got)
	}
}

func TestForOrgEmptyOrgIsUnbindable(t *testing.T) {
	files := fixedFile(map[string]string{"/etc/machine-id": "abc"})
	hn := func() (string, error) { return "host", nil }
	rt := func(string, ...string) ([]byte, error) { return nil, errors.New("unused") }
	var got string
	withSeams(t, "linux", files, hn, rt, func() { got, _ = ForOrg("") })
	if got != "" {
		t.Errorf("empty orgID must yield an empty (unbindable) identity, got %q", got)
	}
}

func TestDarwinPlatformUUIDParsing(t *testing.T) {
	noFiles := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	hn := func() (string, error) { return "mac-host", nil }
	ioreg := `+-o IOPlatformExpertDevice  <class IOPlatformExpertDevice>
    "IOPlatformUUID" = "11112222-3333-4444-5555-666677778888"
    "IOPlatformSerialNumber" = "C02XYZ"`
	rt := func(name string, _ ...string) ([]byte, error) {
		if name != "ioreg" {
			return nil, errors.New("unexpected tool")
		}
		return []byte(ioreg), nil
	}
	var got string
	withSeams(t, "darwin", noFiles, hn, rt, func() { got, _ = ForOrg("org") })
	want := hashIdentity("org", "11112222-3333-4444-5555-666677778888")
	if got != want {
		t.Errorf("darwin UUID parse = %q, want hash of the IOPlatformUUID %q", got, want)
	}
}

func TestWindowsMachineGUIDParsing(t *testing.T) {
	noFiles := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	hn := func() (string, error) { return "win-host", nil }
	regOut := "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    MachineGuid    REG_SZ    aaaabbbb-cccc-dddd-eeee-ffff00001111\r\n"
	rt := func(name string, _ ...string) ([]byte, error) {
		if name != "reg" {
			return nil, errors.New("unexpected tool")
		}
		return []byte(regOut), nil
	}
	var got string
	withSeams(t, "windows", noFiles, hn, rt, func() { got, _ = ForOrg("org") })
	want := hashIdentity("org", "aaaabbbb-cccc-dddd-eeee-ffff00001111")
	if got != want {
		t.Errorf("windows GUID parse = %q, want hash of the MachineGuid %q", got, want)
	}
}

// --- persisted-seed rung (the ACI machine-identity fix) ----------------------

// TestPersistedSeedMintsOnceAndIsStable is the rung's reason for existing: a
// container with no /etc/machine-id and a REMINTED hostname must still report
// the same identity across restarts, as long as the data dir is a mounted
// volume. The hostname changes between the two calls exactly as ACI's
// SandboxHost-<n> does; the identity must not.
func TestPersistedSeedMintsOnceAndIsStable(t *testing.T) {
	dir := t.TempDir()

	var first, second string
	withSeedDir(t, dir, func() {
		var err error
		if first, err = ForOrg("org-A"); err != nil {
			t.Fatalf("ForOrg (mint): %v", err)
		}
	})
	if first == "" {
		t.Fatal("expected the persisted-seed rung to yield an identity")
	}

	seed := filepath.Join(dir, ".observer", "machine-id")
	raw, err := os.ReadFile(seed)
	if err != nil {
		t.Fatalf("seed file not written at %s: %v", seed, err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		t.Fatal("seed file is empty")
	}

	// Restart with a DIFFERENT hostname, the way ACI remints SandboxHost-<n>.
	withSeedDir(t, dir, func() {
		hostname = func() (string, error) { return "SandboxHost-999999999999", nil }
		var err error
		if second, err = ForOrg("org-A"); err != nil {
			t.Fatalf("ForOrg (re-read): %v", err)
		}
	})
	if first != second {
		t.Errorf("identity changed across restart: %q != %q — the seed was not re-read", first, second)
	}

	// And the value must actually be the SEED, not the hostname: the whole
	// point is that the hostname rung was skipped.
	if want := hashIdentity("org-A", strings.TrimSpace(string(raw))); first != want {
		t.Errorf("identity = %q, want the hash of the persisted seed %q", first, want)
	}

	after, err := os.ReadFile(seed)
	if err != nil || !bytes.Equal(raw, after) {
		t.Errorf("seed file was rewritten on the second call; want mint-once (err=%v)", err)
	}
}

// TestPersistedSeedFallsBackToHostnameWhenUnwritable pins the read-only-
// filesystem case: minting fails, and the ladder must degrade to the hostname
// rather than to an unbindable empty identity.
func TestPersistedSeedFallsBackToHostnameWhenUnwritable(t *testing.T) {
	dir := t.TempDir()
	origWrite, origMkdir := writeFileExcl, mkdirAll
	defer func() { writeFileExcl, mkdirAll = origWrite, origMkdir }()
	writeFileExcl = func(string, []byte, fs.FileMode) error { return errors.New("read-only file system") }
	mkdirAll = func(string, fs.FileMode) error { return nil }

	var got string
	withSeedDir(t, dir, func() { got, _ = ForOrg("org-A") })

	if want := hashIdentity("org-A", "SandboxHost-000000000000"); got != want {
		t.Errorf("unwritable seed dir: identity = %q, want the hostname fallback %q", got, want)
	}
}

// TestPersistedSeedLostMintRaceReadsWinnersValue covers two processes racing to
// mint: O_EXCL fails for the loser, which must adopt the winner's value rather
// than fall through to the hostname (which would give one machine two
// identities).
func TestPersistedSeedLostMintRaceReadsWinnersValue(t *testing.T) {
	dir := t.TempDir()
	seedDir := filepath.Join(dir, ".observer")
	if err := os.MkdirAll(seedDir, 0o700); err != nil {
		t.Fatal(err)
	}

	origWrite := writeFileExcl
	defer func() { writeFileExcl = origWrite }()
	writeFileExcl = func(path string, _ []byte, _ fs.FileMode) error {
		// The "other process" wins between our read and our create.
		if err := os.WriteFile(path, []byte("winner-seed\n"), 0o600); err != nil {
			return err
		}
		return fs.ErrExist
	}

	var got string
	withSeedDir(t, dir, func() { got, _ = ForOrg("org-A") })

	if want := hashIdentity("org-A", "winner-seed"); got != want {
		t.Errorf("lost mint race: identity = %q, want the winner's seed %q", got, want)
	}
}

// TestOSNativeSourceSkipsPersistedSeed is the additive guarantee: a host that
// already has /etc/machine-id must neither read nor CREATE the seed file, so
// shipping this rung cannot change any existing machine's identity.
func TestOSNativeSourceSkipsPersistedSeed(t *testing.T) {
	dir := t.TempDir()
	origRF, origHome := readFile, homeDir
	defer func() { readFile, homeDir = origRF, origHome }()

	var native string
	withSeams(t, "linux", fixedFile(map[string]string{"/etc/machine-id": "native-id"}),
		func() (string, error) { return "host", nil },
		func(string, ...string) ([]byte, error) { return nil, errors.New("unused") },
		func() {
			// Re-enable the seed dir INSIDE the OS-source case: if rawIdentity
			// consulted it anyway, the file below would appear.
			homeDir = func() (string, error) { return dir, nil }
			native, _ = ForOrg("org-A")
		})

	if want := hashIdentity("org-A", "native-id"); native != want {
		t.Errorf("identity = %q, want the /etc/machine-id value %q", native, want)
	}
	if _, err := os.Stat(filepath.Join(dir, ".observer", "machine-id")); !os.IsNotExist(err) {
		t.Error("a host with an OS-native id must not mint a persisted seed")
	}
}

func TestHashIdentityDomainSeparation(t *testing.T) {
	// (org="a", raw="bc") must not collide with (org="ab", raw="c").
	if hashIdentity("a", "bc") == hashIdentity("ab", "c") {
		t.Error("hashIdentity must domain-separate the org salt from the raw id")
	}
}
