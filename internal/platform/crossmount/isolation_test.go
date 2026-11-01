package crossmount

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIsolationReasonWith pins the ordered isolation rule table (R-013).
func TestIsolationReasonWith(t *testing.T) {
	t.Parallel()
	real := t.TempDir()
	inside := filepath.Join(real, "sub")
	outside := t.TempDir()
	cases := []struct {
		name string
		in   isolationInputs
		want string // substring; "" means not isolated
	}{
		{"real home: not isolated", isolationInputs{home: real, realHome: real}, ""},
		{"home under the real home: isolated (LEFT2 audit S3)", isolationInputs{home: inside, realHome: real}, "not the real user home"},
		{"the real home spelled with a trailing separator: not isolated", isolationInputs{home: real + string(filepath.Separator), realHome: real}, ""},
		{"real home unknown: not isolated", isolationInputs{home: outside}, ""},
		{"home outside the real home", isolationInputs{home: outside, realHome: real}, "not the real user home"},
		{"process reason", isolationInputs{home: real, realHome: real, process: "--no-crossmount was given"}, "--no-crossmount"},
		{"harness knob", isolationInputs{home: real, realHome: real, disableEnv: "1"}, EnvDisableForeignHomes},
		{"knob wins over the process reason", isolationInputs{disableEnv: "yes", process: "--no-crossmount"}, EnvDisableForeignHomes},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := isolationReasonWith(c.in)
			if c.want == "" && got != "" {
				t.Fatalf("isolationReasonWith(%+v) = %q, want not isolated", c.in, got)
			}
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("isolationReasonWith(%+v) = %q, want it to name %q", c.in, got, c.want)
			}
		})
	}
}

// setHome points this process's home at dir on every OS.
func setHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

// foreignFound reports whether AllHomes lists the staged foreign home.
func foreignFound(home string) bool {
	for _, h := range AllHomes() {
		if h.Origin != "native" && h.Path == home {
			return true
		}
	}
	return false
}

// TestIsolatedHomeDetectsAndWritesNoForeignProfile is the R-013 regression at
// the source: a detectable foreign profile sits at the scanned root and
// discovery is allowed, but HOME points outside the real user home, so no
// foreign home is detected and no named foreign home outside HOME passes the
// write gate. The control with HOME at the real home finds it. Not parallel:
// it stages process-wide state.
func TestIsolatedHomeDetectsAndWritesNoForeignProfile(t *testing.T) {
	root, foreign := stageFakeForeignMount(t, "operator")
	realHome := t.TempDir()
	scratch := t.TempDir()

	t.Run("control: HOME is the real home", func(t *testing.T) {
		StageForeignLayoutForTest(t, ForeignLayoutForTest{Root: root, WindowsUser: "operator", Discover: true, RealHome: realHome})
		setHome(t, realHome)
		if !foreignFound(foreign) {
			t.Fatalf("foreign home %s not detected with HOME at the real home; the fixture is not detectable", foreign)
		}
		if AutoDetectSuppressed("", "") {
			t.Fatal("AutoDetectSuppressed(\"\", \"\") = true with HOME at the real home, want the production answer false")
		}
		if r := DetectionOffReason(); r != "" {
			t.Fatalf("DetectionOffReason() = %q, want \"\"", r)
		}
	})
	t.Run("HOME set to a temp dir", func(t *testing.T) {
		StageForeignLayoutForTest(t, ForeignLayoutForTest{Root: root, WindowsUser: "operator", Discover: true, RealHome: realHome})
		setHome(t, scratch)
		if foreignFound(foreign) {
			t.Fatalf("foreign home %s detected under an isolated HOME", foreign)
		}
		if !AutoDetectSuppressed("", "") {
			t.Fatal("AutoDetectSuppressed(\"\", \"\") = false under an isolated HOME")
		}
		if !AutoDetectSuppressed("", foreign) {
			t.Fatal("a named foreign home outside the isolated HOME passed the write gate")
		}
		if AutoDetectSuppressed("", filepath.Join(scratch, "win")) {
			t.Fatal("a named foreign home inside the isolated HOME was refused")
		}
		if r := DetectionOffReason(); !strings.Contains(r, "not the real user home") {
			t.Fatalf("DetectionOffReason() = %q, want it to name the isolated home", r)
		}
	})
	t.Run("--no-crossmount at the real home", func(t *testing.T) {
		StageForeignLayoutForTest(t, ForeignLayoutForTest{Root: root, WindowsUser: "operator", Discover: true, RealHome: realHome})
		setHome(t, realHome)
		DisableForProcess("--no-crossmount was given")
		if foreignFound(foreign) {
			t.Fatal("foreign home detected after --no-crossmount")
		}
		if r := DetectionOffReason(); r != "--no-crossmount was given" {
			t.Fatalf("DetectionOffReason() = %q, want the flag", r)
		}
	})
	t.Run("restored after the stage", func(t *testing.T) {
		if p := processIsolation.Load(); p != nil {
			t.Fatalf("DisableForProcess reason %q leaked past its test", *p)
		}
	})
}

// TestConfigOutsideRealHome pins the --config rule.
func TestConfigOutsideRealHome(t *testing.T) {
	root, _ := stageFakeForeignMount(t, "operator")
	realHome := t.TempDir()
	StageForeignLayoutForTest(t, ForeignLayoutForTest{Root: root, Discover: true, RealHome: realHome})
	if r := ConfigOutsideRealHome(filepath.Join(realHome, ".observer", "config.toml")); r != "" {
		t.Errorf("config under the real home = %q, want \"\"", r)
	}
	if r := ConfigOutsideRealHome(""); r != "" {
		t.Errorf("no --config = %q, want \"\"", r)
	}
	other := filepath.Join(t.TempDir(), "config.toml")
	if r := ConfigOutsideRealHome(other); !strings.Contains(r, "--config") {
		t.Errorf("config outside the real home = %q, want a reason naming --config", r)
	}
}

// TestUnstagedTestBinaryIgnoresIsolationRules: in a test binary with nothing
// staged, a TestMain's harness knob must not change what an explicit foreign
// override does (the guard already covers detection).
func TestUnstagedTestBinaryIgnoresIsolationRules(t *testing.T) {
	if envTruthy(os.Getenv(AllowLiveForeignHomesInTestEnv)) {
		t.Skip("live hatch open")
	}
	t.Setenv(EnvDisableForeignHomes, "1")
	if r := IsolationReason(); r != "" {
		t.Fatalf("IsolationReason() = %q in an unstaged test binary, want \"\"", r)
	}
	if AutoDetectSuppressed("", "/some/explicit/override") {
		t.Fatal("an explicit override was suppressed in an unstaged test binary")
	}
	if r := DetectionOffReason(); r != "this is a test binary" {
		t.Fatalf("DetectionOffReason() = %q, want the test-binary guard", r)
	}
}

// TestScratchHomeUnderTheRealHomeIsIsolated (LEFT2 audit S3): the operator's
// kit pattern, HOME=<realhome>/scratch/x, is isolated like any other HOME
// that is not exactly the real home: no foreign home is detected, the write
// gate refuses a foreign home outside it, and doctor names why. A symlink
// that resolves to the real home is the real home.
func TestScratchHomeUnderTheRealHomeIsIsolated(t *testing.T) {
	root, foreign := stageFakeForeignMount(t, "operator")
	realHome := t.TempDir()
	scratch := filepath.Join(realHome, "scratch", "x")
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	StageForeignLayoutForTest(t, ForeignLayoutForTest{Root: root, WindowsUser: "operator", Discover: true, RealHome: realHome})
	setHome(t, scratch)
	if foreignFound(foreign) {
		t.Fatalf("foreign home %s detected under HOME=%s", foreign, scratch)
	}
	if !AutoDetectSuppressed("", foreign) {
		t.Fatal("a named foreign home outside the scratch HOME passed the write gate")
	}
	if r := DetectionOffReason(); !strings.Contains(r, "not the real user home") {
		t.Fatalf("DetectionOffReason() = %q, want the scratch home named", r)
	}
	link := filepath.Join(t.TempDir(), "home-link")
	if err := os.Symlink(realHome, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	setHome(t, link)
	if r := IsolationReason(); r != "" {
		t.Fatalf("a HOME that resolves to the real home reads isolated: %q", r)
	}
}

// TestForeignHomesSuppressedHonoursIsolation (LEFT2 audit S5): the raw
// foreign-path writers (the antigravity bridge cache under /mnt/c, the
// shell-wrap target) consult ForeignHomesSuppressed, so it must say true
// under an isolated home even when the staged layout allows discovery.
func TestForeignHomesSuppressedHonoursIsolation(t *testing.T) {
	root, _ := stageFakeForeignMount(t, "operator")
	realHome := t.TempDir()
	StageForeignLayoutForTest(t, ForeignLayoutForTest{Root: root, WindowsUser: "operator", Discover: true, RealHome: realHome})
	setHome(t, realHome)
	if ForeignHomesSuppressed() {
		t.Fatal("control: suppressed at the real home with discovery allowed")
	}
	setHome(t, t.TempDir())
	if !ForeignHomesSuppressed() {
		t.Fatal("ForeignHomesSuppressed() = false under an isolated HOME")
	}
	setHome(t, realHome)
	DisableForProcess("--no-crossmount was given")
	if !ForeignHomesSuppressed() {
		t.Fatal("ForeignHomesSuppressed() = false after --no-crossmount")
	}
}
