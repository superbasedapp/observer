package integration_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestLaunchableWindowsSpellingGroundedOrNoted pins the T2 honesty
// contract (2026-09-02 dashboard-install-gap-remediation research §1.7,
// §6.2): every launchable tool's Binary row either carries a grounded
// Windows spelling OR an honest WindowsNote explaining why not (muse: no
// Windows build exists). A launchable row with NEITHER is an undeclared
// gap, not a valid final state.
func TestLaunchableWindowsSpellingGroundedOrNoted(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if !c.Handoff.Launchable() {
			continue
		}
		if c.Binary == nil {
			// TestEveryLaunchableToolHasBinarySpec already fails this row;
			// avoid a nil-deref pile-on here.
			continue
		}
		if len(c.Binary.Names.Windows) == 0 && c.Binary.WindowsNote == "" {
			t.Errorf("adapter %q: launchable with no Names.Windows AND no WindowsNote — either ground a Windows spelling or state why not", c.Tool)
		}
	}
}

// TestWindowsSpellingsHaveNoPS1 pins the registry convention
// (capability.go BinaryNames doc, §1.1 of the research): a `.ps1` script
// is never a candidate spelling — it cannot be launched directly by
// exec.Command / CreateProcess (a PowerShell script is not an executable
// image). Walks every non-nil Binary row, not just launchable ones.
func TestWindowsSpellingsHaveNoPS1(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.Binary == nil {
			continue
		}
		for i, w := range c.Binary.Names.Windows {
			if strings.HasSuffix(strings.ToLower(w), ".ps1") {
				t.Errorf("adapter %q: Names.Windows[%d] = %q is a .ps1 script — not launchable, must never be a candidate spelling", c.Tool, i, w)
			}
		}
	}
}

// installHintMatchesOS reports whether hint applies to the given OS: an
// empty InstallHint.OS means "any OS".
func installHintMatchesOS(h integration.InstallHint, os string) bool {
	return h.OS == "" || h.OS == os
}

// TestNoGroundedWindowsInstallHasNote pins the T2 honesty contract for
// Installs: for every launchable tool with a Binary row, each of
// linux/darwin/windows either has a matching InstallHint OR the row
// carries an honest InstallNote (zcode: desktop-installer-only, no CLI
// channel; muse: no Windows channel). A silent gap (no hint, no note) is
// the failure this test exists to catch.
func TestNoGroundedWindowsInstallHasNote(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if !c.Handoff.Launchable() || c.Binary == nil {
			continue
		}
		for _, os := range []string{"linux", "darwin", "windows"} {
			matched := false
			for _, h := range c.Binary.Installs {
				if installHintMatchesOS(h, os) {
					matched = true
					break
				}
			}
			if !matched && c.Binary.InstallNote == "" {
				t.Errorf("adapter %q: no InstallHint matches OS %q AND no InstallNote — either ground a hint or state why not", c.Tool, os)
			}
		}
	}
}

// TestNoUnofficialInstallChannels is a frozen deny-list regression guard
// for DI-11 (zcode's unaffiliated zcode-app-cli npm package, removed
// 2026-09-02) and the prime-agent 404 npm trap (2026-08-07,
// TestGuidedInstallGapClosed's sibling guard): neither string may
// reappear in any registry Argv.
func TestNoUnofficialInstallChannels(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.Binary == nil {
			continue
		}
		for i, h := range c.Binary.Installs {
			for _, tok := range h.Argv {
				if strings.Contains(tok, "zcode-app-cli") {
					t.Errorf("adapter %q: Installs[%d].Argv contains %q — zcode-app-cli is an unaffiliated third-party npm package (DI-11), never a grounded zcode channel", c.Tool, i, tok)
				}
			}
			if h.Channel == "npm" {
				for _, tok := range h.Argv {
					if strings.Contains(tok, "prime-agent") {
						t.Errorf("adapter %q: Installs[%d] is an npm channel naming %q — prime-agent has never been published to the public npm registry (registry.npmjs.org/prime-agent 404s)", c.Tool, i, tok)
					}
				}
			}
		}
	}
}

// installHintValidOS is the closed vocabulary for InstallHint.OS.
var installHintValidOS = map[string]bool{"": true, "linux": true, "darwin": true, "windows": true}

// installHintValidChannel is the closed vocabulary for InstallHint.Channel
// (capability.go doc comment, §1.6 of the research). "choco" is
// deliberately excluded; see capability.go's Channel doc.
var installHintValidChannel = map[string]bool{
	"npm": true, "script": true, "brew": true, "winget": true, "uv": true, "scoop": true,
}

// TestInstallHintsUseClosedVocabularies pins every registry InstallHint to
// the two closed vocabularies. OS: a typo (e.g. "Windows", "win32") silently
// produces a dead row that no OS ever matches (§6.2, "a typo is an invisible
// dead row today"). Channel: a typo would make T5's
// dashboardInstallChannelRank table fall through to its "else" bucket.
func TestInstallHintsUseClosedVocabularies(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.Binary == nil {
			continue
		}
		for i, h := range c.Binary.Installs {
			if !installHintValidOS[h.OS] {
				t.Errorf("adapter %q: Installs[%d].OS = %q is not in the closed vocabulary {\"\",\"linux\",\"darwin\",\"windows\"}", c.Tool, i, h.OS)
			}
			if !installHintValidChannel[h.Channel] {
				t.Errorf("adapter %q: Installs[%d].Channel = %q is not in the closed vocabulary {npm,script,brew,winget,uv,scoop}", c.Tool, i, h.Channel)
			}
		}
	}
}

// TestProbeDirEnvRootIsWindowsOnly pins the capability.go doc for
// ProbeDir.EnvRoot: it is a Windows-only concept (a non-HOME root like
// %ProgramFiles%), so a row that sets EnvRoot must carry OS ==
// ProbeWindows. TestBinarySpecHonesty (registry_coverage_test.go) already
// covers Rel's HOME-relative/slash/no-".." shape; this test is scoped
// narrowly to the new field.
func TestProbeDirEnvRootIsWindowsOnly(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.Binary == nil {
			continue
		}
		for i, p := range c.Binary.ProbeDirs {
			if p.EnvRoot != "" && p.OS != integration.ProbeWindows {
				t.Errorf("adapter %q: ProbeDirs[%d] sets EnvRoot %q but OS is %q, not ProbeWindows — EnvRoot is a Windows-only concept", c.Tool, i, p.EnvRoot, p.OS)
			}
		}
	}
}

// TestGooseInstallHintsMatchVendorDocs pins goose's guided install to the
// commands https://goose-docs.ai/docs/getting-started/installation documents
// (re-grounded 2026-10-02 after a failed guided install on a Linux node): the
// stable-channel download_cli.sh from the aaif-goose/goose repo on Unix, the
// `block-goose-cli` brew formula, and the branch-tip download_cli.ps1 on
// Windows. The repo moved from block/goose in Dec 2025; no hint may point at
// the old location.
func TestGooseInstallHintsMatchVendorDocs(t *testing.T) {
	c, ok := integration.For("goose")
	if !ok || c.Binary == nil {
		t.Fatal("goose has no Binary row")
	}
	// CONFIGURE=false: the documented non-interactive form (the script
	// otherwise ends in `goose configure`, which kept the guided-install PTY
	// open; TestScriptInstallsAreNonInteractive).
	const unixScript = "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash"
	seen := map[string]bool{}
	for i, h := range c.Binary.Installs {
		cmd := strings.Join(h.Argv, " ")
		if strings.Contains(cmd, "block/goose") || strings.Contains(h.Display, "block/goose") {
			t.Errorf("Installs[%d] still points at the moved block/goose repo: %q", i, cmd)
		}
		switch {
		case h.Channel == "script" && (h.OS == "linux" || h.OS == "darwin"):
			if got := h.Argv[len(h.Argv)-1]; got != unixScript || h.Display != unixScript {
				t.Errorf("Installs[%d] (%s script) = %q / display %q, want the documented %q", i, h.OS, got, h.Display, unixScript)
			}
		case h.Channel == "brew":
			if strings.Join(h.Argv, " ") != "brew install block-goose-cli" {
				t.Errorf("Installs[%d] brew = %q, want brew install block-goose-cli", i, cmd)
			}
		case h.Channel == "script" && h.OS == "windows":
			if !strings.Contains(cmd, "https://raw.githubusercontent.com/aaif-goose/goose/main/download_cli.ps1") {
				t.Errorf("Installs[%d] windows script = %q, want the documented download_cli.ps1 URL", i, cmd)
			}
		}
		seen[h.OS+"/"+h.Channel] = true
	}
	for _, want := range []string{"linux/script", "darwin/script", "windows/script"} {
		if !seen[want] {
			t.Errorf("goose has no %s install hint", want)
		}
	}
}

// TestInstallHintRequiresGrounded pins InstallHint.Requires (the host programs
// a guided install checks BEFORE running a vendor script, 2026-10-03): every
// Unix curl|sh hint names curl, every entry is a bare program name (or "a|b"
// alternatives), and the two prerequisites that failed live on demo node 1
// are declared - kiro-cli's Linux script hard-requires unzip, goose's Linux
// script extracts a .tar.bz2 with tar + bzip2.
func TestInstallHintRequiresGrounded(t *testing.T) {
	prog := regexp.MustCompile(`^[a-z0-9][a-z0-9_.+-]*(\|[a-z0-9][a-z0-9_.+-]*)*$`)
	has := func(h integration.InstallHint, want string) bool {
		for _, r := range h.Requires {
			if r == want {
				return true
			}
		}
		return false
	}
	pinned := map[string][]string{
		"kiro-cli/linux": {"curl", "unzip"},
		"goose/linux":    {"curl", "tar", "bzip2"},
	}
	for _, c := range integration.Capabilities() {
		if c.Binary == nil {
			continue
		}
		for i, h := range c.Binary.Installs {
			for _, r := range h.Requires {
				if !prog.MatchString(r) {
					t.Errorf("%s Installs[%d].Requires entry %q is not a bare program name (or a|b alternatives)", c.Tool, i, r)
				}
			}
			cmd := strings.Join(h.Argv, " ")
			if h.OS != "windows" && h.Channel == "script" && strings.Contains(cmd, "curl ") && !has(h, "curl") {
				t.Errorf("%s Installs[%d] (%s) pipes from curl but does not require it: %q", c.Tool, i, h.OS, cmd)
			}
			if h.Channel == "script" {
				for _, want := range pinned[c.Tool+"/"+h.OS] {
					if !has(h, want) {
						t.Errorf("%s Installs[%d] (%s script) must require %q (grounded from the vendor script)", c.Tool, i, h.OS, want)
					}
				}
			}
		}
	}
}
