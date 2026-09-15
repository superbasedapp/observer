package integration_test

import (
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

// TestInstallHintOSIsClosedVocabulary pins InstallHint.OS to
// {"", "linux", "darwin", "windows"} — a typo here (e.g. "Windows",
// "win32") silently produces a dead row: no OS ever matches it (§6.2, the
// research's "a typo is an invisible dead row today" note).
func TestInstallHintOSIsClosedVocabulary(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.Binary == nil {
			continue
		}
		for i, h := range c.Binary.Installs {
			if !installHintValidOS[h.OS] {
				t.Errorf("adapter %q: Installs[%d].OS = %q is not in the closed vocabulary {\"\",\"linux\",\"darwin\",\"windows\"}", c.Tool, i, h.OS)
			}
		}
	}
}

// installHintValidChannel is the closed vocabulary for InstallHint.Channel
// (capability.go doc comment, §1.6 of the research). "choco" is
// deliberately excluded — see capability.go's Channel doc.
var installHintValidChannel = map[string]bool{
	"npm": true, "script": true, "brew": true, "winget": true, "uv": true, "scoop": true,
}

// TestInstallHintChannelIsClosedVocabulary pins InstallHint.Channel to
// the documented vocabulary, so T5's dashboardInstallChannelRank table
// never silently falls through to the "else" bucket for a typo'd channel.
func TestInstallHintChannelIsClosedVocabulary(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.Binary == nil {
			continue
		}
		for i, h := range c.Binary.Installs {
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

// TestRegistryTotals pins the raw registry shape at HEAD as DI-19's
// recurrence gate: a silent drift in these three counts means a doc
// (docs/plans/adapter-coverage-parity-plan-2026-06-26.md §15,
// docs/README.md) has gone stale and needs a bump alongside the code
// change that moved the number. Verified 2026-09-02 against the live
// registry (matches docs/audits/dashboard-install-audit-2026-09-02.md
// §3's count and the adapter-coverage-parity plan's 2026-08-27 snapshot).
func TestRegistryTotals(t *testing.T) {
	const (
		wantTotal      = 45 // len(integration.Tools()); 42 -> 43 on 2026-09-03 (kiro-crew), 43 -> 44 on 2026-09-05 (poolside), 44 -> 45 on 2026-09-06 (zed)
		wantLaunchable = 27 // Handoff.Launchable() == true
		wantBinary     = 28 // Binary != nil (27 launchable + aider, Binary-only)
	)
	caps := integration.Capabilities()
	if got := len(caps); got != wantTotal {
		t.Errorf("total registry rows = %d, want %d (bump docs/plans/adapter-coverage-parity-plan-2026-06-26.md §15 and docs/README.md alongside this constant if the change is intentional)", got, wantTotal)
	}
	launchable, binary := 0, 0
	for _, c := range caps {
		if c.Handoff.Launchable() {
			launchable++
		}
		if c.Binary != nil {
			binary++
		}
	}
	if launchable != wantLaunchable {
		t.Errorf("launchable rows = %d, want %d (bump docs/plans/adapter-coverage-parity-plan-2026-06-26.md §15 and docs/README.md alongside this constant if the change is intentional)", launchable, wantLaunchable)
	}
	if binary != wantBinary {
		t.Errorf("Binary != nil rows = %d, want %d (bump docs/plans/adapter-coverage-parity-plan-2026-06-26.md §15 and docs/README.md alongside this constant if the change is intentional)", binary, wantBinary)
	}
}
