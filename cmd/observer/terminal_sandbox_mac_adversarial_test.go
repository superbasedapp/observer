//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
)

// terminal_sandbox_mac_adversarial_test.go is the section 13.12 gate for the
// two macOS rows (lane SBX-P5): every case A1 to A13 has, per row, a
// disposition that is a unit test that passes here, a register entry
// (section 13.9) a Mac must close, a shared mechanism with its own tests,
// or a reasoned not-applicable. Nothing is silently skipped: a case without
// a row, a test that does not exist or a register entry that is not a MAC
// id fails. docs/sandboxed-terminals.md carries the same table.
//
// The table walk is BOOKKEEPING: it proves each named test exists, not that
// it passes (the named tests run, and fail, in their own packages), and a
// "Shared" or "NotApplicable" cell is a reasoned claim, not a check. Apple
// A7 in particular maps to a metadata test (the row's declared lifecycle);
// its behaviour is register MAC-33. The behaviour this gate does check
// itself is TestMacAdversarialBehaviour: per row, A13 (automatic selection
// never picks it) and A1 (no host tier, the provider-host block declared).

// macCase is one case's disposition on one row.
type macCase struct {
	// Tests are "pkgdir:TestName" ("." is cmd/observer); each must exist.
	Tests []string
	// Register are the section 13.9 rows a live run must close.
	Register []string
	// Shared names the shared mechanism that carries the case unchanged.
	Shared string
	// NotApplicable says why the case cannot arise on this row.
	NotApplicable string
}

// macAdversarialGate is the table, row id -> case id -> disposition.
var macAdversarialGate = map[string]map[string]macCase{
	"seatbelt": {
		"A1":  {Tests: []string{"internal/sandboxsbpl:TestOracleNetworkPerTier", ".:TestSeatbeltComputedCapture", "internal/sandboxsbpl:TestCheckerRefusals"}, Register: []string{"MAC-4", "MAC-7"}},
		"A2":  {Tests: []string{".:TestSeatbeltLifecycleIsPTYOwned"}, Register: []string{"MAC-35"}},
		"A3":  {Shared: "the capture relay blocks gate events while it is unreachable and replays capture events (internal/sandboxrelayd)", Register: []string{"MAC-35"}},
		"A4":  {Shared: "the section 5.5 update deferral for live sandboxed runs"},
		"A5":  {Shared: "the relay's frame decoder and its fuzz targets (the same code over the same unix socket)", Register: []string{"MAC-5"}},
		"A6":  {NotApplicable: "same host, no transport to drop (RelayReattach not_needed)", Register: []string{"MAC-5"}},
		"A7":  {Tests: []string{".:TestSeatbeltLifecycleIsPTYOwned"}, Register: []string{"MAC-2", "MAC-3"}},
		"A8":  {NotApplicable: "no org-published endpoint: sandbox-exec is local and never pinned"},
		"A9":  {Tests: []string{"internal/sandboxsbpl:TestProbeLadder"}, NotApplicable: "no engine socket; the one binary run is Apple's root-owned /usr/bin/sandbox-exec, refused otherwise"},
		"A10": {Shared: "continuous hook verification and drift (sandboxrelayd HookProbe, A10 under require_full_capture)", Register: []string{"MAC-35"}},
		"A11": {NotApplicable: "no snapshot or warm image exists for this row"},
		"A12": {Tests: []string{"internal/sandboxsbpl:TestProbeLadder"}, Register: []string{"MAC-32"}},
		"A13": {Tests: []string{".:TestSeatbeltIsNeverAnAutoPick", "internal/sandboxbackend:TestMacOSRowsAreDocVerified"}},
	},
	"apple-container": {
		"A1":  {Tests: []string{"internal/sandboxapple:TestRunArgv", "internal/sandboxapple:TestContainerMachineIsRefused", "internal/sandboxapple:TestContractInspectReadBack"}, Register: []string{"MAC-13", "MAC-14"}},
		"A2":  {Tests: []string{"internal/sandboxapple:TestOrphanSweep", ".:TestAppleDriverIsOptIn"}, Register: []string{"MAC-17", "MAC-27"}},
		"A3":  {Shared: "the capture relay's rules over the mounted socket dir", Register: []string{"MAC-33"}},
		"A4":  {Shared: "the section 5.5 update deferral for live sandboxed runs"},
		"A5":  {Shared: "the relay's frame decoder and its fuzz targets", Register: []string{"MAC-15"}},
		"A6":  {NotApplicable: "the relay is a mounted socket dir, not the CLI's TTY stream (RelayReattach not_needed)", Register: []string{"MAC-15", "MAC-33"}},
		"A7":  {Tests: []string{"internal/sandboxbackend:TestOfferedRowsAreFullyGrounded"}, Register: []string{"MAC-33"}},
		"A8":  {NotApplicable: "no org-published endpoint: the CLI and its service are local"},
		"A9":  {Tests: []string{"internal/sandboxapple:TestProbeLadder"}, NotApplicable: "no engine socket; a CLI that is not a regular file owned by you or root, or that others can write, is refused"},
		"A10": {Shared: "continuous hook verification and drift (sandboxrelayd HookProbe)", Register: []string{"MAC-33"}},
		"A11": {Tests: []string{"internal/sandboxapple:TestRunArgv"}, NotApplicable: "no snapshot; every run is --rm and removed again by the helper"},
		"A12": {Tests: []string{"internal/sandboxapple:TestRunArgvRefusals", "internal/sandboxapple:TestContractImages"}, Register: []string{"MAC-32"}},
		"A13": {Tests: []string{".:TestAppleIsNeverAnAutoPick", "internal/sandboxbackend:TestMacOSRowsAreDocVerified"}},
	},
}

var macRegisterID = regexp.MustCompile(`^MAC-([0-9]|[1-3][0-9])$`)

func TestMacAdversarialGate(t *testing.T) {
	publictree.Skip(t, "docs/sandboxed-terminals.md")
	sources := map[string]string{}
	read := func(dir string) string {
		if s, ok := sources[dir]; ok {
			return s
		}
		path := dir
		if dir != "." {
			path = filepath.Join("..", "..", dir)
		}
		files, _ := filepath.Glob(filepath.Join(path, "*_test.go"))
		var sb strings.Builder
		for _, f := range files {
			b, err := os.ReadFile(f) //nolint:gosec // G304: the repository's own test files
			if err == nil {
				sb.Write(b)
			}
		}
		sources[dir] = sb.String()
		return sources[dir]
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "sandboxed-terminals.md"))
	if err != nil {
		t.Fatal(err)
	}
	for row, cases := range macAdversarialGate {
		for i := 1; i <= 13; i++ {
			id := "A" + strconv.Itoa(i)
			c, ok := cases[id]
			if !ok {
				t.Errorf("%s: case %s has no disposition", row, id)
				continue
			}
			if len(c.Tests) == 0 && len(c.Register) == 0 && c.Shared == "" && c.NotApplicable == "" {
				t.Errorf("%s %s: an empty disposition", row, id)
			}
			for _, ref := range c.Tests {
				dir, name, ok := strings.Cut(ref, ":")
				if !ok || !strings.Contains(read(dir), "func "+name+"(") {
					t.Errorf("%s %s: test %s does not exist", row, id, ref)
				}
			}
			for _, r := range c.Register {
				if !macRegisterID.MatchString(r) || !strings.Contains(string(doc), "| "+r+" |") {
					t.Errorf("%s %s: register entry %q is not a MAC row of the docs' register", row, id, r)
				}
			}
		}
		if len(cases) != 13 {
			t.Errorf("%s: %d cases, want A1 to A13", row, len(cases))
		}
	}
	if !strings.Contains(string(doc), "### Adversarial cases (plan section 13.12, the macOS rows)") {
		t.Error("docs/sandboxed-terminals.md has no macOS adversarial table")
	}
}

// TestMacAdversarialBehaviour checks the two cases the gate can judge on any
// host, per macOS row, through the real rule table rather than a test name:
// A13, a launch that names no backend never takes the row (S4c, ruling
// P-062) while a launch that names it may; A1, the row offers no host tier
// (the box would share the daemon's loopback) and declares the provider-host
// block.
func TestMacAdversarialBehaviour(t *testing.T) {
	for row := range macAdversarialGate {
		c, ok := sandboxbackend.Get(row)
		if !ok {
			t.Fatalf("%s: no registry row", row)
		}
		v, _ := c.VerificationOn(sandboxbackend.HostMacOS)
		d, dropped := sandboxselect.AutoDrop(c, v.Kind)
		if !dropped || d.Verdict != sandboxselect.VerdictBetaNotChosen {
			t.Errorf("%s A13: an automatic choice is not refused: %+v", row, d)
		}
		if c.OffersTier(vocab.TierHost) || !c.Net.ProviderHostBlock {
			t.Errorf("%s A1: host tier %v, provider-host block %v", row, c.OffersTier(vocab.TierHost), c.Net.ProviderHostBlock)
		}
	}
}
