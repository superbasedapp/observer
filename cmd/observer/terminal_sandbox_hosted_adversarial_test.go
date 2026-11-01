//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
)

// terminal_sandbox_hosted_adversarial_test.go is the section 13.12 gate for
// the three hosted rows (lane SBX-P7): every case the lane owns (A1 to A7,
// A11, A12) has, per row, a disposition that is a unit test here, a
// register entry (REM, docs/sandboxed-terminals.md) a live run with a real
// account must close, a shared mechanism with its own tests, or a reasoned
// not-applicable. A case without a row, a test that does not exist or a
// register entry that is not a REM row of the docs fails.
//
// Like the macOS gate, the walk is BOOKKEEPING: it proves each named test
// exists (the tests run, and fail, in their own packages); a Shared or
// NotApplicable cell is a reasoned claim.

// hostedAdversarialCases are the 13.12 cases this lane owns.
var hostedAdversarialCases = []string{"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A11", "A12"}

// hostedAdversarialGate is the table, row id -> case id -> disposition.
var hostedAdversarialGate = map[string]map[string]macCase{
	sandboxbackend.BackendE2B: {
		"A1":  {Tests: []string{"internal/sandboxremote/e2b:TestLifecycle", "internal/sandboxbackend:TestHostedRowsAreBetaRemoteAndRelayed", "internal/sandboxremote/relaymux:TestMuxRefusesAKindTheTierDoesNotAllow"}, Register: []string{"REM-3", "REM-4", "REM-5"}},
		"A2":  {Tests: []string{".:TestHostedLiveRunIsNotALeftover", ".:TestHostedLeftoverDeleteConfirms", "internal/sandboxremote:TestLeftovers"}, Register: []string{"REM-8"}},
		"A3":  {Tests: []string{"internal/sandboxremote/relaymux:TestDeadlineConn"}, Shared: "the relay exec stream is re-opened and re-keyed after a drop (keepRelay); gate events block while it is down", Register: []string{"REM-7"}},
		"A4":  {Shared: "the section 5.5 update deferral for live sandboxed runs; the box keeps its vendor timeout either way"},
		"A5":  {Tests: []string{"internal/sandboxremote/relaymux:TestMuxHostileGuest", "internal/sandboxremote/relaymux:TestMuxWindowOverrunCloses", "internal/sandboxremote/relaymux:TestLineCodec", ".:TestHostedQuarantineWriteConfined"}, Register: []string{"REM-6"}},
		"A6":  {Tests: []string{".:TestHostedHostCutTransportReattaches", "internal/sandboxremote/e2b:TestProcessPTYResizeAndReattach"}, Register: []string{"REM-7"}},
		"A7":  {Tests: []string{".:TestHostedHostLifecycle", ".:TestHostedHostLostCreate", "internal/sandboxremote:TestTeardownTable"}, Register: []string{"REM-7", "REM-10"}},
		"A11": {Tests: []string{"internal/sandboxremote/e2b:TestLifecycle"}, NotApplicable: "no snapshot is taken: autoPause is false at create and nothing pauses a box", Register: []string{"REM-10"}},
		"A12": {Tests: []string{".:TestHostedProbeLadder", ".:TestHostedHostLifecycle"}, Shared: "the in-box observer is this running Linux binary after a version and architecture check, never a download", Register: []string{"REM-2"}},
	},
	sandboxbackend.BackendModal: {
		"A1":  {Tests: []string{"internal/sandboxremote/modal:TestCreateMapsTiersRegionsAndTags", "internal/sandboxbackend:TestHostedRowsAreBetaRemoteAndRelayed", "internal/sandboxremote/relaymux:TestMuxRefusesAKindTheTierDoesNotAllow"}, Register: []string{"REM-3", "REM-4", "REM-5"}},
		"A2":  {Tests: []string{".:TestHostedLiveRunIsNotALeftover", ".:TestHostedLeftoverDeleteConfirms", "internal/sandboxremote/modal:TestDeleteConfirmsAndListFilters"}, Register: []string{"REM-8"}},
		"A3":  {Tests: []string{"internal/sandboxremote/relaymux:TestDeadlineConn"}, Shared: "the relay exec stream is re-opened and re-keyed after a drop (keepRelay)", Register: []string{"REM-7"}},
		"A4":  {Shared: "the section 5.5 update deferral for live sandboxed runs; the box keeps its vendor timeout either way"},
		"A5":  {Tests: []string{"internal/sandboxremote/relaymux:TestMuxHostileGuest", "internal/sandboxremote/relaymux:TestMuxWindowOverrunCloses", ".:TestHostedQuarantineWriteConfined"}, Register: []string{"REM-6"}},
		"A6":  {Tests: []string{".:TestHostedHostNoReattachEndsHonestly", "internal/sandboxremote/modal:TestExecRelayStreamAndUnsupported"}, NotApplicable: "Modal documents no reattach, so Observer has none: its SDK resumes a cut exec stream itself (live REM-7, run 2), and a stream it cannot resume ends the run and says to resume the agent's own session (A7)", Register: []string{"REM-7"}},
		"A7":  {Tests: []string{".:TestHostedHostGuestPTY", ".:TestHostedHostLostCreate", "internal/sandboxremote/modal:TestLostCreateAndRateLimit"}, Register: []string{"REM-7", "REM-10"}},
		"A11": {NotApplicable: "no snapshot is ever requested: the create sets neither the exit snapshot nor memory snapshots (sdk.go)", Register: []string{"REM-10"}},
		"A12": {Tests: []string{".:TestHostedProbeLadder"}, Shared: "the in-box observer is this running Linux binary after a version and architecture check; the SDK is pinned in go.mod (v0.11.1)", Register: []string{"REM-2"}},
	},
	sandboxbackend.BackendVercelSandbox: {
		"A1":  {Tests: []string{"internal/sandboxremote/vercel:TestCreateBodyPerTier", "internal/sandboxbackend:TestHostedRowsAreBetaRemoteAndRelayed", "internal/sandboxremote/relaymux:TestMuxRefusesAKindTheTierDoesNotAllow"}, Register: []string{"REM-3", "REM-4", "REM-5"}},
		"A2":  {Tests: []string{".:TestHostedLiveRunIsNotALeftover", ".:TestHostedLeftoverDeleteConfirms", "internal/sandboxremote/vercel:TestGetDeleteConfirmAndList"}, Register: []string{"REM-8"}},
		"A3":  {Tests: []string{"internal/sandboxremote/vercel:TestLogStreamDropResumes", "internal/sandboxremote/relaymux:TestDeadlineConn"}, Register: []string{"REM-7"}},
		"A4":  {Shared: "the section 5.5 update deferral for live sandboxed runs; the box keeps its vendor timeout either way"},
		"A5":  {Tests: []string{"internal/sandboxremote/relaymux:TestMuxHostileGuest", "internal/sandboxremote/relaymux:TestMuxWindowOverrunCloses", ".:TestHostedQuarantineWriteConfined"}, Register: []string{"REM-6"}},
		"A6":  {Tests: []string{".:TestHostedHostNoReattachEndsHonestly", "internal/sandboxremote/vercel:TestExitCodeKillAndUnsupported"}, NotApplicable: "Vercel documents no reattach (the interactive WebSocket is undocumented and unused): a cut transport ends the run with the native-resume message", Register: []string{"REM-7"}},
		"A7":  {Tests: []string{".:TestHostedHostGuestPTY", "internal/sandboxremote/vercel:TestCreateConflictAndLost"}, Register: []string{"REM-7", "REM-10"}},
		"A11": {Tests: []string{"internal/sandboxremote/vercel:TestCreateBodyPerTier", "internal/sandboxremote/vercel:TestGetDeleteConfirmAndList"}, NotApplicable: "persistent=false at create (no snapshot on stop) and deleteOrphanSnapshots=true at delete", Register: []string{"REM-10"}},
		"A12": {Tests: []string{".:TestHostedProbeLadder"}, Shared: "the in-box observer is this running Linux binary after a version and architecture check, never a download", Register: []string{"REM-2"}},
	},
}

var remRegisterID = regexp.MustCompile(`^REM-([1-9]|1[0-2])$`)

func TestHostedAdversarialGate(t *testing.T) {
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
	for _, row := range []string{sandboxbackend.BackendE2B, sandboxbackend.BackendModal, sandboxbackend.BackendVercelSandbox} {
		cases := hostedAdversarialGate[row]
		for _, id := range hostedAdversarialCases {
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
				if !remRegisterID.MatchString(r) || !strings.Contains(string(doc), "| "+r+" |") {
					t.Errorf("%s %s: register entry %q is not a REM row of the docs' register", row, id, r)
				}
			}
		}
		if len(cases) != len(hostedAdversarialCases) {
			t.Errorf("%s: %d cases, want %d", row, len(cases), len(hostedAdversarialCases))
		}
	}
	if !strings.Contains(string(doc), "### Adversarial cases (plan section 13.12, the hosted rows)") {
		t.Error("docs/sandboxed-terminals.md has no hosted adversarial table")
	}
}
