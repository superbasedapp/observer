package secverify

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Fake credentials are assembled at run time so no credential-shaped
// literal sits in the source.
var (
	fakeAWSKey  = "AKIA" + "Q3EGRQ7XB2LPHJ5N"
	fakeGitHub  = "ghp_" + strings.Repeat("Z9y8", 9)
	privKeyHead = "-----BEGIN " + "RSA PRIVATE KEY-----"
	privKeyTail = "-----END " + "RSA PRIVATE KEY-----"
)

// change builds the name-status and patch for added files.
type change struct {
	status string
	path   string
	lines  []string
}

func build(changes ...change) (nameStatus, patch []byte) {
	var n, p strings.Builder
	for _, c := range changes {
		n.WriteString(c.status + "\x00" + c.path + "\x00")
		p.WriteString("diff --git a/" + c.path + " b/" + c.path + "\n")
		if len(c.lines) > 0 {
			p.WriteString("@@ -0,0 +1," + strconv.Itoa(len(c.lines)) + " @@\n")
			for _, l := range c.lines {
				p.WriteString("+" + l + "\n")
			}
		}
	}
	return []byte(n.String()), []byte(p.String())
}

func run(t *testing.T, pol Policy, dets []Detector, changes ...change) Report {
	t.Helper()
	n, p := build(changes...)
	return Verify(context.Background(), Request{Policy: pol, Base: "b", Head: "h", NameStatus: n, Patch: p}, dets)
}

func TestVerifyAcceptanceRows(t *testing.T) {
	cases := []struct {
		name    string
		changes []change
		want    Verdict
		rule    string
	}{
		{"clean change passes", []change{{"A", "src/app.go", []string{"package app", "func F() {}"}}}, VerdictPass, "clean"},
		{"secret fails", []change{{"M", "config/prod.py", []string{"x = 1", "AWS = '" + fakeAWSKey + "'"}}}, VerdictFail, "deny_finding"},
		{"github token fails", []change{{"A", "deploy.sh", []string{"TOKEN=" + fakeGitHub}}}, VerdictFail, "deny_finding"},
		{"private key block fails", []change{{"A", "id_rsa", []string{privKeyHead, "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn", privKeyTail}}}, VerdictFail, "deny_finding"},
		{"planted hook config fails", []change{{"A", ".claude/settings.json", []string{`{"hooks":{}}`}}}, VerdictFail, "deny_finding"},
		{"planted mcp config fails", []change{{"A", ".mcp.json", []string{`{"mcpServers":{}}`}}}, VerdictFail, "deny_finding"},
		{"nested instructions only flag", []change{{"M", "pkg/AGENTS.md", []string{"be nice"}}}, VerdictPass, "clean"},
		{"vscode settings only flag", []change{{"M", ".vscode/settings.json", []string{"{}"}}}, VerdictPass, "clean"},
		{"documentation example key never fires", []change{{"A", "README.md", []string{"AKIAIOSFODNN7EXAMPLE"}}}, VerdictPass, "clean"},
		{"fixture secret lowered to flag", []change{{"A", "pkg/testdata/creds.txt", []string{fakeAWSKey}}}, VerdictPass, "clean"},
		{"deleted agent config passes", []change{{"D", ".mcp.json", nil}}, VerdictPass, "clean"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := run(t, DefaultPolicy(), nil, c.changes...)
			if rep.Verdict != c.want || rep.Rule != c.rule {
				t.Fatalf("verdict %s/%s, want %s/%s; findings %+v; err %q", rep.Verdict, rep.Rule, c.want, c.rule, rep.Findings, rep.Error)
			}
		})
	}
}

func TestSecretFindingCarriesNoValue(t *testing.T) {
	rep := run(t, DefaultPolicy(), nil, change{"M", "a.py", []string{"one", "two", "k = '" + fakeAWSKey + "'"}})
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	f := rep.Findings[0]
	if f.Line != 3 || f.RuleID != "secret/aws_access_key" || f.Action != ActionDeny {
		t.Errorf("finding = %+v", f)
	}
	for _, s := range []string{f.Message, f.Fingerprint, f.RuleID, f.Path} {
		if strings.Contains(s, fakeAWSKey) || strings.Contains(s, fakeAWSKey[4:]) {
			t.Errorf("secret value leaked into %q", s)
		}
	}
}

func TestEverySecretTypeHasARule(t *testing.T) {
	for _, name := range scrub.DetectorNames() {
		class, _ := scrub.DetectorClass(name)
		if class != scrub.ClassSecret || name == "entropy" {
			continue
		}
		if _, ok := secretRules[name]; !ok {
			t.Errorf("scrub secret detector %q has no secretRules row: decide whether it denies in CI", name)
		}
	}
}

func TestPolicyOverridesAndModes(t *testing.T) {
	secret := change{"A", "a.go", []string{fakeAWSKey}}
	flagged := DefaultPolicy()
	flagged.Detectors["secrets"] = ActionFlag
	if rep := run(t, flagged, nil, secret); rep.Verdict != VerdictPass || rep.Findings[0].Action != ActionFlag {
		t.Errorf("flag override: %s %+v", rep.Verdict, rep.Findings)
	}
	observe := DefaultPolicy()
	observe.Mode = ModeObserve
	if rep := run(t, observe, nil, secret); rep.Verdict != VerdictPass || len(rep.Findings) != 1 {
		t.Errorf("observe: %s", rep.Verdict)
	}
	off := DefaultPolicy()
	off.Require = []string{"agent_config"}
	off.Detectors["secrets"] = ActionOff
	rep := run(t, off, nil, secret)
	if rep.Verdict != VerdictPass || len(rep.Findings) != 0 || rep.Coverage[0].Status != CoverageOff {
		t.Errorf("off: %s %+v %+v", rep.Verdict, rep.Findings, rep.Coverage)
	}
	raised := DefaultPolicy()
	raised.Detectors["agent_config"] = ActionDeny
	if rep := run(t, raised, nil, change{"M", "AGENTS.md", []string{"x"}}); rep.Verdict != VerdictFail {
		t.Errorf("raise: %s", rep.Verdict)
	}
}

// TestUnknownIsNeverPass: every way the run can be incomplete exits non-zero
// even when nothing was found, and a deny under an incomplete read is
// unknown rather than fail (both exit non-zero).
func TestUnknownIsNeverPass(t *testing.T) {
	clean := change{"A", "a.go", []string{"package a"}}
	n, p := build(clean)
	cases := []struct {
		name string
		req  Request
		dets []Detector
		rule string
	}{
		{"read error", Request{Policy: DefaultPolicy(), ReadErr: errors.New("git failed")}, nil, "read_error"},
		{"truncated", Request{Policy: DefaultPolicy(), NameStatus: n, Patch: p, Truncated: true}, nil, "diff_truncated"},
		{"malformed diff", Request{Policy: DefaultPolicy(), NameStatus: []byte("Q\x00a\x00")}, nil, "read_error"},
		{"invalid policy", Request{Policy: Policy{Mode: "lenient"}, NameStatus: n, Patch: p}, nil, "read_error"},
		{"required detector not in build", Request{Policy: withRequire("install_index"), NameStatus: n, Patch: p}, notBuilt("install_index"), "required_incomplete"},
		{"required detector panics", Request{Policy: DefaultPolicy(), NameStatus: n, Patch: p}, []Detector{{ID: "secrets", Run: func(context.Context, Input) Result { panic("boom") }}}, "required_incomplete"},
		{"required detector reports nothing", Request{Policy: DefaultPolicy(), NameStatus: n, Patch: p}, []Detector{{ID: "secrets", Run: func(context.Context, Input) Result { return Result{} }}}, "required_incomplete"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := Verify(context.Background(), c.req, c.dets)
			if rep.Verdict != VerdictUnknown || rep.Rule != c.rule || rep.Verdict.ExitCode() != ExitUnknown {
				t.Fatalf("got %s/%s exit %d, want unknown/%s", rep.Verdict, rep.Rule, rep.Verdict.ExitCode(), c.rule)
			}
		})
	}
	// A partial read that also found a deny is unknown, not pass.
	big := DefaultPolicy()
	big.MaxFileAddedBytes = 25
	rep := run(t, big, nil, change{"A", "a.go", []string{"k=" + fakeAWSKey, strings.Repeat("z", 40)}})
	if rep.Verdict != VerdictUnknown {
		t.Errorf("partial with deny = %s", rep.Verdict)
	}
}

// notBuilt is the detector table with id's Run removed: every phase's row
// is built now, so tests of the "not in this build" path unbuild one.
func notBuilt(id string) []Detector {
	dets := Detectors()
	for i := range dets {
		if dets[i].ID == id {
			dets[i].Run = nil
		}
	}
	return dets
}

func withRequire(ids ...string) Policy {
	p := DefaultPolicy()
	p.Require = append(p.Require, ids...)
	return p
}

// TestLaterPhaseDetectorPlugsIn shows the seam a later phase's detector
// uses (the phase C rows ci_workflow and test_tampering went through it):
// one table row with a Run function, and its deny fails the check like a
// built detector's.
func TestLaterPhaseDetectorPlugsIn(t *testing.T) {
	dets := Detectors()
	for i := range dets {
		if dets[i].ID == "install_index" {
			dets[i].Run = func(_ context.Context, in Input) Result {
				var out []Finding
				for _, f := range in.Files {
					if strings.HasPrefix(f.Path, ".github/workflows/") {
						out = append(out, Finding{RuleID: "ci/pull-request-target", Detector: "install_index", Category: CategoryMalicious, Severity: SeverityHigh, Confidence: ConfidenceHigh, Path: f.Path, Message: "m", Fingerprint: "f", DefaultAction: ActionDeny})
					}
				}
				return Result{Findings: out, Coverage: Coverage{Status: CoverageComplete, Files: len(in.Files)}}
			}
		}
	}
	rep := run(t, withRequire("install_index"), dets, change{"A", ".github/workflows/x.yml", []string{"on: pull_request_target"}})
	if rep.Verdict != VerdictFail {
		t.Fatalf("verdict %s %s", rep.Verdict, rep.Reason)
	}
	// Without the row wired, the same run reports the detector honestly.
	rep = run(t, DefaultPolicy(), notBuilt("install_index"), change{"A", ".github/workflows/x.yml", []string{"on: pull_request_target"}})
	for _, c := range rep.Coverage {
		if c.Detector == "install_index" && c.Status != CoverageNotInBuild {
			t.Errorf("install_index coverage %s", c.Status)
		}
	}
}

// TestBinaryFilesAreSkippedNotClean: a file the patch shows as binary is
// not read, so a required secrets check is partial and the verdict
// unknown, never a pass. The cmd layer diffs with --text, so a pull
// request's own .gitattributes (-diff, binary) cannot produce this shape
// for a text file; this is the backstop for any patch that still does.
func TestBinaryFilesAreSkippedNotClean(t *testing.T) {
	n := []byte("A\x00img.png\x00")
	p := []byte("diff --git a/img.png b/img.png\nBinary files /dev/null and b/img.png differ\n")
	rep := Verify(context.Background(), Request{Policy: DefaultPolicy(), NameStatus: n, Patch: p}, nil)
	if rep.Verdict != VerdictUnknown {
		t.Fatalf("verdict %s, want unknown", rep.Verdict)
	}
	if c := rep.Coverage[0]; c.Detector != "secrets" || c.Skipped != 1 || c.SkipReason == "" || c.Status != CoveragePartial {
		t.Errorf("coverage %+v", c)
	}
}

func TestDetectorTableIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range Detectors() {
		if seen[d.ID] || d.ID == "" || d.Phase == "" {
			t.Errorf("bad row %+v", d)
		}
		seen[d.ID] = true
	}
}
