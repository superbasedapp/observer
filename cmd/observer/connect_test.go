package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/frontdoor"
	"github.com/marmutapp/superbased-observer/internal/managedconfig"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pairing"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// connectRun records what connect asked its owners to do.
type connectRun struct {
	enrollArgs  []string
	enrollStdin string
	identity    []string
	asked       []string
	enrolled    bool
	// enrollCalls records every attach attempt's args and standard input;
	// enrollErrs, when set, is each attempt's answer in order (nil: ok).
	enrollCalls []connectEnrollCall
	enrollErrs  []error
}

// connectEnrollCall is one attach attempt.
type connectEnrollCall struct {
	args  []string
	stdin string
}

// connectHarness is connect over fakes: env and files are maps, the owners
// record their calls, and the enrolment is whatever the test sets.
type connectHarness struct {
	run     *connectRun
	env     map[string]string
	files   map[string]string
	pol     managedconfig.AttachResult
	enr     *store.Enrolment
	id      frontdoor.Identity
	answer  bool
	enrolTo *store.Enrolment
	// disc, when set, wires the discovery seams (rows 7-9).
	disc *discoveryFake
}

func newConnectHarness() *connectHarness {
	return &connectHarness{run: &connectRun{}, env: map[string]string{}, files: map[string]string{}, id: frontdoor.IdentitySignedOut}
}

func (h *connectHarness) deps() connectDeps {
	d := connectDeps{
		attachPolicy:  func() managedconfig.AttachResult { return h.pol },
		loadEnrolment: func(context.Context, string) (*store.Enrolment, error) { return h.enr, nil },
		identity:      func(string) frontdoor.Identity { return h.id },
		runIdentity: func(_ *cobra.Command, args []string) error {
			h.run.identity = append([]string{"cloud", "login"}, args...)
			h.id = frontdoor.IdentitySignedIn
			return nil
		},
		runEnroll: func(_ *cobra.Command, args []string, stdin io.Reader) error {
			b, _ := io.ReadAll(stdin)
			n := len(h.run.enrollCalls)
			h.run.enrollCalls = append(h.run.enrollCalls, connectEnrollCall{args: args, stdin: string(b)})
			if n < len(h.run.enrollErrs) && h.run.enrollErrs[n] != nil {
				return h.run.enrollErrs[n]
			}
			h.run.enrollArgs, h.run.enrollStdin, h.run.enrolled = args, string(b), true
			if h.enrolTo != nil {
				h.enr = h.enrolTo
			}
			return nil
		},
		getenv: func(k string) string { return h.env[k] },
		readFile: func(p string) ([]byte, error) {
			v, ok := h.files[p]
			if !ok {
				return nil, os.ErrNotExist
			}
			return []byte(v), nil
		},
		confirm: func(cmd *cobra.Command, q string) bool {
			h.run.asked = append(h.run.asked, q)
			fmt.Fprintf(cmd.OutOrStdout(), "%s [y/N] %s\n", q, map[bool]string{true: "y", false: "n"}[h.answer])
			return h.answer
		},
	}
	if h.disc != nil {
		h.disc.wire(&d)
	}
	return d
}

func (h *connectHarness) exec(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newConnectCmdWith(h.deps())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func testPairCode(t *testing.T) string {
	t.Helper()
	c, err := pairing.Format("org-a", "0123456789abcdef0123456789abcdef."+base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func lockedTo(url string) managedconfig.AttachResult {
	return managedconfig.AttachResult{
		Status: managedconfig.AttachStatusValid, Source: "/etc/observer/managed.toml",
		Policy: &managedconfig.AttachPolicy{OrgURL: url, Method: managedconfig.AttachMethodIdP, Locked: true},
	}
}

func enrolledIn(url, name string, managed bool) *store.Enrolment {
	e := &store.Enrolment{OrgID: "org-" + name, OrgName: name, OrgServerURL: url, UserEmail: "dev@" + strings.ToLower(name) + ".example", Tenancy: orgcontract.TenancyIndividual}
	if managed {
		e.Tenancy = orgcontract.TenancyManaged
	}
	return e
}

func TestConnectStatusOnly(t *testing.T) {
	h := newConnectHarness()
	out, err := h.exec(t, "--status")
	if err != nil || strings.TrimSpace(out) != "Local only" {
		t.Fatalf("status = %q (%v)", out, err)
	}
	h.enr, h.id = enrolledIn("https://acme.example", "Acme", true), frontdoor.IdentitySignedIn
	h.pol = lockedTo("https://acme.example")
	out, _ = h.exec(t, "--status")
	if want := "Acme (managed, locked) as dev@acme.example · signed in to superbased"; strings.TrimSpace(out) != want {
		t.Fatalf("status = %q, want %q", out, want)
	}
	if h.run.enrolled || h.run.identity != nil {
		t.Fatal("--status changed something")
	}
}

// TestConnectWithPairingCode: a code from SBO_PAIR_CODE reaches enroll on
// stdin (--token-file -), never in its argv.
func TestConnectWithPairingCode(t *testing.T) {
	h := newConnectHarness()
	code := testPairCode(t)
	h.env[pairing.EnvVar] = code
	h.enrolTo = enrolledIn("https://acme.example", "Acme", true)
	out, err := h.exec(t, "https://acme.example", "--config", "/tmp/c.toml", "--accept-governance")
	if err != nil {
		t.Fatalf("connect: %v\n%s", err, out)
	}
	args := strings.Join(h.run.enrollArgs, " ")
	if !strings.HasPrefix(args, "https://acme.example --token-file - --config /tmp/c.toml") || !strings.Contains(args, "--accept-governance") {
		t.Fatalf("enroll argv = %q", args)
	}
	if strings.Contains(args, code) || strings.Contains(args, "sbp1") {
		t.Fatal("the pairing code is in enroll's argv")
	}
	if strings.TrimSpace(h.run.enrollStdin) != code {
		t.Fatalf("enroll stdin = %q", h.run.enrollStdin)
	}
	if !strings.Contains(out, "Now: Acme (managed) as dev@acme.example") {
		t.Fatalf("no closing sentence: %s", out)
	}
}

func TestConnectWithPairFile(t *testing.T) {
	h := newConnectHarness()
	h.files["/run/code"] = testPairCode(t) + "\n"
	if _, err := h.exec(t, "https://acme.example", "--pair-file", "/run/code"); err != nil {
		t.Fatal(err)
	}
	if h.run.enrollArgs[1] != "--token-file" || strings.TrimSpace(h.run.enrollStdin) != testPairCode(t) {
		t.Fatalf("enroll = %v / %q", h.run.enrollArgs, h.run.enrollStdin)
	}
	// Both sources at once is refused before anything runs.
	h2 := newConnectHarness()
	h2.files["/run/code"], h2.env[pairing.EnvVar] = testPairCode(t), testPairCode(t)
	if _, err := h2.exec(t, "https://acme.example", "--pair-file", "/run/code"); !errors.Is(err, pairing.ErrTwoSources) || h2.run.enrolled {
		t.Fatalf("two sources: %v (enrolled %v)", err, h2.run.enrolled)
	}
}

// TestConnectRefusesACodeOnTheCommandLine: as connect's server argument and
// as enroll's positional token.
func TestConnectRefusesACodeOnTheCommandLine(t *testing.T) {
	h := newConnectHarness()
	if _, err := h.exec(t, testPairCode(t)); !errors.Is(err, pairing.ErrArgument) || h.run.enrolled {
		t.Fatalf("connect <code>: %v", err)
	}
	enroll := newEnrollCmdWith(enrolCmdDeps{
		attachPolicy: func() managedconfig.AttachResult {
			t.Fatal("enroll read the policy before refusing")
			return managedconfig.AttachResult{}
		},
	})
	enroll.SetArgs([]string{"https://acme.example", testPairCode(t)})
	enroll.SetOut(io.Discard)
	enroll.SilenceUsage, enroll.SilenceErrors = true, true
	if err := enroll.ExecuteContext(context.Background()); !errors.Is(err, pairing.ErrArgument) {
		t.Fatalf("enroll <url> <code>: %v", err)
	}
}

// TestConnectWithoutACodeUsesTheDeviceCode: no code means the
// organization's device-code sign-in.
func TestConnectWithoutACodeUsesTheDeviceCode(t *testing.T) {
	h := newConnectHarness()
	if _, err := h.exec(t, "https://acme.example"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.run.enrollArgs[:2], " "); got != "--idp https://acme.example" {
		t.Fatalf("enroll argv = %v", h.run.enrollArgs)
	}
}

// TestConnectIdentityOnly is attachrule row 2: identity changes, the
// destination never does.
func TestConnectIdentityOnly(t *testing.T) {
	h := newConnectHarness()
	h.enr = enrolledIn("https://acme.example", "Acme", true)
	if _, err := h.exec(t, "--identity-only", "--dev-token", "wtok"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.run.identity, " "); got != "cloud login --dev-token wtok" || h.run.enrolled {
		t.Fatalf("identity = %q, enrolled = %v", got, h.run.enrolled)
	}
	if _, err := h.exec(t, "--identity-only", "https://other.example"); err == nil {
		t.Fatal("--identity-only with a server was accepted")
	}
	h.env[pairing.EnvVar] = testPairCode(t)
	if _, err := h.exec(t, "--identity-only"); err == nil {
		t.Fatal("--identity-only with a pairing code was accepted")
	}
	// A locked machine may still sign in (row 1, identity only).
	h2 := newConnectHarness()
	h2.pol = lockedTo("https://acme.example")
	if _, err := h2.exec(t, "--identity-only"); err != nil || h2.run.identity == nil {
		t.Fatalf("locked identity-only: %v", err)
	}
}

// TestConnectLockedMachine is row 1: only the locked destination.
func TestConnectLockedMachine(t *testing.T) {
	h := newConnectHarness()
	h.pol = lockedTo("https://acme.example")
	_, err := h.exec(t, "https://other.example")
	var r *attachPolicyRefusal
	if !errors.As(err, &r) || !errors.Is(err, errManagedAttachRefused) || h.run.enrolled {
		t.Fatalf("locked, elsewhere: %v (enrolled %v)", err, h.run.enrolled)
	}
	if !strings.Contains(err.Error(), "acme.example") {
		t.Fatalf("the refusal does not name the locking org: %v", err)
	}
	// No server: the lock's own destination.
	if _, err := h.exec(t); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.run.enrollArgs[:2], " "); got != "--idp https://acme.example" {
		t.Fatalf("locked, no server: enroll %v", h.run.enrollArgs)
	}
	// An invalid policy refuses every change.
	h2 := newConnectHarness()
	h2.pol = managedconfig.AttachResult{Status: managedconfig.AttachStatusInvalid, Source: "/etc/x", FailedCheck: "owner"}
	if _, err := h2.exec(t, "https://acme.example"); !errors.Is(err, errManagedAttachRefused) || h2.run.enrolled {
		t.Fatalf("invalid policy: %v", err)
	}
}

// TestConnectSwitchFromManagedNeedsConfirmation is row 4: the question
// names the old organization; "no" changes nothing, --yes skips it.
func TestConnectSwitchFromManagedNeedsConfirmation(t *testing.T) {
	h := newConnectHarness()
	h.enr = enrolledIn("https://acme.example", "Acme", true)
	_, err := h.exec(t, "https://other.example")
	if err == nil || h.run.enrolled || len(h.run.asked) != 1 || !strings.Contains(h.run.asked[0], "Acme") {
		t.Fatalf("declined switch: %v, enrolled %v, asked %v", err, h.run.enrolled, h.run.asked)
	}
	h.answer = true
	if _, err := h.exec(t, "https://other.example"); err != nil || !h.run.enrolled {
		t.Fatalf("confirmed switch: %v", err)
	}
	h2 := newConnectHarness()
	h2.enr = enrolledIn("https://acme.example", "Acme", true)
	if _, err := h2.exec(t, "https://other.example", "--yes"); err != nil || !h2.run.enrolled || len(h2.run.asked) != 0 {
		t.Fatalf("--yes switch: %v asked %v", err, h2.run.asked)
	}
}

// TestConnectSwitchFromIndividual is row 6: allowed without a question
// (enroll drains first).
func TestConnectSwitchFromIndividual(t *testing.T) {
	h := newConnectHarness()
	h.enr = enrolledIn("https://acme.example", "Acme", false)
	if _, err := h.exec(t, "https://other.example", "--drop-unsent"); err != nil || len(h.run.asked) != 0 {
		t.Fatalf("individual switch: %v asked %v", err, h.run.asked)
	}
	if !strings.Contains(strings.Join(h.run.enrollArgs, " "), "--drop-unsent") {
		t.Fatalf("--drop-unsent not passed: %v", h.run.enrollArgs)
	}
}

// TestConnectSameDestination is row 10: already connected.
func TestConnectSameDestination(t *testing.T) {
	h := newConnectHarness()
	h.enr = enrolledIn("https://acme.example", "Acme", false)
	if _, err := h.exec(t, "https://acme.example/"); err == nil || !strings.Contains(err.Error(), "already connected") || h.run.enrolled {
		t.Fatalf("same destination: %v", err)
	}
}

// TestConnectWithNoAddress is rows 7-9 in a build without Cloud
// Intelligence (no discovery seams): it asks for the organization's address
// and changes nothing.
func TestConnectWithNoAddress(t *testing.T) {
	h := newConnectHarness()
	out, err := h.exec(t)
	if err != nil || h.run.enrolled || h.run.identity != nil {
		t.Fatalf("no address: %v", err)
	}
	for _, want := range []string{"Local only.", "observer connect https://", pairing.EnvVar, "not in this build"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	// An attached machine with no server named is told to name one.
	h.enr = enrolledIn("https://acme.example", "Acme", false)
	if _, err := h.exec(t); err == nil || h.run.enrolled {
		t.Fatalf("attached, no server: %v", err)
	}
}

func TestReadPairFileRefusesAWorldReadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no permission bits")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "code")
	if err := os.WriteFile(p, []byte(testPairCode(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPairFile(p); err == nil {
		t.Fatal("a world-readable pair file was read")
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readPairFile(p); err != nil || string(b) != testPairCode(t) {
		t.Fatalf("a private pair file: %v", err)
	}
}
