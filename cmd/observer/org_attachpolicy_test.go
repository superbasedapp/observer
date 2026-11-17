package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/attachrule"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/managedconfig"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// M8.6: the company-managed attach policy at the node's attach and detach
// entry points.

const (
	attachTestSource = "/etc/superbased/managed.toml"
	attachTestAcme   = "https://observer.acme.example"
	attachTestOther  = "https://observer.other.example"
)

func attachPolicyFor(url string, locked bool) managedconfig.AttachResult {
	return managedconfig.AttachResult{
		Status: managedconfig.AttachStatusValid, Source: attachTestSource,
		Policy: &managedconfig.AttachPolicy{OrgURL: url, Method: managedconfig.AttachMethodIdP, Locked: locked},
	}
}

func attachPolicyNone() managedconfig.AttachResult {
	return managedconfig.AttachResult{Status: managedconfig.AttachStatusNone}
}

func attachPolicyInvalid() managedconfig.AttachResult {
	return managedconfig.AttachResult{Status: managedconfig.AttachStatusInvalid, Source: attachTestSource, FailedCheck: "group_or_world_writable"}
}

// TestCheckManagedAttach: one row per policy shape and intent.
func TestCheckManagedAttach(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		pol     managedconfig.AttachResult
		intent  attachrule.Intent
		request string
		want    []string // substrings of the refusal; nil = allowed
	}{
		{name: "no policy: attach", pol: attachPolicyNone(), intent: attachrule.IntentAttach, request: attachTestOther},
		{name: "no policy: leave", pol: attachPolicyNone(), intent: attachrule.IntentDisconnect},
		{name: "unlocked: attach elsewhere is a default, not a refusal", pol: attachPolicyFor(attachTestAcme, false), intent: attachrule.IntentAttach, request: attachTestOther},
		{name: "unlocked: leave", pol: attachPolicyFor(attachTestAcme, false), intent: attachrule.IntentDisconnect},
		{name: "locked: the locked org", pol: attachPolicyFor(attachTestAcme, true), intent: attachrule.IntentAttach, request: "HTTPS://observer.ACME.example:443/"},
		{
			name: "locked: another org", pol: attachPolicyFor(attachTestAcme, true), intent: attachrule.IntentAttach, request: attachTestOther,
			want: []string{
				"refused by company-managed configuration (" + attachTestSource + ")", "locked to observer.acme.example",
				"cannot enrol with " + attachTestOther, "administrator who manages " + attachTestSource,
			},
		},
		{
			name: "locked: the same host over http", pol: attachPolicyFor(attachTestAcme, true), intent: attachrule.IntentAttach, request: "http://observer.acme.example",
			want: []string{"cannot enrol with http://observer.acme.example"},
		},
		{
			name: "locked: leave", pol: attachPolicyFor(attachTestAcme, true), intent: attachrule.IntentDisconnect,
			want: []string{"locked to observer.acme.example and cannot leave it", attachTestSource},
		},
		{
			name: "invalid source: attach", pol: attachPolicyInvalid(), intent: attachrule.IntentAttach, request: attachTestAcme,
			want: []string{"failed a check (group_or_world_writable)", "enrolling and leaving are refused"},
		},
		{name: "invalid source: leave", pol: attachPolicyInvalid(), intent: attachrule.IntentDisconnect, want: []string{"failed a check (group_or_world_writable)"}},
	}
	for _, tc := range cases {
		err := checkManagedAttach(tc.pol, attachrule.Destination{}, tc.intent, tc.request)
		if tc.want == nil {
			if err != nil {
				t.Errorf("%s: refused: %v", tc.name, err)
			}
			continue
		}
		var ref *attachPolicyRefusal
		if !errors.As(err, &ref) || !errors.Is(err, errManagedAttachRefused) {
			t.Errorf("%s: err = %v, want an *attachPolicyRefusal", tc.name, err)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q does not say %q", tc.name, err, w)
			}
		}
	}
}

func TestManagedEnrolDefaultIdP(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		pol  managedconfig.AttachResult
		want string
	}{
		"no policy": {pol: attachPolicyNone()},
		"invalid":   {pol: attachPolicyInvalid()},
		"unlocked":  {pol: attachPolicyFor(attachTestAcme, false), want: attachTestAcme},
		"locked":    {pol: attachPolicyFor(attachTestAcme, true), want: attachTestAcme},
	} {
		if got := managedEnrolDefaultIdP(tc.pol); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

// guardedDeps are seams that fail the test when the command gets past the
// policy check to the bundle or the sign-in.
func guardedDeps(t *testing.T, pol managedconfig.AttachResult) enrolCmdDeps {
	t.Helper()
	return enrolCmdDeps{
		attachPolicy: func() managedconfig.AttachResult { return pol },
		bundle: func(context.Context, string) (orgBundle, error) {
			t.Error("the org bundle was opened: the refusal must come first")
			return orgBundle{}, errors.New("no bundle in this test")
		},
		idpFlow: func(*orgclient.Client, io.Writer) *idpEnrolFlow {
			t.Error("the sign-in flow was built: the refusal must come first")
			return nil
		},
	}
}

// runAttachCmd runs a freshly built command with args, no terminal on stdin.
func runAttachCmd(cmdArgs []string, build func() *cobra.Command) (string, error) {
	cmd := build()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs(cmdArgs)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// TestEnrollCmdLockedRefusesAnotherOrg: a locked machine refuses `observer
// enroll` to any other server, by every credential form, before the bundle
// or a sign-in.
func TestEnrollCmdLockedRefusesAnotherOrg(t *testing.T) {
	t.Parallel()
	for name, args := range map[string][]string{
		"positional pair": {attachTestOther, "tok_id.secret"},
		"magic link":      {"--link", attachTestOther + "/enrol/tok_id.secret"},
		"idp":             {"--idp", attachTestOther},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			deps := guardedDeps(t, attachPolicyFor(attachTestAcme, true))
			_, err := runAttachCmd(args, func() *cobra.Command { return newEnrollCmdWith(deps) })
			var ref *attachPolicyRefusal
			if !errors.As(err, &ref) || !strings.Contains(err.Error(), "locked to observer.acme.example") {
				t.Fatalf("err = %v, want the lock refusal", err)
			}
		})
	}
}

// TestUnenrollCmdLockedRefusesLeave: a locked, enrolled machine refuses
// `observer unenroll` and stays enrolled; --plan still prints. With no
// managed config the same machine leaves as before.
func TestUnenrollCmdLockedRefusesLeave(t *testing.T) {
	// Not parallel: enrolSequenceBundle sets HOME and USERPROFILE.
	org := newEnrolFakeOrg(t, orgcontract.TenancyManaged, nil)
	b, cfgPath := enrolSequenceBundle(t, "[observer]\nlog_level = \"warn\"\n")
	b.attachPolicy = attachPolicyNone
	if _, err := runEnrolSequence(context.Background(), b, cfgPath, org.url, idpTestEnrolCode, true, false); err != nil {
		t.Fatalf("enrol: %v", err)
	}
	deps := enrolCmdDeps{
		attachPolicy: func() managedconfig.AttachResult { return attachPolicyFor(attachTestAcme, true) },
		bundle:       func(context.Context, string) (orgBundle, error) { return b, nil },
	}
	build := func() *cobra.Command { return newUnenrollCmdWith(deps) }

	out, err := runAttachCmd([]string{"--config", cfgPath, "--plan"}, build)
	if err != nil || out == "" {
		t.Fatalf("--plan on a locked machine = (%q, %v), want the plan", out, err)
	}
	_, err = runAttachCmd([]string{"--config", cfgPath}, build)
	if !errors.Is(err, errManagedAttachRefused) || !strings.Contains(err.Error(), "cannot leave it") {
		t.Fatalf("unenroll on a locked machine: %v, want the lock refusal", err)
	}
	if enr, lerr := b.store.LoadEnrolment(context.Background()); lerr != nil || enr == nil {
		t.Fatalf("the refused leave removed the enrolment (%v, %v)", enr, lerr)
	}

	deps.attachPolicy = attachPolicyNone
	if _, err := runAttachCmd([]string{"--config", cfgPath}, build); err != nil {
		t.Fatalf("unenroll with no managed config: %v", err)
	}
	if enr, _ := b.store.LoadEnrolment(context.Background()); enr != nil {
		t.Fatal("with no managed config the machine did not leave")
	}
}

// TestRunEnrolSequenceLockedRefusesAnotherOrg: the shared enrol core (CLI and
// dashboard) refuses before the code is spent.
func TestRunEnrolSequenceLockedRefusesAnotherOrg(t *testing.T) {
	// Not parallel: enrolSequenceBundle sets HOME and USERPROFILE.
	org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, nil)
	b, cfgPath := enrolSequenceBundle(t, "[observer]\n")
	b.attachPolicy = func() managedconfig.AttachResult { return attachPolicyFor(attachTestAcme, true) }
	_, err := runEnrolSequence(context.Background(), b, cfgPath, org.url, idpTestEnrolCode, true, false)
	if !errors.Is(err, errManagedAttachRefused) || org.enrolCalls != 0 {
		t.Fatalf("err = %v after %d enrol calls, want the lock refusal and none", err, org.enrolCalls)
	}
	b.attachPolicy = attachPolicyInvalid
	if _, err := runEnrolSequence(context.Background(), b, cfgPath, org.url, idpTestEnrolCode, true, false); !errors.Is(err, errManagedAttachRefused) {
		t.Fatalf("invalid source: %v, want a refusal", err)
	}
}

// TestEnrollCmdManagedURLIsTheDefault: a bare `observer enroll` on a machine
// whose company config sets the org URL signs in there (idp) and enrols;
// unlocked and locked alike. With no managed config the bare command is the
// same usage error as before.
func TestEnrollCmdManagedURLIsTheDefault(t *testing.T) {
	// Not parallel: enrolSequenceBundle sets HOME and USERPROFILE.
	for _, locked := range []bool{false, true} {
		org := newIdPFakeOrg(t, 0)
		srv := httptest.NewTLSServer(http.HandlerFunc(org.route))
		t.Cleanup(srv.Close)
		org.url = srv.URL
		managedURL, err := managedconfig.CanonicalOrgURL(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		b, cfgPath := enrolSequenceBundle(t, "[observer]\nlog_level = \"warn\"\n")
		b.client = orgclient.New(config.OrgClientConfig{
			Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
			MaxPushBytes: config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
		}, b.store, &idpMemBearerStore{}, "test-version", srv.Client(), newLogger("error"))
		deps := enrolCmdDeps{
			attachPolicy: func() managedconfig.AttachResult { return attachPolicyFor(managedURL, locked) },
			bundle:       func(context.Context, string) (orgBundle, error) { return b, nil },
			idpFlow: func(c *orgclient.Client, out io.Writer) *idpEnrolFlow {
				return &idpEnrolFlow{client: c, out: out, sleep: func(time.Duration) {}, open: func(string) {}}
			},
		}
		out, err := runAttachCmd([]string{"--config", cfgPath, "--wire-clients=false"},
			func() *cobra.Command { return newEnrollCmdWith(deps) })
		if err != nil {
			t.Fatalf("locked=%v: bare enroll: %v\n%s", locked, err, out)
		}
		if !strings.Contains(out, "Enrolling with "+managedURL+", set by company-managed configuration ("+attachTestSource+")") {
			t.Fatalf("locked=%v: the output does not name the managed default:\n%s", locked, out)
		}
		enr, err := b.store.LoadEnrolment(context.Background())
		if err != nil || enr == nil || orgclient.NormalizeOrgURL(enr.OrgServerURL) != srv.URL {
			t.Fatalf("locked=%v: enrolment = %+v (%v), want one at %s", locked, enr, err, srv.URL)
		}
	}

	deps := guardedDeps(t, attachPolicyNone())
	_, err := runAttachCmd(nil, func() *cobra.Command { return newEnrollCmdWith(deps) })
	if err == nil || !strings.Contains(err.Error(), "supply --link <url> OR positional <org-url> <token>") {
		t.Fatalf("bare enroll with no managed config: %v, want today's usage error", err)
	}
}
