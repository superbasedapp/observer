package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/frontdoor"
	"github.com/marmutapp/superbased-observer/internal/managedconfig"
	"github.com/marmutapp/superbased-observer/internal/pairing"
)

// discoveryFake is the discovery seams over scripted answers: lists[i] is
// the i-th GET /v1/orgs answer (the last repeats), ensure the
// personal:ensure answer.
type discoveryFake struct {
	t        *testing.T
	lists    [][]cloudcontract.DeviceOrg
	listErr  error
	ensure   cloudcontract.EnsurePersonalOrgResponse
	tty      bool
	choice   string
	forbid   bool // any discovery call fails the test (rule 4)
	listed   int
	ensured  int
	slept    int
	asked    []string
	lastOpts connectCloudOpts
}

func (f *discoveryFake) wire(d *connectDeps) {
	d.listOrgs = func(_ context.Context, o connectCloudOpts) (cloudcontract.DeviceOrgList, error) {
		if f.forbid {
			f.t.Fatal("discovery listed organizations although a server or a company pre-set was given")
		}
		f.lastOpts = o
		if f.listErr != nil {
			return cloudcontract.DeviceOrgList{}, f.listErr
		}
		i := f.listed
		if i >= len(f.lists) {
			i = len(f.lists) - 1
		}
		f.listed++
		if i < 0 {
			return cloudcontract.DeviceOrgList{}, nil
		}
		return cloudcontract.DeviceOrgList{Orgs: f.lists[i]}, nil
	}
	d.ensurePersonal = func(context.Context, connectCloudOpts) (cloudcontract.EnsurePersonalOrgResponse, error) {
		if f.forbid {
			f.t.Fatal("discovery ensured a personal organization although a server or a company pre-set was given")
		}
		f.ensured++
		return f.ensure, nil
	}
	d.sleep = func(_ context.Context, dur time.Duration) error {
		if dur != connectPollEvery {
			f.t.Fatalf("poll interval = %s, want %s", dur, connectPollEvery)
		}
		f.slept++
		return nil
	}
	d.isTerminal = func(*cobra.Command) bool { return f.tty }
	d.ask = func(_ *cobra.Command, q string) string {
		f.asked = append(f.asked, q)
		return f.choice
	}
}

func personalOrg(status cloudcontract.DeviceOrgStatus, stage string) cloudcontract.DeviceOrg {
	o := cloudcontract.DeviceOrg{
		OrgID: "org-p", Slug: "u-abcdefgh", DisplayName: "Personal", Kind: cloudcontract.DeviceOrgPersonal,
		Status: status, Tenancy: "individual", Stage: stage,
	}
	if status == cloudcontract.DeviceOrgActive {
		o.ServerURL = "https://u-abcdefgh.superbased.test"
	}
	return o
}

func teamOrg(slug, name string) cloudcontract.DeviceOrg {
	return cloudcontract.DeviceOrg{
		OrgID: "org-" + slug, Slug: slug, DisplayName: name, Kind: cloudcontract.DeviceOrgTeam,
		Status: cloudcontract.DeviceOrgActive, Tenancy: "managed", ServerURL: "https://" + slug + ".superbased.test",
	}
}

func discoveryHarness(t *testing.T, f *discoveryFake) *connectHarness {
	f.t = t
	h := newConnectHarness()
	h.disc = f
	return h
}

// TestConnectDiscoveryRow7OfferOne: signed out, so identity runs first;
// one org is offered with a preview; yes attaches with the organization's
// device code to its own address.
func TestConnectDiscoveryRow7OfferOne(t *testing.T) {
	f := &discoveryFake{lists: [][]cloudcontract.DeviceOrg{{teamOrg("acme", "Acme")}}}
	h := discoveryHarness(t, f)
	h.answer = true
	out, err := h.exec(t, "--base-url", "https://cloud.superbased.test", "--dev-token", "wtok")
	if err != nil {
		t.Fatalf("row 7: %v\n%s", err, out)
	}
	t.Logf("row 7 transcript:\n%s", out)
	if got := strings.Join(h.run.identity, " "); got != "cloud login --base-url https://cloud.superbased.test --dev-token wtok" {
		t.Fatalf("identity = %q", got)
	}
	if f.lastOpts.baseURL != "https://cloud.superbased.test" || f.lastOpts.devToken != "wtok" {
		t.Fatalf("discovery opts = %+v", f.lastOpts)
	}
	if got := strings.Join(h.run.enrollArgs[:2], " "); got != "--idp https://acme.superbased.test" {
		t.Fatalf("enroll argv = %v", h.run.enrollArgs)
	}
	for _, want := range []string{"One dashboard is available to you:", "Acme (team; managed", "This list may be incomplete.", "Is your company's team server missing?", "Connect this machine to Acme?"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if f.ensured != 0 {
		t.Fatal("row 7 created a personal organization")
	}

	// Declined: nothing attached, an error says so.
	f2 := &discoveryFake{lists: f.lists}
	h2 := discoveryHarness(t, f2)
	h2.id = frontdoor.IdentitySignedIn
	if _, err := h2.exec(t); !errors.Is(err, errConnectNotChosen) || h2.run.enrolled || h2.run.identity != nil {
		t.Fatalf("declined row 7: %v enrolled %v identity %v", err, h2.run.enrolled, h2.run.identity)
	}
	// --yes accepts without a question.
	if _, err := h2.exec(t, "--yes"); err != nil || !h2.run.enrolled || len(h2.run.asked) != 1 {
		t.Fatalf("--yes row 7: %v asked %v", err, h2.run.asked)
	}
}

// TestConnectDiscoveryRow8Chooser: several orgs; a terminal picks by number,
// anything else is listed and refused with the way to name one.
func TestConnectDiscoveryRow8Chooser(t *testing.T) {
	orgs := []cloudcontract.DeviceOrg{personalOrg(cloudcontract.DeviceOrgActive, ""), teamOrg("acme", "Acme")}
	f := &discoveryFake{lists: [][]cloudcontract.DeviceOrg{orgs}, tty: true, choice: "2"}
	h := discoveryHarness(t, f)
	h.id = frontdoor.IdentitySignedIn
	out, err := h.exec(t)
	if err != nil {
		t.Fatalf("row 8: %v\n%s", err, out)
	}
	t.Logf("row 8 transcript (choice 2):\n%s", out)
	if h.run.identity != nil {
		t.Fatal("signed in, yet identity ran again")
	}
	if got := strings.Join(h.run.enrollArgs[:2], " "); got != "--idp https://acme.superbased.test" {
		t.Fatalf("enroll argv = %v", h.run.enrollArgs)
	}
	for _, want := range []string{"1) Personal (personal dashboard; individual", "2) Acme (team; managed", "This list may be incomplete."} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if len(f.asked) != 1 || !strings.Contains(f.asked[0], "[1-2]") {
		t.Fatalf("chooser asked %v", f.asked)
	}

	for _, tc := range []struct {
		name, choice string
		tty          bool
		want         string
	}{
		{"not a terminal", "", false, "choose one by its address: observer connect <server_url>"},
		{"cancel", "", true, "nothing changed"},
		{"out of range", "3", true, "is not one of 1-2"},
		{"not a number", "acme", true, "is not one of 1-2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &discoveryFake{lists: [][]cloudcontract.DeviceOrg{orgs}, tty: tc.tty, choice: tc.choice}
			h := discoveryHarness(t, f)
			h.id = frontdoor.IdentitySignedIn
			if _, err := h.exec(t); err == nil || !strings.Contains(err.Error(), tc.want) || h.run.enrolled {
				t.Fatalf("%s: %v (enrolled %v)", tc.name, err, h.run.enrolled)
			}
		})
	}
}

// TestConnectDiscoveryRow9CreatesThePersonalOrg: no orgs; the offer also
// names "Enter its address"; yes ensures the personal org, polls every 3 s
// with the stage word until it is active, then attaches to its address.
func TestConnectDiscoveryRow9CreatesThePersonalOrg(t *testing.T) {
	f := &discoveryFake{
		lists: [][]cloudcontract.DeviceOrg{
			{}, // the first list: no orgs
			{personalOrg(cloudcontract.DeviceOrgProvisioning, "creating")},
			{personalOrg(cloudcontract.DeviceOrgProvisioning, "finishing")},
			{personalOrg(cloudcontract.DeviceOrgActive, "")},
		},
		ensure: cloudcontract.EnsurePersonalOrgResponse{Org: personalOrg(cloudcontract.DeviceOrgProvisioning, "queued"), Created: true},
	}
	h := discoveryHarness(t, f)
	h.answer = true
	h.enrolTo = enrolledIn("https://u-abcdefgh.superbased.test", "Personal", false)
	out, err := h.exec(t)
	if err != nil {
		t.Fatalf("row 9: %v\n%s", err, out)
	}
	t.Logf("row 9 transcript:\n%s", out)
	if f.ensured != 1 || f.slept != 3 {
		t.Fatalf("ensured %d, slept %d (want 1, 3)", f.ensured, f.slept)
	}
	if got := strings.Join(h.run.enrollArgs[:2], " "); got != "--idp https://u-abcdefgh.superbased.test" {
		t.Fatalf("enroll argv = %v", h.run.enrollArgs)
	}
	for _, want := range []string{
		"No dashboards are listed for your superbased sign-in.",
		"Is your company's team server missing? Enter its address: observer connect <url>",
		"Create your personal dashboard",
		"Created your personal dashboard.",
		"Waiting for Personal to be ready: queued",
		"Waiting for Personal to be ready: creating",
		"Waiting for Personal to be ready: finishing",
		"Connecting this machine to Personal.",
		"Now: Personal",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	// The tenancy flag is never chosen by the node: enroll is given none.
	if strings.Contains(strings.Join(h.run.enrollArgs, " "), "tenancy") {
		t.Fatalf("connect chose a tenancy: %v", h.run.enrollArgs)
	}
}

// TestConnectDiscoveryRow9Outcomes covers the wait's other ends.
func TestConnectDiscoveryRow9Outcomes(t *testing.T) {
	waitlisted := personalOrg(cloudcontract.DeviceOrgProvisioning, "waitlisted")
	for _, tc := range []struct {
		name      string
		ensure    cloudcontract.DeviceOrg
		later     []cloudcontract.DeviceOrg
		wantErr   string // "" = success with nothing attached
		wantOut   string
		wantSlept int
	}{
		{"waitlisted exits 0", waitlisted, nil, "", "will be created when there is room", 0},
		{"waitlisted later", personalOrg(cloudcontract.DeviceOrgProvisioning, "queued"), []cloudcontract.DeviceOrg{waitlisted}, "", "run `observer connect` again later", 1},
		{"failed", personalOrg(cloudcontract.DeviceOrgProvisioning, "failed"), nil, "creating Personal failed", "", 0},
		{"suspended", personalOrg(cloudcontract.DeviceOrgSuspended, ""), nil, "is suspended and cannot take a machine", "", 0},
		{"active without an address", cloudcontract.DeviceOrg{OrgID: "org-p", Slug: "u-abcdefgh", DisplayName: "Personal", Kind: cloudcontract.DeviceOrgPersonal, Status: cloudcontract.DeviceOrgActive, Tenancy: "individual"}, nil, "has no address yet", "", 0},
		{"timeout", personalOrg(cloudcontract.DeviceOrgProvisioning, "creating"), []cloudcontract.DeviceOrg{personalOrg(cloudcontract.DeviceOrgProvisioning, "creating")}, "still creating after 3m0s", "", int(connectPollFor / connectPollEvery)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lists := [][]cloudcontract.DeviceOrg{{}}
			if tc.later != nil {
				lists = append(lists, tc.later)
			}
			f := &discoveryFake{lists: lists, ensure: cloudcontract.EnsurePersonalOrgResponse{Org: tc.ensure}}
			h := discoveryHarness(t, f)
			h.id = frontdoor.IdentitySignedIn
			out, err := h.exec(t, "--yes")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("%v\n%s", err, out)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if tc.wantOut != "" && !strings.Contains(out, tc.wantOut) {
				t.Fatalf("output lacks %q:\n%s", tc.wantOut, out)
			}
			if h.run.enrolled || f.slept != tc.wantSlept {
				t.Fatalf("enrolled %v slept %d (want false, %d)", h.run.enrolled, f.slept, tc.wantSlept)
			}
			if !strings.Contains(out, "Your personal dashboard already exists.") {
				t.Fatalf("an existing org was not named as existing:\n%s", out)
			}
		})
	}
}

// TestConnectNeverDiscoversWithAnAddress is rule 4: with a server argument,
// a company pre-set or a lock, SuperBased is never asked for the list (an
// air-gapped private enrolment never touches discovery).
func TestConnectNeverDiscoversWithAnAddress(t *testing.T) {
	preset := managedconfig.AttachResult{
		Status: managedconfig.AttachStatusValid, Source: "/etc/observer/managed.toml",
		Policy: &managedconfig.AttachPolicy{OrgURL: "https://private.example", Method: managedconfig.AttachMethodIdP},
	}
	for _, tc := range []struct {
		name string
		pol  managedconfig.AttachResult
		args []string
		want string
	}{
		{"server argument", managedconfig.AttachResult{}, []string{"https://private.example"}, "https://private.example"},
		{"company pre-set", preset, nil, "https://private.example"},
		{"company lock", lockedTo("https://private.example"), nil, "https://private.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &discoveryFake{forbid: true}
			h := discoveryHarness(t, f)
			h.pol = tc.pol
			if _, err := h.exec(t, tc.args...); err != nil {
				t.Fatal(err)
			}
			if got := h.run.enrollArgs[1]; got != tc.want || f.listed != 0 || f.ensured != 0 || h.run.identity != nil {
				t.Fatalf("enroll %v listed %d ensured %d identity %v", h.run.enrollArgs, f.listed, f.ensured, h.run.identity)
			}
		})
	}
}

// TestConnectDiscoveryRefusals: an attached machine (row 11, and row 5's
// managed machine) is never offered the personal org, a pairing code needs
// its organization's address, and a list failure says how to go on.
func TestConnectDiscoveryRefusals(t *testing.T) {
	f := &discoveryFake{forbid: true}
	h := discoveryHarness(t, f)
	h.enr = enrolledIn("https://acme.example", "Acme", true)
	if _, err := h.exec(t); err == nil || h.run.enrolled {
		t.Fatalf("managed machine, no address: %v", err)
	}

	h2 := discoveryHarness(t, &discoveryFake{forbid: true})
	h2.env[pairing.EnvVar] = testPairCode(t)
	if _, err := h2.exec(t); err == nil || !strings.Contains(err.Error(), "give its server address too") || h2.run.enrolled {
		t.Fatalf("pairing code, no address: %v", err)
	}

	f3 := &discoveryFake{listErr: errors.New("cloudgateway: no base URL")}
	h3 := discoveryHarness(t, f3)
	h3.id = frontdoor.IdentitySignedIn
	if _, err := h3.exec(t); err == nil || !strings.Contains(err.Error(), "observer connect <server>") || h3.run.enrolled {
		t.Fatalf("list failure: %v", err)
	}
}

// TestConnectAttachableOrgs: only active and provisioning orgs are offered;
// the rest are counted.
func TestConnectAttachableOrgs(t *testing.T) {
	keep, hidden := connectAttachableOrgs([]cloudcontract.DeviceOrg{
		personalOrg(cloudcontract.DeviceOrgActive, ""),
		personalOrg(cloudcontract.DeviceOrgProvisioning, "queued"),
		personalOrg(cloudcontract.DeviceOrgSuspended, ""),
		personalOrg(cloudcontract.DeviceOrgPurged, ""),
	})
	if len(keep) != 2 || hidden != 2 {
		t.Fatalf("keep %d hidden %d", len(keep), hidden)
	}
}
