package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/attachrule"
	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/frontdoor"
	"github.com/marmutapp/superbased-observer/internal/managedconfig"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// connect_discover.go is `observer connect` with no address (managed SaaS
// plan 06 section 19.3 rows 7-9; plan 07 M8.4 and M8.7): identity first,
// then the organizations the signed-in account belongs to, then
// internal/attachrule's decision over them (offer one, choose, or create the
// personal org), then the existing attach owner (`observer enroll`) against
// the chosen organization's own address.
//
// The two discovery calls ride the existing cloud lanes through the consent
// gateway's Bootstrap family (connect_discover_cloud.go; design decision
// D-IND-2, ledger row IND-2). They are reached only from here, only when
// connect was given no server and company configuration pre-sets none
// (planConnect decides that before anything else runs), so an air-gapped
// private enrolment never touches them (rule 4). A build without Cloud
// Intelligence has no seams (connect_discover_cloud_omit.go) and asks for the
// organization's address instead.
//
// Tenancy is never chosen here: the tenant decides it from the org's kind
// (rule 6), so a personal org yields an individual enrolment.

// connectCloudOpts is what the discovery seams need to reach the cloud: the
// same --config, --base-url and --dev-token `observer cloud login` takes.
type connectCloudOpts struct {
	configPath string
	baseURL    string
	devToken   string
}

// connectDiscovery is the pair of discovery seams; both nil in a build
// without Cloud Intelligence.
type connectDiscovery struct {
	listOrgs       func(ctx context.Context, o connectCloudOpts) (cloudcontract.DeviceOrgList, error)
	ensurePersonal func(ctx context.Context, o connectCloudOpts) (cloudcontract.EnsurePersonalOrgResponse, error)
}

// Waiting for a new org to be ready: poll every connectPollEvery, at most
// connectPollFor.
const (
	connectPollEvery = 3 * time.Second
	connectPollFor   = 3 * time.Minute
)

// The provisioning stages that end the wait without an org to attach to.
const (
	connectStageWaitlisted = "waitlisted"
	connectStageFailed     = "failed"
)

// connectEnterAddress is row 9's second offer, also printed under every list
// because the list may be incomplete.
const connectEnterAddress = "Is your company's team server missing? Enter its address: observer connect <url>"

// errConnectNotChosen is a discovery offer the user did not take.
var errConnectNotChosen = errors.New("observer connect: not attached; nothing changed")

// connectDiscoveryAvailable reports whether this build can find
// organizations from the SuperBased sign-in.
func connectDiscoveryAvailable(deps connectDeps) bool {
	return deps.listOrgs != nil && deps.ensurePersonal != nil
}

// runConnectDiscovery runs rows 7-9 and returns the chosen organization's
// address, or "" (with a nil error) when there is nothing to attach to yet
// (a waitlisted org). It is called only after planConnect returned
// errConnectNeedsAddress: no server, no company pre-set, no destination.
func runConnectDiscovery(cmd *cobra.Command, deps connectDeps, f connectFlags, pol managedconfig.AttachResult, enr *store.Enrolment) (string, error) {
	out := cmd.OutOrStdout()
	ctx := cmd.Context()
	opts := connectCloudOpts{configPath: f.configPath, baseURL: f.baseURL, devToken: f.devToken}

	if deps.identity(f.configPath) != frontdoor.IdentitySignedIn {
		fmt.Fprintln(out, "Finding your dashboards needs your SuperBased sign-in first (signing in never moves data).")
		if err := deps.runIdentity(cmd, connectIdentityArgs(f)); err != nil {
			return "", fmt.Errorf("observer connect: sign in to SuperBased: %w", err)
		}
	}
	list, err := deps.listOrgs(ctx, opts)
	if err != nil {
		return "", fmt.Errorf("observer connect: list your dashboards: %w (or give the address: observer connect <server>)", err)
	}
	listed, hidden := connectAttachableOrgs(list.Orgs)

	in := attachrule.Input{Current: currentDestination(enr), Lock: pol.Lock(), Intent: attachrule.IntentAttach}
	for _, o := range listed {
		in.Listed = append(in.Listed, connectOrgDestination(o))
	}
	d := attachrule.Decide(in)

	var org cloudcontract.DeviceOrg
	switch d.Outcome {
	case attachrule.OutcomeOfferOne:
		org = listed[0]
		fmt.Fprintln(out, "One dashboard is available to you:")
		fmt.Fprintln(out, "  "+connectOrgLine(org))
		printConnectListFooter(out, hidden)
		if !f.yes && !deps.confirm(cmd, "Connect this machine to "+connectOrgName(org)+"? Only activity from now on is sent there; earlier sessions stay on this machine.") {
			return "", fmt.Errorf("%w (pass --yes to accept without a prompt)", errConnectNotChosen)
		}
	case attachrule.OutcomeShowChooser:
		fmt.Fprintln(out, "Several dashboards are available to you:")
		for i, o := range listed {
			fmt.Fprintf(out, "  %d) %s\n", i+1, connectOrgLine(o))
		}
		printConnectListFooter(out, hidden)
		if !deps.isTerminal(cmd) {
			return "", errors.New("observer connect: several dashboards are available; choose one by its address: observer connect <server_url>")
		}
		pick, err := connectChoose(deps.ask(cmd, fmt.Sprintf("Choose one [1-%d], or press Enter to cancel:", len(listed))), len(listed))
		if err != nil {
			return "", err
		}
		org = listed[pick]
		fmt.Fprintln(out, "Only activity from now on is sent to "+connectOrgName(org)+"; earlier sessions stay on this machine.")
	case attachrule.OutcomeOfferCreatePersonal:
		fmt.Fprintln(out, "No dashboards are listed for your SuperBased sign-in.")
		if hidden > 0 {
			fmt.Fprintf(out, "(%d dashboard(s) not shown: suspended or being deleted.)\n", hidden)
		}
		fmt.Fprintln(out, connectEnterAddress)
		if !f.yes && !deps.confirm(cmd, "Create your personal dashboard and connect this machine to it? It is yours alone, and this machine sends a summary only (no prompts or file contents unless you choose to share them).") {
			return "", fmt.Errorf("%w (pass --yes to accept without a prompt)", errConnectNotChosen)
		}
		ens, err := deps.ensurePersonal(ctx, opts)
		if err != nil {
			return "", fmt.Errorf("observer connect: create your personal dashboard: %w", err)
		}
		org = ens.Org
		if ens.Created {
			fmt.Fprintln(out, "Created your personal dashboard.")
		} else {
			fmt.Fprintln(out, "Your personal dashboard already exists.")
		}
	default:
		return "", connectRefusal(pol, d, "")
	}

	ready, err := waitForConnectOrg(cmd, deps, opts, org, out)
	if err != nil || ready.ServerURL == "" {
		return "", err
	}
	// Belt: the same table, now with the destination named (row 5 keeps a
	// managed machine off the personal org; rows 7-9 only run with none).
	in.Listed, in.Requested = nil, connectOrgDestination(ready)
	if d := attachrule.Decide(in); d.Outcome != attachrule.OutcomeAllow {
		return "", connectRefusal(pol, d, ready.ServerURL)
	}
	fmt.Fprintf(out, "Connecting this machine to %s%s.\n", connectOrgName(ready), connectWhere(ready))
	return ready.ServerURL, nil
}

// waitForConnectOrg returns org once it is active with an address, polling
// the list every connectPollEvery for at most connectPollFor and printing the
// stage word each time it changes. A waitlisted org returns a zero org and a
// nil error (it will be created when there is room); a failed, suspended or
// deleted one, or a timeout, is an error. Progress lines go to out.
func waitForConnectOrg(cmd *cobra.Command, deps connectDeps, opts connectCloudOpts, org cloudcontract.DeviceOrg, out io.Writer) (cloudcontract.DeviceOrg, error) {
	name := connectOrgName(org)
	lastStage := ""
	for poll := 0; ; poll++ {
		switch org.Status {
		case cloudcontract.DeviceOrgActive:
			if org.ServerURL == "" {
				return cloudcontract.DeviceOrg{}, fmt.Errorf("observer connect: %s is active but has no address yet; ask for its address and run observer connect <url>", name)
			}
			return org, nil
		case cloudcontract.DeviceOrgProvisioning:
		default:
			return cloudcontract.DeviceOrg{}, fmt.Errorf("observer connect: %s is %s and cannot take a machine", name, strings.ReplaceAll(string(org.Status), "_", " "))
		}
		stage := org.Stage
		if stage == "" {
			stage = "unknown"
		}
		switch stage {
		case connectStageWaitlisted:
			fmt.Fprintf(out, "%s is waitlisted: it will be created when there is room. Nothing is attached yet; run `observer connect` again later to finish.\n", name)
			return cloudcontract.DeviceOrg{}, nil
		case connectStageFailed:
			return cloudcontract.DeviceOrg{}, fmt.Errorf("observer connect: creating %s failed; run `observer connect` again later", name)
		}
		if stage != lastStage {
			fmt.Fprintf(out, "Waiting for %s to be ready: %s\n", name, stage)
			lastStage = stage
		}
		if time.Duration(poll+1)*connectPollEvery > connectPollFor {
			return cloudcontract.DeviceOrg{}, fmt.Errorf("observer connect: %s is still %s after %s; run `observer connect` again to finish attaching", name, stage, connectPollFor)
		}
		if err := deps.sleep(cmd.Context(), connectPollEvery); err != nil {
			return cloudcontract.DeviceOrg{}, err
		}
		list, err := deps.listOrgs(cmd.Context(), opts)
		if err != nil {
			return cloudcontract.DeviceOrg{}, fmt.Errorf("observer connect: check on %s: %w", name, err)
		}
		for _, o := range list.Orgs {
			if o.OrgID == org.OrgID {
				org = o
				break
			}
		}
	}
}

// connectAttachableOrgs keeps the orgs a machine could attach to now or once
// created (active or provisioning), in the service's order (personal first),
// and counts the others.
func connectAttachableOrgs(orgs []cloudcontract.DeviceOrg) ([]cloudcontract.DeviceOrg, int) {
	var keep []cloudcontract.DeviceOrg
	hidden := 0
	for _, o := range orgs {
		if o.Status == cloudcontract.DeviceOrgActive || o.Status == cloudcontract.DeviceOrgProvisioning {
			keep = append(keep, o)
		} else {
			hidden++
		}
	}
	return keep, hidden
}

// connectOrgDestination is attachrule's view of a listed org.
func connectOrgDestination(o cloudcontract.DeviceOrg) attachrule.Destination {
	d := attachrule.Destination{Kind: attachrule.KindTeamOrg, OrgID: o.OrgID, Name: connectOrgName(o)}
	if o.Kind == cloudcontract.DeviceOrgPersonal {
		d.Kind = attachrule.KindPersonal
	}
	if o.Tenancy == "managed" {
		d.Tenancy = attachrule.TenancyManaged
	}
	return d
}

// connectOrgName is the org's display name, else its slug.
func connectOrgName(o cloudcontract.DeviceOrg) string {
	if n := strings.TrimSpace(o.DisplayName); n != "" {
		return n
	}
	if o.Kind == cloudcontract.DeviceOrgPersonal {
		// Decision 2: a personal dashboard's own u-... slug is never shown.
		return "your personal dashboard"
	}
	return o.Slug
}

// connectWhere is " (<server address>)" for a team and "" for a personal
// dashboard, whose own host is never printed (it opens from
// cloud.superbased.app).
func connectWhere(o cloudcontract.DeviceOrg) string {
	if o.Kind == cloudcontract.DeviceOrgPersonal || o.ServerURL == "" {
		return ""
	}
	return " (" + o.ServerURL + ")"
}

// connectKindLabel names a dashboard kind in the five words.
func connectKindLabel(kind cloudcontract.DeviceOrgKind) string {
	if kind == cloudcontract.DeviceOrgPersonal {
		return "personal dashboard"
	}
	return "team"
}

// connectOrgLine is the preview of one org: name, kind and tenancy, and its
// address or its provisioning stage.
func connectOrgLine(o cloudcontract.DeviceOrg) string {
	tenancy := "individual: metadata only unless you choose to share content"
	if o.Tenancy == "managed" {
		tenancy = "managed: the team's policy applies to this machine"
	}
	where := o.ServerURL
	if o.Kind == cloudcontract.DeviceOrgPersonal {
		where = "opens from cloud.superbased.app"
	}
	if o.Status != cloudcontract.DeviceOrgActive || o.ServerURL == "" {
		stage := o.Stage
		if stage == "" {
			stage = string(o.Status)
		}
		where = "being created (" + stage + ")"
	}
	return fmt.Sprintf("%s (%s; %s) · %s", connectOrgName(o), connectKindLabel(o.Kind), tenancy, where)
}

// printConnectListFooter says the list may be incomplete (rule 3's chooser
// note) and how to reach an org it lacks.
func printConnectListFooter(out io.Writer, hidden int) {
	if hidden > 0 {
		fmt.Fprintf(out, "(%d dashboard(s) not shown: suspended or being deleted.)\n", hidden)
	}
	fmt.Fprintln(out, "This list may be incomplete. "+connectEnterAddress)
}

// connectChoose parses the chooser's answer: 1..n picks, empty cancels.
func connectChoose(answer string, n int) (int, error) {
	a := strings.TrimSpace(answer)
	if a == "" {
		return 0, errConnectNotChosen
	}
	i, err := strconv.Atoi(a)
	if err != nil || i < 1 || i > n {
		return 0, fmt.Errorf("observer connect: %q is not one of 1-%d; nothing changed", a, n)
	}
	return i - 1, nil
}

// connectSleep waits d or until ctx ends.
func connectSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// askOnTTY prints question and reads one line from cmd's input; a closed
// input is an empty answer (cancel).
func askOnTTY(cmd *cobra.Command, question string) string {
	fmt.Fprintf(cmd.OutOrStdout(), "%s ", question)
	line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n') //nolint:errcheck // a closed input is an empty answer
	return strings.TrimSpace(line)
}
