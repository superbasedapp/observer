package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/marmutapp/superbased-observer/internal/attachrule"
	"github.com/marmutapp/superbased-observer/internal/managedconfig"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Company-managed attach policy at the node's attach and detach entry points
// (plan 06 section 19.3 rule 2 way 3 and rule 3 row 1; plan 07 M8.6). The
// policy is read by internal/managedconfig and decided by internal/attachrule;
// this file only builds attachrule's input and turns a refusal into a typed
// error. Where it is enforced:
//
//   - runEnrolSequence (orgenrol_core.go): every enrolment, CLI and dashboard;
//   - performUnenrol (orgreport.go): every leave, CLI and dashboard;
//   - `observer enroll` before the --idp sign-in, and the dashboard's
//     StartIdP, so a refusal never costs a browser approval.
//
// Only the lock refuses here. An unlocked managed URL is a default (a bare
// `observer enroll` uses it), and the rest of the precedence table (rows
// 2-10) is wired by the connect work (M8.4), so a machine with no lock
// behaves exactly as before.

// errManagedAttachRefused is the sentinel every *attachPolicyRefusal unwraps
// to.
var errManagedAttachRefused = errors.New("refused by company-managed configuration")

// attachPolicyRefusal is a destination change the company-managed attach
// policy refuses. It names the managing policy.
type attachPolicyRefusal struct {
	intent attachrule.Intent
	// source is the managing policy (a path or the registry key).
	source string
	// lockOrg and askWho come from attachrule's row-1 refusal.
	lockOrg, askWho string
	// requested is the server an attach asked for.
	requested string
	// failedCheck and detail are set when the policy source failed a check.
	failedCheck, detail string
}

func (e *attachPolicyRefusal) Error() string {
	head := fmt.Sprintf("%v (%s)", errManagedAttachRefused, e.source)
	if e.failedCheck != "" {
		check := e.failedCheck
		if e.detail != "" {
			check += ": " + e.detail
		}
		return fmt.Sprintf("%s: the policy exists but failed a check (%s), so whether this machine is locked to an organization cannot be known; enrolling and leaving are refused until an administrator fixes it", head, check)
	}
	if e.intent == attachrule.IntentDisconnect {
		return fmt.Sprintf("%s: this machine is locked to %s and cannot leave it; ask %s to change it", head, e.lockOrg, e.askWho)
	}
	return fmt.Sprintf("%s: this machine is locked to %s and cannot enrol with %s; ask %s to change it", head, e.lockOrg, e.requested, e.askWho)
}

func (e *attachPolicyRefusal) Unwrap() error { return errManagedAttachRefused }

// checkManagedAttach decides one destination change against the managed
// attach policy: nil to proceed, or an *attachPolicyRefusal. requestedURL is
// the server an attach names ("" for a disconnect).
func checkManagedAttach(pol managedconfig.AttachResult, current attachrule.Destination, intent attachrule.Intent, requestedURL string) error {
	if pol.Status == managedconfig.AttachStatusInvalid {
		return &attachPolicyRefusal{intent: intent, source: pol.Source, failedCheck: pol.FailedCheck, detail: pol.Err}
	}
	lock := pol.Lock()
	if lock == nil {
		return nil
	}
	in := attachrule.Input{Current: current, Lock: lock, Intent: intent}
	if requestedURL != "" {
		in.Requested = managedconfig.OrgDestination(requestedURL, "")
	}
	d := attachrule.Decide(in)
	if d.Outcome != attachrule.OutcomeRefuse {
		return nil
	}
	r := &attachPolicyRefusal{intent: intent, source: pol.Source, requested: requestedURL}
	if d.Refusal != nil {
		r.lockOrg, r.askWho = d.Refusal.LockOrgName, d.Refusal.AskWho
	}
	return r
}

// currentDestination is attachrule's current destination for an enrolment
// (nil: none).
func currentDestination(enr *store.Enrolment) attachrule.Destination {
	if enr == nil {
		return attachrule.Destination{}
	}
	d := managedconfig.OrgDestination(enr.OrgServerURL, enr.OrgName)
	if enr.IsManaged() {
		d.Tenancy = attachrule.TenancyManaged
	}
	return d
}

// managedAttachPolicy is the bundle's attach policy: the snapshot its builder
// set, else this OS's fixed source.
func (b orgBundle) managedAttachPolicy() managedconfig.AttachResult {
	if b.attachPolicy != nil {
		return b.attachPolicy()
	}
	return managedconfig.LoadAttach()
}

// gateManagedAttach is checkManagedAttach with the bundle's policy and its
// current enrolment.
func gateManagedAttach(ctx context.Context, b orgBundle, intent attachrule.Intent, requestedURL string) error {
	var enr *store.Enrolment
	if b.store != nil {
		enr, _ = b.store.LoadEnrolment(ctx) //nolint:errcheck // the current destination is context only; row 1 does not read it
	}
	return checkManagedAttach(b.managedAttachPolicy(), currentDestination(enr), intent, requestedURL)
}

// managedEnrolDefaultIdP is the server a bare `observer enroll` signs in to:
// the managed org URL when the policy's method is idp, else "".
func managedEnrolDefaultIdP(pol managedconfig.AttachResult) string {
	if pol.Policy == nil || pol.Policy.Method != managedconfig.AttachMethodIdP {
		return ""
	}
	return pol.DefaultOrgURL()
}

// managedEnrolIdPURL is the --idp server `observer enroll` uses: idpURL as
// given, or, when the command names no server or code at all, the managed
// default (announced on out).
func managedEnrolIdPURL(out io.Writer, pol managedconfig.AttachResult, tokenFile, linkURL, idpURL string, args []string) string {
	if tokenFile != "" || linkURL != "" || idpURL != "" || len(args) > 0 {
		return idpURL
	}
	u := managedEnrolDefaultIdP(pol)
	if u != "" {
		fmt.Fprintf(out, "Enrolling with %s, set by company-managed configuration (%s).\n", u, pol.Source)
	}
	return u
}

// enrolCmdDeps are the enrol and leave commands' seams.
type enrolCmdDeps struct {
	// attachPolicy reads the company-managed attach policy.
	attachPolicy func() managedconfig.AttachResult
	// bundle opens the org bundle.
	bundle func(ctx context.Context, configPath string) (orgBundle, error)
	// idpFlow builds the --idp sign-in flow.
	idpFlow func(c *orgclient.Client, out io.Writer) *idpEnrolFlow
	// attachProver returns the device-proof signer for an attach grant
	// (--attach-grant-file, Getting started v2 lane 8): this machine's cloud
	// device key through the consent gateway's Bootstrap family. nil in a
	// build without Cloud Intelligence, which then refuses a grant.
	attachProver func(configPath string) func(grant, agentPublicKey string) (orgcontract.AttachProof, error)
}

// defaultEnrolCmdDeps are the production seams.
func defaultEnrolCmdDeps() enrolCmdDeps {
	return enrolCmdDeps{
		attachPolicy: managedconfig.LoadAttach,
		bundle:       buildOrgBundle,
		idpFlow: func(c *orgclient.Client, out io.Writer) *idpEnrolFlow {
			return &idpEnrolFlow{client: c, out: out}
		},
		attachProver: defaultAttachProver(),
	}
}
